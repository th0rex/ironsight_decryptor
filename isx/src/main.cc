#include <isx/isx.hpp>

#include <cstdio>
#include <cstring>
#include <vector>

#include <fmt/printf.h>

#include <gcrypt.h>

#include <zlib.h>

static bool DEBUG_ENABLED = false;

template <typename... Args>
void debug(const char *format, const Args &... args) {
  if (DEBUG_ENABLED) {
    fmt::printf(format, args...);
  }
}

static const std::uint32_t KEY[4] = {
    0x8f4fe388,
    0xf1791708,
    0x3794f3e9,
    0x8905d40a,
};

static const std::uint32_t IV[4] = {
    0xa7668d26,
    0x811aa835,
    0xfad9ba6f,
    0x1251636,
};

struct InvalidSize {
  std::ptrdiff_t needed_size;
  std::ptrdiff_t actual_size;
};

struct InvalidMagic {};

struct InvalidVersion {
  std::uint32_t version;
};

struct GCryError {};
struct ZlibError {};
struct InvalidArgument {};
struct IOError {};

struct FileHeader {
  char magic[4];
  std::uint32_t version;
  char path[128];
  std::uint32_t handle_count;
};

constexpr static std::uint32_t RESOURCE_COMPRESSED = 1;
constexpr static std::uint32_t RESOURCE_ENCRYPTED = 2;

struct ResourceHandle {
  char path[128];
  std::uint32_t offset;
  std::uint32_t size;
  std::uint32_t flags;

  std::uint32_t decrypt(gsl::span<std::uint8_t> buffer_view) const {
    if (size <= 4) {
      debug("ResourceHandle::decrypt: need a size field\n");
      throw InvalidSize{5, size};
    }

    const auto size = buffer_view.size() - 4;

    gcry_cipher_hd_t handle;
    if (gcry_cipher_open(&handle, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CBC, 0)) {
      debug("gcry_cipher_open failed\n");
      throw GCryError{};
    }
    if (gcry_cipher_setkey(handle, &KEY, 16)) {
      debug("gcry_cipher_setkey failed\n");
      throw GCryError{};
    }
    if (gcry_cipher_setiv(handle, &IV, 16)) {
      debug("gcry_cipher_setiv failed\n");
      throw GCryError{};
    }
    if (gcry_cipher_decrypt(handle, buffer_view.data() + 4, size, nullptr, 0)) {
      debug("gcry_cipher_decrypt failed\n");
      throw GCryError{};
    }
    gcry_cipher_close(handle);

    return *reinterpret_cast<const std::uint32_t *>(buffer_view.data());
  }

  std::uint32_t uncompress(gsl::span<std::uint8_t> buffer_view,
                           std::vector<std::uint8_t> &buffer) const {
    if (buffer_view.size() <= 4) {
      debug("ResourceHandle::uncompress(): need a size field\n");
      throw InvalidSize{5, buffer_view.size()};
    }

    const auto out_size =
        *reinterpret_cast<const std::uint32_t *>(buffer_view.data());
    buffer.reserve(out_size);

    const auto in_size = buffer_view.size() - 4;

    z_stream stream;
    stream.next_in = buffer_view.data() + 4;
    stream.avail_in = in_size;
    stream.zalloc = nullptr;
    stream.zfree = nullptr;
    stream.avail_out = out_size;
    stream.next_out = buffer.data();

    if (inflateInit(&stream)) {
      debug("ResourcePackage::uncompress(): inflateInit failed\n");
      throw ZlibError{};
    }
    if (!inflate(&stream, Z_FINISH)) {
      debug("ResourcePackage::uncompress(): inflate failed\n");
      throw ZlibError{};
    }

    inflateEnd(&stream);

    return out_size;
  }

  /// Returns true if the uncompress buffer was used.
  gsl::span<const std::uint8_t>
  extract_to(gsl::span<const std::uint8_t> data,
             std::vector<std::uint8_t> &buffer,
             std::vector<std::uint8_t> &uncompress_buffer) const {
    buffer.reserve(size);
    std::memcpy(buffer.data(), data.data() + offset, size);

    auto buffer_view = gsl::span{buffer.data(), size};

    std::uint32_t real_size = size;
    if (flags & RESOURCE_ENCRYPTED) {
      real_size = decrypt(buffer_view);
      buffer_view = gsl::span{buffer_view.data() + 4, real_size};
      debug(", size after decrypt = 0x%08x", real_size);
    }

    if (flags & RESOURCE_COMPRESSED) {
      real_size = uncompress(buffer_view, uncompress_buffer);
      debug(", size after decompress = 0x%08x", real_size);
    }

    return flags & RESOURCE_COMPRESSED
               ? gsl::span{uncompress_buffer.data(), real_size}
               : buffer_view;
  }
};

constexpr static char DEFAULT_MAGIC[4] = {'R', 'P', 'K', 'G'};

class ResourcePackage {
  const gsl::span<const std::uint8_t> raw_data;
  const FileHeader *file_header;
  std::vector<const ResourceHandle *> resource_handles;

public:
  explicit ResourcePackage(gsl::span<const std::uint8_t> sp) : raw_data{sp} {
    if (sizeof(FileHeader) > sp.size()) {
      debug("ResourcePackage::ResourcePackage(): buffer too small for "
            "file header\n");
      throw InvalidSize{sizeof(FileHeader), sp.size()};
    }

    file_header = reinterpret_cast<const FileHeader *>(sp.data());
    if (std::memcmp(file_header->magic, DEFAULT_MAGIC, 4) != 0) {
      throw InvalidMagic{};
    }
    if (file_header->version > 1) {
      throw InvalidVersion{file_header->version};
    }

    const std::ptrdiff_t needed_size =
        sizeof(FileHeader) + sizeof(ResourceHandle) * file_header->handle_count;
    if (needed_size > sp.size()) {
      debug("ResourcePackage::ResourcePackage(): buffer too small for "
            "all resource handles\n");
      throw InvalidSize{needed_size, sp.size()};
    }

    auto *const begin = reinterpret_cast<const ResourceHandle *>(
        sp.data() + sizeof(FileHeader));
    for (auto *p = begin; p - begin < file_header->handle_count; ++p) {
      resource_handles.emplace_back(p);
    }
  }

  ResourcePackage(const std::uint8_t *data, std::ptrdiff_t length)
      : ResourcePackage{gsl::span{data, length}} {}

  void extract_files(std::string_view output_prefix) const {
    std::vector<std::uint8_t> buffer;
    std::vector<std::uint8_t> uncompress_buffer;

    for (auto *handle : resource_handles) {
      debug("file %-40s: offset = 0x%08x, size = 0x%08x", handle->path,
            handle->offset, handle->size);

      const auto view = handle->extract_to(raw_data, buffer, uncompress_buffer);
      const auto file_name = fmt::sprintf("%s/%s", output_prefix, handle->path);

      auto *file = std::fopen(file_name.c_str(), "wb");
      if (!file) {
        debug("fopen failed\n");
        throw IOError{};
      }

      std::fwrite(view.data(), view.size(), 1, file);
      std::fflush(file);
      std::fclose(file);

      debug("\n");
    }
  }

  void list_files() const {
    for (auto *handle : resource_handles) {
      fmt::printf(
          "file %-40s compressed: %s, encrypted: %s, offset: 0x%08x size: "
          "0x%08x\n",
          handle->path, handle->flags & RESOURCE_COMPRESSED ? "true" : "false",
          handle->flags & RESOURCE_ENCRYPTED ? "true" : "false", handle->offset,
          handle->size);
    }
  }
};

constexpr std::ptrdiff_t round_up_16(std::ptrdiff_t p) {
  return (p + 16 - 1) & ~(16 - 1);
}

struct OwnedSpan {
  std::unique_ptr<std::uint8_t[]> data;
  std::ptrdiff_t size;
};

OwnedSpan load_file(const char *name) {
  auto *file = std::fopen(name, "rb");
  if (!file) {
    debug("fopen failed\n");
    throw IOError{};
  }

  std::fseek(file, 0, SEEK_END);
  const auto size = std::ftell(file);
  std::fseek(file, 0, SEEK_SET);

  auto buffer = std::make_unique<std::uint8_t[]>(size);
  std::fread(buffer.get(), size, 1, file);
  std::fclose(file);

  return {std::move(buffer), size};
}

OwnedSpan compress_buffer(gsl::span<std::uint8_t> data) {
  const auto orig_size = data.size();
  auto compressed_size = orig_size + 4;

  auto tmp_buffer = std::make_unique<std::uint8_t[]>(compressed_size);

  while (true) {
    z_stream stream;
    stream.next_in = data.data();
    stream.avail_in = orig_size;
    stream.zalloc = nullptr;
    stream.zfree = nullptr;
    stream.avail_out = compressed_size - 4;
    stream.next_out = tmp_buffer.get() + 4;

    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION)) {
      debug("deflateInit failed\n");
      throw ZlibError{};
    }

    if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
      compressed_size *= 2;
      tmp_buffer = std::make_unique<std::uint8_t[]>(compressed_size);
      deflateEnd(&stream);
      continue;
    }

    compressed_size -= stream.avail_out;
    deflateEnd(&stream);
    break;
  }

  *reinterpret_cast<std::uint32_t *>(tmp_buffer.get()) = orig_size;

  debug(", compressed size = 0x%08x", compressed_size);

  return {std::move(tmp_buffer), compressed_size};
}

OwnedSpan encrypt_buffer(gsl::span<std::uint8_t> data) {
  const auto enc_size = static_cast<std::uint32_t>([](std::ptrdiff_t size) {
    if (size % 16 != 0) {
      return round_up_16(size);
    }
    return size + 16;
  }(data.size()));

  const auto enc_size_with_tag = enc_size + 4;

  auto tmp_buffer = std::make_unique<std::uint8_t[]>(enc_size_with_tag);
  *reinterpret_cast<std::uint32_t *>(tmp_buffer.get()) = data.size();
  std::memcpy(tmp_buffer.get() + 4, data.data(), data.size());

  gcry_cipher_hd_t handle;
  if (gcry_cipher_open(&handle, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CBC, 0)) {
    debug("gcry_cipher_open failed\n");
    throw GCryError{};
  }
  if (gcry_cipher_setkey(handle, &KEY, 16)) {
    debug("gcry_cipher_setkey failed\n");
    throw GCryError{};
  }
  if (gcry_cipher_setiv(handle, &IV, 16)) {
    debug("gcry_cipher_setiv failed\n");
    throw GCryError{};
  }
  if (gcry_cipher_encrypt(handle, tmp_buffer.get() + 4, enc_size, NULL, 0)) {
    debug("gcry_cipher_encrypt failed\n");
    throw GCryError{};
  }
  gcry_cipher_close(handle);

  debug(", encrypted size: 0x%08x", enc_size_with_tag);

  return {std::move(tmp_buffer), enc_size_with_tag};
}

void pack_files(const char *output_name, const bool compress,
                const bool encrypt, const char **files, const int count) {
  const auto output_buffer = fmt::sprintf("%s.wpg", output_name);
  auto handles = std::make_unique<ResourceHandle[]>(count);
  auto buffers = std::make_unique<std::unique_ptr<std::uint8_t[]>[]>(count);

  debug("output path: %-40s compress: %s, encrypt: %s, file count: %d\n",
        output_buffer, compress ? "true" : "false", encrypt ? "true" : "false",
        count);

  auto current_offset = sizeof(FileHeader) + sizeof(ResourceHandle) * count;

  for (auto i = 0; i < count; ++i) {
    auto[data, size] = load_file(files[i]);
    debug("packing file %-40s: offset = 0x%08x size = 0x%08x", files[i],
          current_offset, size);

    if (compress) {
      auto[d, s] = compress_buffer(gsl::span{data.get(), size});
      data = std::move(d);
      size = s;
    }

    if (encrypt) {
      auto[d, s] = encrypt_buffer(gsl::span{data.get(), size});
      data = std::move(d);
      size = s;
    }
    debug("\n");

    auto &handle = handles[i];

    buffers[i] = std::move(data);
    handle.flags |= compress ? RESOURCE_COMPRESSED : 0;
    handle.flags |= encrypt ? RESOURCE_ENCRYPTED : 0;
    handle.offset = current_offset;
    handle.size = size;

    std::memset(handle.path, 0, 128);
    std::strcpy(handle.path, files[i]);

    current_offset += size;
  }

  const auto actual_output_name = fmt::sprintf("%s\\", output_name);

  FileHeader header;
  std::strcpy(header.magic, "RPKG");
  header.version = 1;
  header.handle_count = count;
  std::strcpy(header.path, actual_output_name.c_str());

  auto *file = std::fopen(output_buffer.c_str(), "wb");
  if (!file) {
    debug("fopen failed\n");
    throw IOError{};
  }

  std::fwrite(&header, sizeof(FileHeader), 1, file);
  std::fwrite(handles.get(), sizeof(ResourceHandle), count, file);

  for (auto i = 0; i < count; ++i) {
    std::fwrite(buffers[i].get(), handles[i].size, 1, file);
  }

  std::fflush(file);
  std::fclose(file);
}

struct Config {
  bool debug;
  enum class Mode {
    None,
    List,
    Pack,
    Extract,
  } mode;
  union {
    const char *file_name;
    struct {
      const char *output_name;
      const char **files;
      int count;
      bool compress;
      bool encrypt;
    };
  };

  Config(int argc, const char **argv) : debug{false}, mode{Mode::None} {
    argc -= 1;
    for (int i = 1; i < argc; ++i) {
      if (!std::strcmp(argv[i], "--debug")) {
        debug = true;
      } else if (!std::strcmp(argv[i], "--extract")) {
        if (i + 1 > argc) {
          fmt::printf("expected file name to extract after `--extract`\n");
          throw InvalidArgument{};
        }
        mode = Mode::Extract;
        file_name = argv[i + 1];
        return;
      } else if (!std::strcmp(argv[i], "--list")) {
        if (i + 1 > argc) {
          fmt::printf("expected file name to list files from after `--list`\n");
          throw InvalidArgument{};
        }
        mode = Mode::List;
        file_name = argv[i + 1];
        return;
      } else if (!std::strcmp(argv[i], "--pack")) {
        if (i + 1 > argc) {
          fmt::printf("expected output name after `--pack`\n");
          throw InvalidArgument{};
        }
        mode = Mode::Pack;
        output_name = argv[i + 1];
        i += 1;
        if (i + 1 <= argc && !std::strcmp(argv[i + 1], "--compress")) {
          compress = true;
          i += 1;
        }
        if (i + 1 <= argc && !std::strcmp(argv[i + 1], "--encrypt")) {
          encrypt = true;
          i += 1;
        }
        files = &argv[i + 1];
        count = argc - i;
        return;
      }
    }
  }
};

int main(int argc, const char **argv) {
  Config c{argc, argv};
  DEBUG_ENABLED = c.debug;

  if (c.mode == Config::Mode::Extract) {
    auto[buffer, size] = load_file(c.file_name);

    ResourcePackage pckg{buffer.get(), size};
    pckg.extract_files("output");
  } else if (c.mode == Config::Mode::List) {
    auto[buffer, size] = load_file(c.file_name);

    ResourcePackage pckg{buffer.get(), size};
    pckg.list_files();
  } else if (c.mode == Config::Mode::Pack) {
    pack_files(c.output_name, c.compress, c.encrypt, c.files, c.count);
  }

  return 0;
}
