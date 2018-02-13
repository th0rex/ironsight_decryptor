project(isx)

set(SOURCE_FILES src/main.cc)

add_executable(isx ${SOURCE_FILES})
target_compile_options(isx PRIVATE -Wall)
target_include_directories(isx PRIVATE include/)
target_link_libraries(isx fmt GSL zlib "-lgcrypt")
