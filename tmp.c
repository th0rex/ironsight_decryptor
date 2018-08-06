#include <stdio.h>

/*
 * Serves for documentation of currently not completly known structures.
 */

struct model_data {
  struct {
    char magic[4]; // MODL
    uint32_t version; // 7
  } header;
  float unk0[7];
  uint32_t mesh_path_length;
  char mesh_path[mesh_path_length];
  uint32_t phys_path_length;
  char phys_path[phys_path_length];
  uint32_t num_bfx_elements;
  uint64_t please_kill_me_already_bfx_1;
  uint32_t bfx_1_path_length;
  char bfx_1_path [bfx_1_path_length];
  uint32_t bfx_yet_another_size;
};

