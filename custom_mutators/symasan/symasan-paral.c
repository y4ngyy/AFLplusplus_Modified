#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "config.h"
#include "debug.h"
#include "afl-fuzz.h"
#include "common.h"


typedef struct my_mutator {

  afl_state_t *afl;
  u8 *         mutator_buf;
  u8 *         out_dir;
  u8 *         tmp_dir;
  u8 *         target;
  uint32_t     seed;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
}

