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


afl_state_t *afl_struct;

// #define DEBUG

#ifdef DEBUG
  #define DBG(x...) fprintf(stderr, x)
#else
  #define DBG(x...) \
    {}
#endif

typedef struct my_mutator {
  afl_state_t *afl;
  u8          *mutator_buf;
  u8          *out_dir;
  u8          *tmp_dir;
  u8          *target;
  uint32_t     seed;
  char        *conc_argv[20];
} my_mutator_t;


my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }
  if ((data->mutator_buf = malloc(MAX_FILE)) == NULL) {
    free(data);
    perror("mutator_buf alloc");
    return NULL;
  }
  if (!(data->target = getenv("SYMASAN_TARGET")))
    FATAL(
        "SYMASAN_TARGET not defined, this should point to the full path of the "
        "SYMASAN compiled binary.");
  data->out_dir = alloc_printf("%s/symasan", afl->out_dir);
  data->tmp_dir = alloc_printf("%s/tmp", data->out_dir);
  int pid = fork();

  if (pid == -1) return NULL;

  if (pid) pid = waitpid(pid, NULL, 0);

  if (pid == 0) {
    char *args[4];
    args[0] = "/bin/rm";
    args[1] = "-rf";
    args[2] = data->out_dir;
    args[3] = NULL;
    execvp(args[0], args);
    DBG("exec:FAIL\n");
    exit(-1);
  }
  data->afl = afl;
  data->seed = seed;
  afl_struct = afl;
  for(int i=0; i<20; i++) data->conc_argv[i] = NULL;
  data->conc_argv[0] = "timeout";
  data->conc_argv[1] = "5m";
  data->conc_argv[2] = data->target;
  if (mkdir(data->out_dir, 0755))
    PFATAL("Could not create directory %s", data->out_dir);

  if (mkdir(data->tmp_dir, 0755))
    PFATAL("Could not create directory %s", data->tmp_dir);

  DBG("out_dir=%s, target=%s\n", data->out_dir, data->target);
  return data;
}

uint8_t afl_custom_queue_new_entry(my_mutator_t  *data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {
  struct stat st;
  u8 *fn = alloc_printf("%s", filename_new_queue);
  if (!(stat(fn, &st) == 0 && S_ISREG(st.st_mode) && st.st_size)) {
    ck_free(fn);
    PFATAL("Couldn't find enqueued file: %s", fn);
  }

  int pid = fork();

  if (pid == -1) return 0;
  if (pid) {
    pid = waitpid(pid, NULL, 0);
    struct dirent **nl;
    int32_t items = scandir(data->tmp_dir, &nl, NULL, NULL);
    u8 *origin_name = basename(filename_new_queue);
    int32_t         i;
    if (items > 0) {
      for (i = 0; i < items; ++i) {
        struct stat st;
        u8 *source_name = alloc_printf("%s/%s", data->tmp_dir, nl[i]->d_name);
        if (stat(source_name, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {
          u8 *destination_name = alloc_printf("%s/%s.%s", data->out_dir,
                                              origin_name, nl[i]->d_name);
          rename(source_name, destination_name);
          ck_free(destination_name);
          DBG("found=%s\n", source_name);
        }

        ck_free(source_name);
        free(nl[i]);
      }

      free(nl);
    }
  }

  if (pid == 0) {
    u8 *taint_options = alloc_printf("taint_file=%s:output_dir=%s", afl_struct->fsrv.out_file, data->tmp_dir);
    setenv("TAINT_OPTIONS", taint_options, 1);
    DBG("TAINT_OPTIONS:%s\n", taint_options);
    DBG("exec=%s\n", data->target);
    // 
    char **p = afl_struct->argv+1;
    for(int i=3; i<20 || *p == NULL; i++) {
      data->conc_argv[i] = *p;
      p++;
    } 
    ck_free(taint_options);
    close(1);
    close(2);
    dup2(afl_struct->fsrv.dev_null_fd, 1);
    dup2(afl_struct->fsrv.dev_null_fd, 2);

    execvp(data->conc_argv[0], data->conc_argv);
    DBG("exec=FAIL\n");
    exit(-1);
  }
  return 0;
}


uint32_t afl_custom_fuzz_count(my_mutator_t *data, const u8 *buf,
                               size_t buf_size) {

  uint32_t        count = 0, i;
  struct dirent **nl;
  int32_t         items = scandir(data->out_dir, &nl, NULL, NULL);

  if (items > 0) {

    for (i = 0; i < (u32)items; ++i) {

      struct stat st;
      u8 * fn = alloc_printf("%s/%s", data->out_dir, nl[i]->d_name);
      DBG("test=%s\n", fn);
      if (stat(fn, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

        DBG("found=%s\n", fn);
        count++;

      }

      ck_free(fn);
      free(nl[i]);

    }
    free(nl);
  }

  DBG("dir=%s, count=%u\n", data->out_dir, count);
  return count;

}


/* here we actually just read the files generated from symasan */
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  struct dirent **nl;
  int32_t  i, done = 0;
  int32_t items = scandir(data->out_dir, &nl, NULL, NULL);
  ssize_t  size = 0;

  if (items <= 0) return 0;

  for (i = 0; i < items; ++i) {

    struct stat st;
    u8 * fn = alloc_printf("%s/%s", data->out_dir, nl[i]->d_name);

    if (done == 0) {

      if (stat(fn, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

        int fd = open(fn, O_RDONLY);

        if (fd >= 0) {

          size = read(fd, data->mutator_buf, max_size);
          *out_buf = data->mutator_buf;

          close(fd);
          done = 1;

        }

      }

      unlink(fn);

    }

    ck_free(fn);
    free(nl[i]);

  }

  free(nl);
  DBG("FUZZ size=%lu\n", size);
  return (uint32_t)size;

}



void afl_custom_deinit(my_mutator_t *data) {
  free(data->mutator_buf);
  free(data);
}