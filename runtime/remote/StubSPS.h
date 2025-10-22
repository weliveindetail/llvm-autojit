#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Simple Packed Serialization Encoding/Decoding from LLVM OrcJIT */

typedef struct {
  uint8_t *data;
  size_t size;
  size_t capacity;
} sps_buffer_t;

void sps_buffer_init(sps_buffer_t *buf, size_t capacity);
void sps_buffer_free(sps_buffer_t *buf);

void sps_write_uint8(sps_buffer_t *buf, uint8_t value);
void sps_write_uint64(sps_buffer_t *buf, uint64_t value);
void sps_write_string(sps_buffer_t *buf, const char *str);
void sps_write_skip(sps_buffer_t *buf, size_t count);

int sps_read_uint64(const uint8_t **ptr, const uint8_t *end, uint64_t *value);
int sps_read_string(const uint8_t **ptr, const uint8_t *end, char **str,
                    uint64_t *len);
