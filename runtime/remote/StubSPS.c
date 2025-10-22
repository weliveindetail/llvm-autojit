#include "runtime/remote/StubSPS.h"

void sps_buffer_init(sps_buffer_t *buf, size_t capacity) {
  buf->data = malloc(capacity);
  buf->size = 0;
  buf->capacity = capacity;
}

void sps_buffer_free(sps_buffer_t *buf) {
  free(buf->data);
  buf->data = NULL;
  buf->size = 0;
  buf->capacity = 0;
}

void sps_write_uint8(sps_buffer_t *buf, uint8_t value) {
  if (buf->size + 1 > buf->capacity) {
    buf->capacity *= 2;
    buf->data = realloc(buf->data, buf->capacity);
  }
  memcpy(buf->data + buf->size, &value, 1);
  buf->size += 1;
}

void sps_write_uint64(sps_buffer_t *buf, uint64_t value) {
  if (buf->size + 8 > buf->capacity) {
    buf->capacity *= 2;
    buf->data = realloc(buf->data, buf->capacity);
  }
  memcpy(buf->data + buf->size, &value, 8);
  buf->size += 8;
}

void sps_write_string(sps_buffer_t *buf, const char *str) {
  uint64_t len = strlen(str);
  sps_write_uint64(buf, len);

  if (buf->size + len > buf->capacity) {
    buf->capacity = buf->size + len + 256;
    buf->data = realloc(buf->data, buf->capacity);
  }
  memcpy(buf->data + buf->size, str, len);
  buf->size += len;
}

void sps_write_skip(sps_buffer_t *buf, size_t count) {
  if (buf->size + count > buf->capacity) {
    buf->capacity = buf->size + count + 256;
    buf->data = realloc(buf->data, buf->capacity);
  }
  /* Zero out the skipped bytes */
  memset(buf->data + buf->size, 0, count);
  buf->size += count;
}

int sps_read_uint64(const uint8_t **ptr, const uint8_t *end, uint64_t *value) {
  if (*ptr + 8 > end) {
    // ERROR_LOG("SPS: buffer underrun reading uint64\n");
    return -1;
  }
  memcpy(value, *ptr, 8);
  *ptr += 8;
  return 0;
}

int sps_read_string(const uint8_t **ptr, const uint8_t *end, char **str,
                    uint64_t *len) {
  if (sps_read_uint64(ptr, end, len) < 0)
    return -1;

  if (*ptr + *len > end) {
    // ERROR_LOG("SPS: buffer underrun reading string\n");
    return -1;
  }

  *str = malloc(*len + 1);
  if (!*str)
    return -1;

  memcpy(*str, *ptr, *len);
  (*str)[*len] = '\0';
  *ptr += *len;
  return 0;
}
