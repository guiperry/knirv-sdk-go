#ifndef KNIRV_SDK_H
#define KNIRV_SDK_H

#include <stddef.h>
#include <stdint.h>

typedef struct { const uint8_t *ptr; size_t len; } knirv_bytes_t;

typedef enum {
  KNIRV_STATUS_OK = 0,
  KNIRV_STATUS_INVALID_ARGUMENT = 1,
  KNIRV_STATUS_AUTHENTICATION = 2,
  KNIRV_STATUS_TIMEOUT = 3,
  KNIRV_STATUS_TRANSPORT = 4,
  KNIRV_STATUS_API = 5,
  KNIRV_STATUS_CRYPTO = 6,
  KNIRV_STATUS_INTERNAL_PANIC = 7
} knirv_status_t;

/* request_proto and response_proto encode the generated SdkRequest and
 * SdkResponse messages. Response memory belongs to the SDK until freed. */
knirv_status_t knirv_sdk_invoke_proto(knirv_bytes_t request_proto, knirv_bytes_t *response_proto);
void knirv_sdk_free_buffer(knirv_bytes_t bytes);

#endif
