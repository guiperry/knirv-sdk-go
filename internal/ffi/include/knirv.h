#ifndef KNIRV_SDK_H
#define KNIRV_SDK_H

#include <stddef.h>
#include <stdint.h>

typedef struct knirv_engine knirv_engine_t;
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

/* JSON inputs are borrowed for each call. response_json is SDK-owned and must
 * be released exactly once with knirv_bytes_free (a repeated free is ignored). */
knirv_status_t knirv_engine_new(knirv_bytes_t config_json, knirv_engine_t **out);
knirv_status_t knirv_engine_call(knirv_engine_t *engine, knirv_bytes_t request_json, knirv_bytes_t *response_json);
void knirv_engine_free(knirv_engine_t *engine);
void knirv_bytes_free(knirv_bytes_t bytes);

/* Protobuf envelope API used by sdk-go. request_proto and response_proto use
 * SdkRequest/SdkResponse; output is SDK-owned and freed with this function. */
knirv_status_t knirv_sdk_invoke_proto(knirv_bytes_t request_proto, knirv_bytes_t *response_proto);
void knirv_sdk_free_buffer(knirv_bytes_t bytes);

/* Both outputs are SDK-owned copies and must be freed with knirv_bytes_free. */
knirv_status_t knirv_module_manifest(knirv_bytes_t *out);
knirv_status_t knirv_module_bytes(knirv_bytes_t name, knirv_bytes_t *out);

#endif
