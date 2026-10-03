#ifndef HB_TRACE_H
#define HB_TRACE_H

#include "hb_result.h"
#include "hb_context.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HB_TRACE_DECODE,
    HB_TRACE_LIFT,
    HB_TRACE_EXEC,
    HB_TRACE_MEMORY,
    HB_TRACE_FAULT,
    HB_TRACE_THUNK,
    HB_TRACE_CACHE,
    HB_TRACE_BENCH
} hb_trace_kind_t;

typedef struct {
    uint64_t timestamp_ns;
    hb_trace_kind_t kind;
    uint64_t guest_addr;
    const char* message;
    const char* detail;
} hb_trace_entry_t;

typedef struct hb_trace {
    hb_trace_entry_t* entries;
    size_t count;
    size_t capacity;
    bool enabled;
} hb_trace_t;

hb_trace_t* hb_trace_create(size_t capacity);
void hb_trace_destroy(hb_trace_t* trace);

void hb_trace_record(hb_trace_t* trace, hb_trace_kind_t kind, uint64_t guest_addr, const char* msg, const char* detail);
void hb_trace_clear(hb_trace_t* trace);

char* hb_trace_to_json(hb_trace_t* trace);
char* hb_trace_to_string(hb_trace_t* trace);

#ifdef __cplusplus
}
#endif

#endif
