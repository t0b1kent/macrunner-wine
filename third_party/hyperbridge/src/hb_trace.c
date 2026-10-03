#include "hb_trace.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

hb_trace_t* hb_trace_create(size_t capacity) {
    hb_trace_t* t = calloc(1, sizeof(hb_trace_t));
    if (!t) return NULL;
    t->capacity = capacity;
    t->entries = calloc(capacity, sizeof(hb_trace_entry_t));
    if (!t->entries) { free(t); return NULL; }
    return t;
}

void hb_trace_destroy(hb_trace_t* trace) {
    if (!trace) return;
    for (size_t i = 0; i < trace->count; i++) {
        free((void*)trace->entries[i].message);
        free((void*)trace->entries[i].detail);
    }
    free(trace->entries);
    free(trace);
}

void hb_trace_record(hb_trace_t* trace, hb_trace_kind_t kind, uint64_t guest_addr, const char* msg, const char* detail) {
    if (!trace || !trace->enabled || trace->count >= trace->capacity) return;
    hb_trace_entry_t* e = &trace->entries[trace->count++];
    e->timestamp_ns = (uint64_t)clock() * 1000000000ULL / CLOCKS_PER_SEC;
    e->kind = kind;
    e->guest_addr = guest_addr;
    e->message = msg ? strdup(msg) : NULL;
    e->detail = detail ? strdup(detail) : NULL;
}

void hb_trace_clear(hb_trace_t* trace) {
    if (!trace) return;
    for (size_t i = 0; i < trace->count; i++) {
        free((void*)trace->entries[i].message);
        free((void*)trace->entries[i].detail);
    }
    trace->count = 0;
}

char* hb_trace_to_json(hb_trace_t* trace) {
    if (!trace) return strdup("[]");
    size_t cap = 4096 + trace->count * 256;
    char* buf = malloc(cap);
    if (!buf) return strdup("[]");
    int n = snprintf(buf, cap, "[\n");
    for (size_t i = 0; i < trace->count; i++) {
        hb_trace_entry_t* e = &trace->entries[i];
        n += snprintf(buf + n, cap - n,
            "  {\"ts\":%llu,\"kind\":%d,\"addr\":\"0x%llx\",\"msg\":\"%s\",\"detail\":\"%s\"}%s\n",
            (unsigned long long)e->timestamp_ns, (int)e->kind,
            (unsigned long long)e->guest_addr,
            e->message ? e->message : "",
            e->detail ? e->detail : "",
            i + 1 < trace->count ? "," : "");
        if (n < 0 || (size_t)n >= cap) break;
    }
    n += snprintf(buf + n, cap - n, "]");
    return buf;
}

char* hb_trace_to_string(hb_trace_t* trace) {
    if (!trace) return strdup("");
    size_t cap = 4096 + trace->count * 128;
    char* buf = malloc(cap);
    if (!buf) return strdup("");
    int n = 0;
    for (size_t i = 0; i < trace->count; i++) {
        n += snprintf(buf + n, cap - n, "[%llu] %d @0x%llx: %s\n",
            (unsigned long long)trace->entries[i].timestamp_ns,
            (int)trace->entries[i].kind,
            (unsigned long long)trace->entries[i].guest_addr,
            trace->entries[i].message ? trace->entries[i].message : "");
        if (n < 0 || (size_t)n >= cap) break;
    }
    return buf;
}
