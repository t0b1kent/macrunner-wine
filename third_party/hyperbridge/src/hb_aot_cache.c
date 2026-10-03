#include "hb_env.h"
#include "hb_gates.h"
#include "hb_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include "hb_alloc_count.h"

#define HB_AOT_MAGIC   "HBTC"
#define HB_AOT_VERSION 2u
#define HB_AOT_ABI     1u

/* ★★★ 06.09.2026, лейн КЕШ — ОТПЕЧАТОК СБОРКИ В ЗАГОЛОВКЕ ФАЙЛА.
 *
 * ЧТО БЫЛО. Заголовок проверял magic + версию формата + константу HB_AOT_ABI. Все три —
 * величины ВРЕМЕНИ КОМПИЛЯЦИИ, одинаковые у любых двух сборок движка. То есть файл кеша,
 * записанный ДРУГОЙ сборкой, проходил проверку заголовка и его записи попадали в поиск.
 * От чужого выпуска спасал только ключ записи (`persistent_cache_version`), а разделение
 * по сборкам целиком лежало на ВЫЗЫВАЮЩЕМ: `scripts/laneA-run-hk.sh:9-12` считает SHA
 * ntdll.so и делает корень `artifacts/hb-translation-cache/ntdll-<sha16>`.
 *
 * Дисциплина вызывающего здесь не работает по построению: лейны A/B задают корень СВОИМ
 * именем (`flagi-ZAM-0`, `nm-on`, `chainx64b-ct1-s0` — 61 корень на диске), и такой корень
 * ПЕРЕЖИВАЕТ пересборку движка. Пересобрал — прогон молча пошёл на вчерашнем выпуске.
 *
 * ЧТО ТЕПЕРЬ. В поле `reserved` кладётся свёртка `hb_build_stamp` — md5 СОДЕРЖИМОГО всех
 * исходников движка, который Makefile уже порождает (`src/hb_stamp.c`) и который уже
 * печатается первой строкой прогона. Несовпадение = файл отвергается ЦЕЛИКОМ при открытии,
 * без чтения 42 МБ чужих записей. Отвергает САМ файл, а не дисциплина вызывающего.
 *
 * Почему именно этот отпечаток, а не дата или LC_UUID: даты врут в обе стороны (холостая
 * пересборка двигает дату, правка общего заголовка — нет), а UUID меняется и от флагов
 * линковки. Хеш содержимого исходников — семантический идентификатор сборки, ровно то,
 * что требуется ключу кеша.
 *
 * ГРАНИЦА. Отпечаток берётся от ИСХОДНИКОВ hyperbridge. Правка вне `engine/hyperbridge`
 * (например в `dlls/ntdll/unix/`), меняющая раскладку или поведение вокруг выпуска, его
 * НЕ сдвинет. Раскладка `hb_context_t` закрыта отдельно — она входит в
 * `persistent_cache_version()` слагаемым `lay`. */
extern const char hb_build_stamp[];   /* ПОРОЖДАЕТСЯ сборкой, см. STAMP_C в Makefile */

static uint32_t build_stamp32(void) {
    static uint32_t cached;
    if (!cached) {
        uint32_t h = 2166136261u;         /* FNV-1a 32 */
        const char* p;
        for (p = hb_build_stamp; *p; ++p) h = (h ^ (uint32_t)(unsigned char)*p) * 16777619u;
        /* 0 означает «не считан», поэтому ноль исключается: иначе одна сборка из 4 млрд
         * пересчитывала бы свёртку на каждом вызове, а её значение совпало бы со старыми
         * файлами (там reserved=0) — то есть ровно та сборка, которую надо отвергнуть,
         * прошла бы. Один запрещённый исход дешевле такой ловушки. */
        cached = h ? h : 1u;
    }
    return cached;
}

/* Persistent translation cache.  The cache is append-mode logically, but every
 * mutation rewrites through a temp file + fsync + rename so readers never see a
 * partially-written entry. */
typedef struct {
    char     magic[4];
    uint32_t version;
    uint32_t abi_version;
    uint32_t reserved;
} hb_aot_header_t;

typedef struct {
    uint32_t key_size;
    uint32_t native_size;
    uint32_t steps;
    uint8_t  valid;
    uint8_t  unsupported;
    uint16_t reserved;
} hb_aot_entry_meta_t;

typedef struct {
    hb_cache_key_t key;
    uint8_t* native_code;
    size_t native_size;
    uint32_t steps;
    uint8_t valid;
    uint8_t unsupported;
} hb_disk_entry_t;

struct hb_cache {
    char path[512];
    char root[512];
    uint32_t format_version;
    uint32_t abi_version;
    hb_cache_stats_t stats;
    hb_disk_entry_t* entries;
    size_t count;
    size_t cap;
    bool dirty;
    /* MacRunner 2026-06-22 (lever #1, ABZU first-frame): open-addressing hash index over
     * `entries` so hb_cache_get/put are O(1) avg instead of an O(N) backward linear scan
     * (was 50.9% of ABZU's _initterm grind: 13777 nested run_x64 callbacks re-look-up the
     * warm cache). Maps hash(key) -> entry position; the full-key memcmp on the matched
     * position stays the authority, so a hash collision only costs an extra compare and can
     * NEVER return a wrong entry. Positions are stable across appends/in-place replaces;
     * invalidate/invalidate_module/clear compact or empty `entries`, so they drop index_valid
     * to force a rebuild. If allocation fails the code falls back to the original linear scan
     * (correct, just slow). Single-thread-per-cache (same posture as the unlocked stats). */
    size_t* hash_index;   /* slot -> entry position, or HB_CACHE_INDEX_EMPTY */
    size_t  hash_cap;     /* power-of-two slot count (0 = none) */
    bool    index_valid;  /* false -> rebuild on next lookup */

    /* MacRunner 2026-07-29 (HK speed lane, iter 7): process-wide sharing, gated by
     * MACRUNNER_HB_CACHE_SHARED. hb_jit_runtime_create() runs once per GUEST THREAD and each
     * one called hb_cache_open() -> load_entries(), i.e. a full read of the whole cache file
     * into a PRIVATE copy. Measured on Hollow Knight: 77 opens per process, 99.9% of all
     * runtime-creation time, growing 34x as the file fills (4.4 ms -> 151 ms, max 229 ms), and
     * 77 x 42 MB of duplicated blobs.
     *
     * Sharing is safe because no pointer into `entries` ever escapes the handle: hb_cache_get()
     * returns a freshly malloc'd COPY including native_code (:372-384) which the caller frees
     * with hb_cache_entry_free(). So the only requirement is mutual exclusion on the handle,
     * which `lock` provides. It is taken ONLY when shared, so the unshared path stays
     * byte-for-byte the code it was and an A/B's control arm is uncontaminated. */
    pthread_mutex_t lock;
    bool     shared;    /* participating in the process-wide singleton */
    unsigned refcount;  /* shared only: opens outstanding; the last close writes back */
};

#define HB_CACHE_INDEX_EMPTY ((size_t)-1)

/* The process-wide handle and the lock that guards *its lifetime* (distinct from c->lock, which
 * guards the handle's contents). Keyed by resolved path + versions: a second root in the same
 * process legitimately gets its own unshared handle rather than silently aliasing the first. */
static pthread_mutex_t g_shared_mu = PTHREAD_MUTEX_INITIALIZER;
static hb_cache_t*     g_shared_cache;
static unsigned long long g_shared_opens, g_shared_reuses;

static bool cache_sharing_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_CACHE_SHARED );
    return v && v[0] && v[0] != '0';
}

static void cache_lock(hb_cache_t* c)   { if (c->shared) pthread_mutex_lock(&c->lock); }
static void cache_unlock(hb_cache_t* c) { if (c->shared) pthread_mutex_unlock(&c->lock); }

static void free_entries(hb_disk_entry_t* entries, size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) free(entries[i].native_code);
    free(entries);
}

static int write_header(FILE* fp, uint32_t format_version, uint32_t abi_version) {
    hb_aot_header_t h;
    memcpy(h.magic, HB_AOT_MAGIC, 4);
    h.version = format_version ? format_version : HB_AOT_VERSION;
    h.abi_version = abi_version ? abi_version : HB_AOT_ABI;
    h.reserved = build_stamp32();
    return (fwrite(&h, sizeof(h), 1, fp) == 1) ? 0 : -1;
}

static bool force_aot_sync_failure(void) {
    const char* value = hb_gate( HB_GATE_HB_TEST_FORCE_AOT_SYNC_FAIL );
    return value && value[0] && value[0] != '0';
}

static int flush_and_sync(FILE* fp) {
    if (!fp) return -1;
    if (fflush(fp) != 0) return -1;
    if (force_aot_sync_failure()) return -1;
    if (fsync(fileno(fp)) != 0) return -1;
    return 0;
}

/* Возвращает 0 — годен; -1 — не наш файл или чужой формат; -2 — наш формат, но ДРУГАЯ
 * сборка движка (значение чужого отпечатка кладётся в *out_foreign, чтобы отказ можно было
 * НАЗВАТЬ ЧИСЛОМ, а не предположить). */
static int read_header(FILE* fp, uint32_t format_version, uint32_t abi_version,
                       uint32_t* out_foreign) {
    hb_aot_header_t h;
    if (out_foreign) *out_foreign = 0;
    if (fread(&h, sizeof(h), 1, fp) != 1) return -1;
    if (memcmp(h.magic, HB_AOT_MAGIC, 4) != 0) return -1;
    if (h.version != (format_version ? format_version : HB_AOT_VERSION)) return -1;
    if (h.abi_version != (abi_version ? abi_version : HB_AOT_ABI)) return -1;
    if (h.reserved != build_stamp32()) {
        if (out_foreign) *out_foreign = h.reserved;
        return -2;
    }
    return 0;
}

static int write_entry(FILE* fp, const hb_disk_entry_t* entry) {
    hb_aot_entry_meta_t meta;

    if (!fp || !entry) return -1;
    memset(&meta, 0, sizeof(meta));
    meta.key_size = sizeof(hb_cache_key_t);
    meta.native_size = (uint32_t)entry->native_size;
    meta.steps = entry->steps;
    meta.valid = entry->valid;
    meta.unsupported = entry->unsupported;
    if (fwrite(&meta, sizeof(meta), 1, fp) != 1 ||
        fwrite(&entry->key, sizeof(entry->key), 1, fp) != 1)
        return -1;
    if (entry->native_size && entry->native_code &&
        fwrite(entry->native_code, 1, entry->native_size, fp) != entry->native_size)
        return -1;
    return 0;
}

static void make_parent_dir(const char* path) {
    char tmp[512];
    const char* slash;
    if (!path) return;
    slash = strrchr(path, '/');
    if (!slash || slash == path) return;
    size_t len = (size_t)(slash - path);
    if (len >= sizeof(tmp)) return;
    memcpy(tmp, path, len);
    tmp[len] = '\0';
    mkdir(tmp, 0755);
}

static int ensure_file(hb_cache_t* c) {
    FILE* fp;
    if (!c || !c->path[0]) return -1;
    make_parent_dir(c->path);
    fp = fopen(c->path, "rb");
    if (fp) {
        uint32_t foreign = 0;
        int ok = read_header(fp, c->format_version, c->abi_version, &foreign);
        fclose(fp);
        if (ok == 0) return 0;
        /* Отказ ОБЯЗАН быть виден: иначе «кеш холодный» и «кеш отвергнут как чужой»
         * в журнале неразличимы, а это разные вещи. Печать безусловна (не под гейтом
         * трассировки) — событие редкое, по одному на открытие. Потолок объявлен ВСЛУХ,
         * чтобы напечатанное число не приняли за полное. */
        {
            static unsigned long said;
            unsigned long n = __atomic_add_fetch(&said, 1, __ATOMIC_RELAXED);
            if (n <= 4) {
                fprintf(stderr,
                        "macrunner-hb-translation-cache-otvergnut: путь=%s причина=%s "
                        "в_файле=%08x наша=%08x отказов=%lu (печатаю первые 4)\n",
                        c->path, ok == -2 ? "чужая-сборка" : "формат",
                        (unsigned)foreign, (unsigned)build_stamp32(), n);
                fflush(stderr);
            }
        }
    }
    fp = fopen(c->path, "wb");
    if (!fp) return -1;
    if (write_header(fp, c->format_version, c->abi_version) != 0) { fclose(fp); return -1; }
    if (flush_and_sync(fp) != 0) { fclose(fp); return -1; }
    if (fclose(fp) != 0) return -1;
    return 0;
}

static hb_result_t load_entries(hb_cache_t* c, hb_disk_entry_t** out_entries, size_t* out_count) {
    FILE* fp;
    size_t cap = 16, count = 0;
    hb_disk_entry_t* entries;
    if (!c || !out_entries || !out_count) return HB_ERR_INVALID_ARG;
    *out_entries = NULL;
    *out_count = 0;
    fp = fopen(c->path, "rb");
    if (!fp) return HB_OK;
    if (read_header(fp, c->format_version, c->abi_version, NULL) != 0) {
        c->stats.corrupt_entries_ignored++;
        fclose(fp);
        return HB_OK;
    }
    entries = calloc(cap, sizeof(*entries));
    if (!entries) { fclose(fp); return HB_ERR_OUT_OF_MEMORY; }
    for (;;) {
        hb_aot_entry_meta_t meta;
        hb_cache_key_t key;
        if (fread(&meta, sizeof(meta), 1, fp) != 1) break;
        if (meta.key_size != sizeof(hb_cache_key_t) || meta.native_size > (128u * 1024u * 1024u)) {
            c->stats.corrupt_entries_ignored++;
            break;
        }
        if (fread(&key, sizeof(key), 1, fp) != 1) {
            c->stats.corrupt_entries_ignored++;
            break;
        }
        if (count >= cap) {
            cap *= 2;
            hb_disk_entry_t* n = realloc(entries, cap * sizeof(*entries));
            if (!n) { free_entries(entries, count); fclose(fp); return HB_ERR_OUT_OF_MEMORY; }
            memset(n + count, 0, (cap - count) * sizeof(*entries));
            entries = n;
        }
        entries[count].key = key;
        entries[count].native_size = meta.native_size;
        entries[count].steps = meta.steps;
        entries[count].valid = meta.valid;
        entries[count].unsupported = meta.unsupported;
        if (meta.native_size) {
            entries[count].native_code = malloc(meta.native_size);
            if (!entries[count].native_code) { free_entries(entries, count); fclose(fp); return HB_ERR_OUT_OF_MEMORY; }
            if (fread(entries[count].native_code, 1, meta.native_size, fp) != meta.native_size) {
                c->stats.corrupt_entries_ignored++;
                free(entries[count].native_code);
                entries[count].native_code = NULL;
                break;
            }
        }
        count++;
    }
    fclose(fp);
    *out_entries = entries;
    *out_count = count;
    return HB_OK;
}

static hb_result_t write_entries_atomic(hb_cache_t* c, const hb_disk_entry_t* entries, size_t count) {
    char tmp[560];
    FILE* fp;
    if (!c) return HB_ERR_INVALID_ARG;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", c->path, (long)getpid());
    fp = fopen(tmp, "wb");
    if (!fp) return HB_ERR_NOT_FOUND;
    if (write_header(fp, c->format_version, c->abi_version) != 0) { fclose(fp); unlink(tmp); return HB_ERR_NOT_FOUND; }
    for (size_t i = 0; i < count; i++) {
        if (write_entry(fp, &entries[i]) != 0) { fclose(fp); unlink(tmp); return HB_ERR_NOT_FOUND; }
    }
    if (flush_and_sync(fp) != 0) { fclose(fp); unlink(tmp); return HB_ERR_NOT_FOUND; }
    if (fclose(fp) != 0) { unlink(tmp); return HB_ERR_NOT_FOUND; }
    if (rename(tmp, c->path) != 0) { unlink(tmp); return HB_ERR_NOT_FOUND; }
    c->dirty = false;
    return HB_OK;
}

static hb_result_t append_entry(hb_cache_t* c, const hb_disk_entry_t* entry) {
    FILE* fp;

    if (!c || !entry) return HB_ERR_INVALID_ARG;
    if (force_aot_sync_failure()) return HB_ERR_NOT_FOUND;
    fp = fopen(c->path, "ab");
    if (!fp) return HB_ERR_NOT_FOUND;
    if (write_entry(fp, entry) != 0) { fclose(fp); return HB_ERR_NOT_FOUND; }
    if (fflush(fp) != 0) { fclose(fp); return HB_ERR_NOT_FOUND; }
    if (fclose(fp) != 0) return HB_ERR_NOT_FOUND;
    c->dirty = true;
    return HB_OK;
}

hb_cache_t* hb_cache_open(const char* root, const hb_cache_options_t* options) {
    hb_cache_t* c;
    char want_root[512], want_path[512];
    uint32_t fv = options && options->format_version ? options->format_version : HB_AOT_VERSION;
    uint32_t av = options && options->abi_version ? options->abi_version : HB_AOT_ABI;
    bool share = cache_sharing_enabled();

    memset(want_root, 0, sizeof(want_root));
    if (root && root[0]) strncpy(want_root, root, sizeof(want_root) - 1);
    else strncpy(want_root, "build/hyperbridge-cache", sizeof(want_root) - 1);
    snprintf(want_path, sizeof(want_path), "%s/translation-cache.bin", want_root);

    /* Fast path: an identical handle already exists in this process. Same file AND same
     * versions -- a version mismatch means a different on-disk format, so aliasing would hand
     * back entries the caller cannot read. */
    if (share) {
        pthread_mutex_lock(&g_shared_mu);
        if (g_shared_cache && g_shared_cache->format_version == fv &&
            g_shared_cache->abi_version == av &&
            strcmp(g_shared_cache->path, want_path) == 0) {
            g_shared_cache->refcount++;
            g_shared_reuses++;
            c = g_shared_cache;
            pthread_mutex_unlock(&g_shared_mu);
            return c;
        }
        pthread_mutex_unlock(&g_shared_mu);
    }

    c = calloc(1, sizeof(hb_cache_t));
    if (!c) return NULL;
    c->format_version = fv;
    c->abi_version = av;
    memcpy(c->root, want_root, sizeof(c->root));
    mkdir(c->root, 0755);
    snprintf(c->path, sizeof(c->path), "%s", want_path);
    if (ensure_file(c) != 0) { free(c); return NULL; }
    if (load_entries(c, &c->entries, &c->count) != HB_OK) { free(c); return NULL; }
    c->stats.entries_loaded = c->count;
    c->stats.entries_current = c->count;
    c->cap = c->count ? c->count : 16;

    if (share) {
        pthread_mutex_lock(&g_shared_mu);
        if (g_shared_cache && g_shared_cache->format_version == fv &&
            g_shared_cache->abi_version == av &&
            strcmp(g_shared_cache->path, want_path) == 0) {
            /* Lost a race: another thread published an identical handle while this one was
             * loading. Drop ours and join theirs -- two live handles on one file is exactly the
             * lost-update hazard this change exists to remove. */
            g_shared_cache->refcount++;
            g_shared_reuses++;
            hb_cache_t* winner = g_shared_cache;
            pthread_mutex_unlock(&g_shared_mu);
            free_entries(c->entries, c->count);
            free(c->hash_index);
            free(c);
            return winner;
        }
        if (!g_shared_cache) {
            if (pthread_mutex_init(&c->lock, NULL) == 0) {
                c->shared = true;
                c->refcount = 1;
                g_shared_cache = c;
                g_shared_opens++;
                fprintf(stderr, "macrunner-hb-cache-shared: mode=shared path=%s entries=%zu\n",
                        c->path, c->count);
                fflush(stderr);
            }
            /* mutex_init failure -> stays unshared; correct, just not shared. */
        }
        pthread_mutex_unlock(&g_shared_mu);
    }
    return c;
}

/* Reuse counters, for proving the shared path was actually taken rather than assumed. */
void hb_cache_shared_stats(unsigned long long* opens, unsigned long long* reuses) {
    pthread_mutex_lock(&g_shared_mu);
    if (opens) *opens = g_shared_opens;
    if (reuses) *reuses = g_shared_reuses;
    pthread_mutex_unlock(&g_shared_mu);
}

hb_cache_t* hb_cache_create(const char* path) {
    hb_cache_t* c = calloc(1, sizeof(hb_cache_t));
    if (!c) return NULL;
    c->format_version = HB_AOT_VERSION;
    c->abi_version = HB_AOT_ABI;
    if (path && path[0]) strncpy(c->path, path, sizeof(c->path) - 1);
    else strncpy(c->path, "build/hyperbridge-cache/translation-cache.bin", sizeof(c->path) - 1);
    if (ensure_file(c) != 0) { free(c); return NULL; }
    if (load_entries(c, &c->entries, &c->count) != HB_OK) { free(c); return NULL; }
    c->stats.entries_loaded = c->count;
    c->stats.entries_current = c->count;
    c->cap = c->count ? c->count : 16;
    return c;
}

void hb_cache_destroy(hb_cache_t* cache) {
    if (!cache) return;
    if (cache->shared) {
        pthread_mutex_lock(&g_shared_mu);
        if (g_shared_cache == cache) g_shared_cache = NULL;
        pthread_mutex_unlock(&g_shared_mu);
        pthread_mutex_destroy(&cache->lock);
    }
    free_entries(cache->entries, cache->count);
    free(cache->hash_index);
    free(cache);
}
void hb_cache_close(hb_cache_t* cache) {
    if (!cache) return;
    if (cache->shared) {
        /* Only the LAST close writes back and frees. This also removes the lost-update hazard
         * the unshared path carries: 77 handles on one file, each rewriting it wholesale from a
         * private snapshot through rename(), is last-close-wins. (Not observed in timeout-killed
         * runs, which never destroy a runtime at all -- but a clean exit is exactly what a user
         * quitting the game produces.) */
        pthread_mutex_lock(&g_shared_mu);
        if (cache->refcount > 1) {
            cache->refcount--;
            pthread_mutex_unlock(&g_shared_mu);
            return;
        }
        cache->refcount = 0;
        pthread_mutex_unlock(&g_shared_mu);
    }
    if (cache->dirty) (void)write_entries_atomic(cache, cache->entries, cache->count);
    hb_cache_destroy(cache);
}

static uint64_t hb_cache_key_hash(const hb_cache_key_t* k) {
    const uint8_t* p = (const uint8_t*)k;
    uint64_t h = 1469598103934665603ULL;  /* FNV-1a 64 over the 48-byte key (no padding) */
    for (size_t i = 0; i < sizeof(*k); i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/* Insert entry position `pos` into the hash index, overwriting any existing slot for the same
 * key. Rebuild iterates positions forward, so the highest (most-recent) position wins for a
 * duplicate key -- matching the old backward linear scan when the append-log holds duplicates. */
static void hb_cache_index_insert_pos(hb_cache_t* c, size_t pos) {
    const hb_cache_key_t* key;
    size_t mask, start, i;
    if (!c->hash_index || c->hash_cap == 0 || pos >= c->count) return;
    key = &c->entries[pos].key;
    mask = c->hash_cap - 1;
    start = (size_t)(hb_cache_key_hash(key) & mask);
    for (i = 0; i < c->hash_cap; i++) {
        size_t slot = (start + i) & mask;
        size_t cur = c->hash_index[slot];
        if (cur == HB_CACHE_INDEX_EMPTY) { c->hash_index[slot] = pos; return; }
        if (cur < c->count && memcmp(&c->entries[cur].key, key, sizeof(*key)) == 0) {
            c->hash_index[slot] = pos;  /* same key: keep most-recent position */
            return;
        }
    }
    /* table full (cannot happen at load factor <= 0.5) -> leave unindexed; lookup still falls
     * back to the linear scan, so correctness is preserved. */
}

static void hb_cache_index_rebuild(hb_cache_t* c) {
    size_t need = c->count * 2 + 1, cap = 32, i, pos;
    size_t* idx;
    while (cap < need) cap <<= 1;
    idx = realloc(c->hash_index, cap * sizeof(*idx));
    if (!idx) {  /* OOM: drop the index; lookups degrade to the linear scan (correct, slow) */
        free(c->hash_index);
        c->hash_index = NULL;
        c->hash_cap = 0;
        c->index_valid = false;
        return;
    }
    c->hash_index = idx;
    c->hash_cap = cap;
    for (i = 0; i < cap; i++) c->hash_index[i] = HB_CACHE_INDEX_EMPTY;
    for (pos = 0; pos < c->count; pos++) hb_cache_index_insert_pos(c, pos);
    c->index_valid = true;
}

static void hb_cache_index_ensure(hb_cache_t* c) {
    if (c->index_valid && c->hash_index && c->hash_cap >= c->count * 2) return;
    hb_cache_index_rebuild(c);
}

/* Position of `key` in `entries`, or HB_CACHE_INDEX_EMPTY. O(1) via the hash index when present;
 * else the original backward linear scan. Full-key memcmp is always the authority. */
static size_t hb_cache_find_pos(hb_cache_t* c, const hb_cache_key_t* key) {
    hb_cache_index_ensure(c);
    if (c->hash_index && c->index_valid && c->hash_cap) {
        size_t mask = c->hash_cap - 1;
        size_t start = (size_t)(hb_cache_key_hash(key) & mask);
        for (size_t i = 0; i < c->hash_cap; i++) {
            size_t slot = (start + i) & mask;
            size_t pos = c->hash_index[slot];
            if (pos == HB_CACHE_INDEX_EMPTY) return HB_CACHE_INDEX_EMPTY;
            if (pos < c->count && memcmp(&c->entries[pos].key, key, sizeof(*key)) == 0) return pos;
        }
        return HB_CACHE_INDEX_EMPTY;
    }
    for (size_t i = c->count; i > 0; i--) {
        size_t pos = i - 1;
        if (memcmp(&c->entries[pos].key, key, sizeof(*key)) == 0) return pos;
    }
    return HB_CACHE_INDEX_EMPTY;
}

/* ── Locked internals ──────────────────────────────────────────────────────────────────────
 * Every public entry point below takes c->lock (a no-op unless the handle is shared) and calls
 * exactly one of these. The split exists so no public function can call another public function
 * and self-deadlock -- hb_cache_lookup->hb_cache_get, hb_cache_store->hb_cache_put and
 * hb_cache_prune->hb_cache_clear were all doing precisely that before sharing existed.
 * INVARIANT: a *_locked function never calls a public hb_cache_* function. */
static hb_result_t cache_get_locked(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t** out) {
    size_t pos;
    if (!cache || !key || !out) return HB_ERR_INVALID_ARG;
    *out = NULL;
    cache->stats.lookups++;
    pos = hb_cache_find_pos(cache, key);
    if (pos != HB_CACHE_INDEX_EMPTY) {
        hb_cache_entry_t* e = calloc(1, sizeof(*e));
        if (!e) return HB_ERR_OUT_OF_MEMORY;
        e->key = cache->entries[pos].key;
        e->valid = cache->entries[pos].valid != 0;
        e->unsupported = cache->entries[pos].unsupported != 0;
        e->steps = cache->entries[pos].steps;
        e->native_size = cache->entries[pos].native_size;
        if (e->native_size) {
            e->native_code = malloc(e->native_size);
            if (!e->native_code) { free(e); return HB_ERR_OUT_OF_MEMORY; }
            memcpy(e->native_code, cache->entries[pos].native_code, e->native_size);
        }
        *out = e;
        cache->stats.hits++;
        return HB_OK;
    }
    cache->stats.misses++;
    return HB_ERR_NOT_FOUND;
}

static hb_result_t cache_put_locked(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t* entry) {
    size_t pos;
    bool replacing;
    if (!cache || !key || !entry) return HB_ERR_INVALID_ARG;
    pos = hb_cache_find_pos(cache, key);
    if (pos == HB_CACHE_INDEX_EMPTY) pos = cache->count;
    replacing = pos != cache->count;
    if (pos == cache->count) {
        if (cache->count >= cache->cap) {
            size_t new_cap = cache->cap ? cache->cap * 2 : 16;
            hb_disk_entry_t* n = realloc(cache->entries, new_cap * sizeof(*cache->entries));
            if (!n) return HB_ERR_OUT_OF_MEMORY;
            memset(n + cache->cap, 0, (new_cap - cache->cap) * sizeof(*n));
            cache->entries = n;
            cache->cap = new_cap;
        }
        cache->count++;
    } else {
        free(cache->entries[pos].native_code);
    }
    memset(&cache->entries[pos], 0, sizeof(cache->entries[pos]));
    cache->entries[pos].key = *key;
    cache->entries[pos].native_size = entry->native_size;
    cache->entries[pos].steps = entry->steps;
    cache->entries[pos].valid = entry->valid ? 1 : 0;
    cache->entries[pos].unsupported = entry->unsupported ? 1 : 0;
    if (entry->native_code && entry->native_size) {
        cache->entries[pos].native_code = malloc(entry->native_size);
        if (!cache->entries[pos].native_code) return HB_ERR_OUT_OF_MEMORY;
        memcpy(cache->entries[pos].native_code, entry->native_code, entry->native_size);
        cache->stats.bytes_stored += entry->native_size;
    }
    cache->stats.entries_stored++;
    if (!replacing) {
        /* new entry appended at `pos`: keep the hash index in sync (idempotent if ensure
         * already rebuilt to include it). */
        hb_cache_index_ensure(cache);
        if (cache->hash_index && cache->index_valid)
            hb_cache_index_insert_pos(cache, pos);
    }
    cache->stats.entries_current = cache->count;
    return append_entry(cache, &cache->entries[pos]);
}

static hb_result_t cache_invalidate_locked(hb_cache_t* cache, uint32_t version) {
    size_t count, keep = 0;
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    count = cache->count;
    for (size_t i = 0; i < count; i++) {
        if (cache->entries[i].key.version == version) {
            if (keep != i) cache->entries[keep] = cache->entries[i];
            keep++;
        } else {
            free(cache->entries[i].native_code);
            cache->stats.invalidations++;
        }
    }
    cache->count = keep;
    cache->stats.entries_current = cache->count;
    cache->index_valid = false;  /* entries compacted -> positions changed; rebuild index lazily */
    r = write_entries_atomic(cache, cache->entries, cache->count);
    return r;
}

static hb_result_t cache_invalidate_module_locked(hb_cache_t* cache, uint64_t module_id) {
    size_t count, keep = 0;
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    count = cache->count;
    for (size_t i = 0; i < count; i++) {
        if (cache->entries[i].key.module_id != module_id) {
            if (keep != i) cache->entries[keep] = cache->entries[i];
            keep++;
        } else {
            free(cache->entries[i].native_code);
            cache->stats.invalidations++;
        }
    }
    cache->count = keep;
    cache->stats.entries_current = cache->count;
    cache->index_valid = false;  /* entries compacted -> positions changed; rebuild index lazily */
    r = write_entries_atomic(cache, cache->entries, cache->count);
    return r;
}

static hb_result_t cache_clear_locked(hb_cache_t* cache) {
    if (!cache) return HB_ERR_INVALID_ARG;
    free_entries(cache->entries, cache->count);
    cache->entries = NULL;
    cache->count = 0;
    cache->cap = 0;
    cache->stats.entries_current = 0;
    cache->index_valid = false;  /* all entries gone -> drop the index (rebuilt empty on next use) */
    cache->stats.invalidations++;
    return write_entries_atomic(cache, NULL, 0);
}

/* ── Public entry points: take the handle lock, delegate to exactly one *_locked ──────────── */

hb_result_t hb_cache_get(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t** out) {
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    cache_lock(cache);
    r = cache_get_locked(cache, key, out);
    cache_unlock(cache);
    return r;
}

hb_result_t hb_cache_lookup(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t** out) {
    return hb_cache_get(cache, key, out);
}

hb_result_t hb_cache_put(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t* entry) {
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    cache_lock(cache);
    r = cache_put_locked(cache, key, entry);
    cache_unlock(cache);
    return r;
}

hb_result_t hb_cache_store(hb_cache_t* cache, const hb_cache_key_t* key, const uint8_t* native_blob, size_t native_size, const hb_cache_entry_t* metadata) {
    hb_cache_entry_t entry;
    hb_result_t r;
    if (!cache || !key) return HB_ERR_INVALID_ARG;
    memset(&entry, 0, sizeof(entry));
    if (metadata) entry = *metadata;
    entry.key = *key;
    entry.native_code = (uint8_t*)native_blob;
    entry.native_size = native_size;
    entry.valid = true;
    cache_lock(cache);
    r = cache_put_locked(cache, key, &entry);
    cache_unlock(cache);
    return r;
}

hb_result_t hb_cache_invalidate(hb_cache_t* cache, uint32_t version) {
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    cache_lock(cache);
    r = cache_invalidate_locked(cache, version);
    cache_unlock(cache);
    return r;
}

hb_result_t hb_cache_invalidate_module(hb_cache_t* cache, uint64_t module_id) {
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    cache_lock(cache);
    r = cache_invalidate_module_locked(cache, module_id);
    cache_unlock(cache);
    return r;
}

hb_result_t hb_cache_clear(hb_cache_t* cache) {
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    cache_lock(cache);
    r = cache_clear_locked(cache);
    cache_unlock(cache);
    return r;
}

hb_result_t hb_cache_prune(hb_cache_t* cache, uint64_t max_bytes) {
    struct stat st;
    hb_result_t r;
    if (!cache) return HB_ERR_INVALID_ARG;
    cache_lock(cache);
    if (stat(cache->path, &st) != 0 || (uint64_t)st.st_size <= max_bytes) {
        cache_unlock(cache);
        return HB_OK;
    }
    r = cache_clear_locked(cache);
    cache_unlock(cache);
    return r;
}

hb_result_t hb_cache_stats(hb_cache_t* cache, hb_cache_stats_t* out) {
    if (!cache || !out) return HB_ERR_INVALID_ARG;
    cache_lock(cache);
    *out = cache->stats;
    out->entries_current = cache->count;
    cache_unlock(cache);
    return HB_OK;
}

void hb_cache_entry_free(hb_cache_entry_t* entry) {
    if (!entry) return;
    free(entry->native_code);
    free(entry);
}

hb_result_t hb_cache_key_compute(const uint8_t* code, size_t len, hb_arch_t arch, uint32_t version, hb_cache_key_t* out) {
    if (!code || !out) return HB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(hb_cache_key_t));
    out->version = version;
    out->abi_version = HB_AOT_ABI;
    out->arch = (uint8_t)arch;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) { h ^= code[i]; h *= 1099511628211ULL; }
    out->code_hash = h;
    out->code_len = len;
    return HB_OK;
}
