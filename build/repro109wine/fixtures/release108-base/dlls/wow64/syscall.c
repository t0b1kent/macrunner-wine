/*
 * WoW64 syscall wrapping
 *
 * Copyright 2021 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <setjmp.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "rtlsupportapi.h"
#include "wine/unixlib.h"
#include "wine/asm.h"
#include "wow64_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wow);

USHORT native_machine = 0;
USHORT current_machine = 0;
ULONG_PTR args_alignment = 0;
ULONG_PTR highest_user_address = 0x7ffeffff;
ULONG_PTR default_zero_bits = 0x7fffffff;
ULONG_PTR macrunner_wow64_guest32_base = 0;
static HANDLE process_heap;

/***********************************************************************
 *  ★★★★ ПАКЕТ-2 08.09.2026 — ВЛАДЕЛЕЦ CPU, КАКИМ ЕГО ВИДИТ wow64.dll (семьи T1/T5/T10)
 *
 * wow64.dll — ТРЕТЬЯ половина: не unix-часть ntdll и не PE-часть ntdll. Своего доступа к
 * выбору двигателя у неё не было, поэтому весь марш HyperBridge в обратных вызовах и в
 * переводе отказа исполнения оставался включённым при уже выбранном FEX.
 *
 * ВТОРОЙ СЕЛЕКТОР НЕ ЗАВОДИТСЯ. Берётся ТОТ ЖЕ, что у пакетов 1 и 3 —
 * `macrunner_cpu_backend_is_hb()` из ntdll (dlls/ntdll/loader.c:1069), по имени, тем же
 * способом `RtlFindExportedRoutineByName`, каким этот файл уже берёт `LdrSystemDllInitBlock`
 * и всё семейство `BTCpu*`. Значение и кеш — ОДНИ на процесс, они лежат в ntdll.
 *
 * ★ ПОЧЕМУ «НЕ НАШЁЛ» НЕ КЕШИРУЕТСЯ И ПЕЧАТАЕТСЯ ГРОМКО. Молчаливый ответ «hb» при
 * ненайденном символе — это ровно наш класс отказа «гейт выключен, а мерили как
 * включённый»: означал бы он на деле, что ntdll.dll и wow64.dll из РАЗНЫХ сборок
 * (разъехавшийся дист), а выглядело бы как честная рука hb. Поэтому:
 *   - ответ кешируется ТОЛЬКО когда символ найден;
 *   - при ненайденном печатается `sel=НЕ-НАЙДЕН`, и прогон с этой строкой
 *     НЕДЕЙСТВИТЕЛЕН, а не «прошёл на hb».
 * Умолчание при ненайденном — TRUE (hb), потому что рука hb несёт все наши прежние
 * замеры и менять её молча нельзя; но доказательством служит НОЛЬ строк `НЕ-НАЙДЕН`. */
int macrunner_wow64_cpu_hb = -1;   /* -1 не спрошено, 1 hb, 0 не hb; читается инлайном в заголовке */

BOOL macrunner_wow64_cpu_is_hb_slow(void)
{
    if (macrunner_wow64_cpu_hb < 0)
    {
        BOOL (*p_is_hb)(void) = NULL;
        UNICODE_STRING str;
        HMODULE mod = NULL;

        RtlInitUnicodeString( &str, L"ntdll.dll" );
        if (!LdrGetDllHandle( NULL, 0, &str, &mod ) && mod)
            p_is_hb = RtlFindExportedRoutineByName( mod, "macrunner_cpu_backend_is_hb" );

        if (!p_is_hb)
        {
            static unsigned int mr_lost;
            if (mr_lost++ < 8)
                MESSAGE( "macrunner-paket2-selector: sel=НЕ-НАЙДЕН ntdll=%p — ПРОГОН НЕДЕЙСТВИТЕЛЕН\n",
                         mod );
            return TRUE;
        }
        macrunner_wow64_cpu_hb = p_is_hb() ? 1 : 0;
        MESSAGE( "macrunner-paket2-selector: sel=%s ntdll=%p\n",
                 macrunner_wow64_cpu_hb ? "hb" : "ne-hb", mod );
    }
    return macrunner_wow64_cpu_hb != 0;
}

/* Двусторонний прибор PE-половины WOW64 — тот же принцип, что у пакета 3: печатается
 * ОБЕ стороны, иначе «погашено» неотличимо от «сюда не дошли». Счёт без потолка. */
BOOL macrunner_wow64_paket2_mute( const char *family )
{
    /* ★ Счётчики ОТДЕЛЬНЫЕ НА СЕМЬЮ. Общая пара смешала бы редкую семью (T5-base — раз
     * на поток) с частой (T1 — тысячи за прогон), и число редкой утонуло бы в чужом.
     * Ключ — сам указатель строкового литерала: у каждого места вызова он свой и
     * постоянен, сравнивать содержимое не нужно. */
    static struct mr_fam { const char *key; unsigned int muted, passed; } fams[12];
    BOOL mute = !macrunner_wow64_is_hb();
    struct mr_fam *f = NULL;
    unsigned int i, n;

    for (i = 0; i < ARRAY_SIZE(fams); i++)
    {
        if (fams[i].key == family) { f = &fams[i]; break; }
        if (!fams[i].key) { fams[i].key = family; f = &fams[i]; break; }
    }
    if (!f) f = &fams[ARRAY_SIZE(fams) - 1];

    n = mute ? ++f->muted : ++f->passed;
    if (n <= 8 || !(n % 512))
        MESSAGE( "macrunner-paket2-pe: family=%s state=%s n=%u\n",
                 family ? family : "?", mute ? "MUTED" : "PASSED", n );
    return mute;
}

typedef NTSTATUS (WINAPI *syscall_thunk)( UINT *args );

static const syscall_thunk syscall_thunks[] =
{
#define SYSCALL_ENTRY(id,name,args) [id] = wow64_ ## name,
    ALL_SYSCALLS32
#undef SYSCALL_ENTRY
};

static BYTE syscall_args[ARRAY_SIZE(syscall_thunks)] =
{
#define SYSCALL_ENTRY(id,name,args) [id] = args,
    ALL_SYSCALLS32
#undef SYSCALL_ENTRY
};

static SYSTEM_SERVICE_TABLE syscall_tables[4] =
{
    { (ULONG_PTR *)syscall_thunks, NULL, ARRAY_SIZE(syscall_thunks), syscall_args }
};

#ifdef __aarch64__
void DECLSPEC_NORETURN macrunner_wow64_longjmp_direct( jmp_buf buf, int ret );
__ASM_GLOBAL_FUNC( macrunner_wow64_longjmp_direct,
                   "mov x2, x0\n\t"
                   "cmp w1, #1\n\t"
                   "csinc w0, w1, wzr, hi\n\t"
                   "ldp x19, x20, [x2, #0x10]\n\t"
                   "ldp x21, x22, [x2, #0x20]\n\t"
                   "ldp x23, x24, [x2, #0x30]\n\t"
                   "ldp x25, x26, [x2, #0x40]\n\t"
                   "ldp x27, x28, [x2, #0x50]\n\t"
                   "ldp x29, x30, [x2, #0x60]\n\t"
                   "ldr x3, [x2, #0x70]\n\t"
                   "ldr w4, [x2, #0x78]\n\t"
                   "msr fpcr, x4\n\t"
                   "ldr w4, [x2, #0x7c]\n\t"
                   "msr fpsr, x4\n\t"
                   "ldp d8, d9, [x2, #0x80]\n\t"
                   "ldp d10, d11, [x2, #0x90]\n\t"
                   "ldp d12, d13, [x2, #0xa0]\n\t"
                   "ldp d14, d15, [x2, #0xb0]\n\t"
                   "mov sp, x3\n\t"
                   "ret" )
#endif

/* header for Wow64AllocTemp blocks; probably not the right layout */
struct mem_header
{
    struct mem_header *next;
    void              *__pad;
    BYTE               data[1];
};

/* stack frame for user callbacks */
struct user_callback_frame
{
    struct user_callback_frame *prev_frame;
    struct mem_header          *temp_list;
    void                      **ret_ptr;
    ULONG                      *ret_len;
    NTSTATUS                    status;
    jmp_buf                     jmpbuf;
    /* ★ MacRunner 2026-08-28: вошёл ли гость в этот обратный вызов С ТРАМПЛИНА
     * (eip 0x00270000). Признак снимается на входе, где он достоверен, и нужен
     * при возврате: восстанавливать сохранённый контекст можно ТОЛЬКО для входа
     * с трамплина. Вложенный вход (1 из 52) уже стоит там, где надо. */
    BOOL                        macrunner_cb_from_trampoline;
};

/* stack frame for user APCs */
struct user_apc_frame
{
    struct user_apc_frame *prev_frame;
    CONTEXT               *context;
    void                  *wow_context;
};

SYSTEM_DLL_INIT_BLOCK *pLdrSystemDllInitBlock = NULL;

static WOW64INFO *wow64info;
static WORD ss32_sel;

/* cpu backend dll functions */
/* the function prototypes most likely differ from Windows */
static void *   (WINAPI *pBTCpuGetBopCode)(void);
/* ★ 2618: «какой системный вызов в полёте» по потокам. Линейный поиск по восьми
 * записям — потоков здесь единицы, дешевле любой синхронизации. */
#define MACRUNNER_SVC_SLOTS 8
/* ★★★ 26.08.2026 — КОНТЕКСТ ГОСТЯ НА ВХОДЕ В СИСТЕМНЫЙ ВЫЗОВ.
 *
 * Обратный вызов может родиться ИЗНУТРИ обработки системного вызова (например,
 * NtGdiGetDCDword → выделение памяти → оконная процедура с WM_NCHITTEST). Тогда
 * `pBTCpuGetContext` отдаёт не трамплин, а точку ПОСЛЕ прошлого возврата: у 51 здорового
 * вызова за прогон Diablo сохранённый eip = 0x00270000 (трамплин), у единственного
 * больного — 0x778f15d9, обычный код. Восстановление такого контекста при возврате
 * ставит гостю esp/ebp, не отвечающие его стеку (расхождение 248 байт), и `leave; ret`
 * берёт со стека мусор: (1801005b, 0000000d), где 0x0D = HTTOPLEFT — результат того же
 * NCHITTEST. Гость уходит исполнять код по адресу 13.
 *
 * Поэтому запоминаем контекст на ВХОДЕ в системный вызов первого уровня и отдаём его
 * вложенному обратному вызову. */
static struct {
    ULONG thread; ULONG num; ULONG depth; ULONG live;
    I386_CONTEXT entry_ctx32;   /* контекст гостя на входе в вызов первого уровня */
    ULONG        has_entry_ctx; /* 0 — не снят */
} macrunner_svc_slot[MACRUNNER_SVC_SLOTS];

/* Гейт: 0 — прежнее поведение (контекст берётся текущий), 1 — контекст входа.
 * Держим выключенным по умолчанию, пока не мерено на второй мишени. */
static int macrunner_nested_cb_ctx(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING( L"MACRUNNER_WOW64_NESTED_CB_CTX" );
        WCHAR value[4] = { 0 };
        UNICODE_STRING val;
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = 0;
        if (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
            value[0] >= '0' && value[0] <= '9')
            cached = value[0] - '0';
        MESSAGE( "macrunner-gate: MACRUNNER_WOW64_NESTED_CB_CTX=%d "
                 "(1 - kontekst vhoda, 2 - ne vosstanavlivat)\n", cached );
    }
    return cached;
}

static unsigned macrunner_svc_index(void)
{
    ULONG me = (ULONG)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
    unsigned i;

    for (i = 0; i < MACRUNNER_SVC_SLOTS; i++)
        if (macrunner_svc_slot[i].thread == me) return i;
    for (i = 0; i < MACRUNNER_SVC_SLOTS; i++)
        if (!macrunner_svc_slot[i].thread) { macrunner_svc_slot[i].thread = me; return i; }
    return 0;
}

static void macrunner_frame_watch( ULONG num, ULONG depth, const char *gde );

/* ★ MacRunner, лейн ЛЕСТНИЦА, итерация 2775 — ГЕЙТ НА ВЫБОРКУ ПО ВХОДУ, УМОЛЧАНИЕ ВЫКЛ.
 *
 * ЗАЧЕМ. d2774 с выборкой по входу шёл 708 с и до стены НЕ дошёл (доставок 16 против 64,
 * непарковавшихся 0 против 1); d2768 без неё — 65 с и дошёл. Но машина в эти два прогона была
 * загружена по-разному, поэтому «виноват зонд» пока предположение. Гейт делает A/B возможным
 * при ОДНОМ двоичном файле: обе руки — один и тот же wow64.dll, различие только здесь.
 *
 * Умолчание 0 — это та конфигурация, что ДОКАЗАННО доходит до стены. Читаем ЗНАЧЕНИЕ, а не
 * наличие: гейт «по наличию» вместе с `${VAR:-0}` в сценарии даёт всегда включено (урок лейна).
 * Печать одна на процесс — иначе активность гейта пришлось бы принимать на веру. */
static BOOL macrunner_frame_watch_enter_enabled(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING( L"MACRUNNER_WOW64_FRAME_WATCH_ENTER" );
        WCHAR value[4] = { 0 };
        UNICODE_STRING val;

        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                 value[0] && value[0] != '0';
        MESSAGE( "macrunner-gate: MACRUNNER_WOW64_FRAME_WATCH_ENTER=%d\n", cached );
    }
    return cached;
}

/* ★ 2809: обход проверки учёта памяти. Умолчание 0 — прежнее поведение. */
static BOOL macrunner_frame_watch_force(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING( L"MACRUNNER_WOW64_FRAME_WATCH_FORCE" );
        WCHAR value[4] = { 0 };
        UNICODE_STRING val;

        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                 value[0] && value[0] != '0';
        MESSAGE( "macrunner-gate: MACRUNNER_WOW64_FRAME_WATCH_FORCE=%d\n", cached );
    }
    return cached;
}

/* ★ ЛЕСТНИЦА 2813 — ГОСТЕВОЙ esp В МОМЕНТ ПЕРЕХОДА. 2812 закрыла замером диспетчер обратного
 * вызова (ноль накрытий за прогон) и оставила ОДНО объяснение: пару {1801005b, 0000000d}
 * проталкивает САМ ГОСТЬ как аргументы NtUserCallHwnd(hwnd, code=13), а ложатся они на ЕЩЁ
 * ЖИВОЙ кадр — то есть вершина стека стоит ВЫШЕ живого кадра. 2812 сама назвала, чем это
 * проверить: напечатать esp на входе в NtUserCallHwnd и на выходе из NtAllocateVirtualMemory
 * и сравнить с 016bf998 (сохранённый ebp умирающей функции, измерен в 2715-2716).
 * Гейт MACRUNNER_WOW64_ESP_PROBE, умолчание 0. */
static BOOL macrunner_esp_probe_enabled(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING( L"MACRUNNER_WOW64_ESP_PROBE" );
        WCHAR value[4] = { 0 };
        UNICODE_STRING val;

        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                 value[0] && value[0] != '0';
        MESSAGE( "macrunner-gate: MACRUNNER_WOW64_ESP_PROBE=%d\n", cached );
    }
    return cached;
}

/* Флаг RESET_STATE здесь НЕ требуется: он означает «контекст переустановлен», а нужно текущее
 * значение на переходе. Что значение осмысленно — не предполагаю: у здоровых вызовов esp обязан
 * лежать в стеке и меняться от вызова к вызову, и это будет видно в печати. */
static BOOL macrunner_peek_i386_sp( ULONG *esp, ULONG *ebp )
{
    WOW64_CPURESERVED *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];
    WOW64_CPU_AREA_INFO info;
    const I386_CONTEXT *ctx;

    if (!cpu) return FALSE;
    if (RtlWow64GetCpuAreaInfo( cpu, 0, &info )) return FALSE;
    if (info.Machine != IMAGE_FILE_MACHINE_I386) return FALSE;
    ctx = (const I386_CONTEXT *)info.Context;
    *esp = ctx->Esp;
    *ebp = ctx->Ebp;
    return TRUE;
}

#define MACRUNNER_ESP_PROBE_FRAME 0x016bf998u

static BOOL macrunner_stale_probe_enabled(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING( L"MACRUNNER_WOW64_STALE_PROBE" );
        WCHAR value[4] = { 0 };
        UNICODE_STRING val;

        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                 value[0] && value[0] != '0';
        MESSAGE( "macrunner-gate: MACRUNNER_WOW64_STALE_PROBE=%d\n", cached );
    }
    return cached;
}

static void macrunner_esp_probe( ULONG num, const char *gde )
{
    static LONG shown;
    ULONG esp = 0, ebp = 0;
    BOOL esp_ok = FALSE;

    if (!macrunner_esp_probe_enabled()) return;
    /* ★ 2822 — ПРЯМОЙ ПРИЗНАК УСТАРЕВШЕГО КАДРА, на ЛЮБОМ вызове, а не на трёх избранных.
     * 2821 доказала числом (71 смена значения за прогон, значения всех сортов), что
     * `016bf998` — обычный горячий слот стека, и вопрос «кто туда пишет» был поставлен
     * неверно. Осталась одна постановка: кто-то держит `ebp`, переживший свой кадр.
     * Признак самоочевиден: стек растёт ВНИЗ, поэтому у живого кадра `ebp >= esp` всегда.
     * `ebp < esp` — кадр за вершиной, то есть мёртвый. Печать по САМОМУ признаку, потолка
     * по номеру вызова нет: именно потолок в 2813 съел то, ради чего зонд писался. */
    /* ★ 2827: СПЛОШНАЯ ПРОВЕРКА УБИВАЛА ПРОГОНЫ. Контроль при прочих равных: тот же двоичный,
     * гейт зонда 0 -> код=0, 64 с, 4398 диспетчеризаций; гейт 1 -> три прогона подряд негодны
     * (137/26 с/дисп=0, 137/34 с/дисп=0, 142/346 с). Разница только в том, что этот блок читает
     * область CPU на КАЖДОМ входе и выходе, то есть ~8800 раз за прогон. Убираю под отдельный
     * гейт с умолчанием 0, чтобы остальная часть зонда снова была пригодна. */
    if (macrunner_stale_probe_enabled())
    {
        static LONG stale_shown;
        ULONG e2 = 0, b2 = 0;

        if (macrunner_peek_i386_sp( &e2, &b2 ) &&
            (b2 < e2 || b2 == MACRUNNER_ESP_PROBE_FRAME) && stale_shown++ < 64)
            MESSAGE( "macrunner-стар2822: %s num=%04lx esp=%08lx ebp=%08lx разн=%ld %s "
                     "поток=%04lx\n",
                     gde, (unsigned long)num, (unsigned long)e2, (unsigned long)b2,
                     (long)(LONG)(b2 - e2),
                     b2 < e2 ? "EBP-НИЖЕ-ESP-КАДР-МЁРТВ" : "EBP-НА-СПОРНОМ-АДРЕСЕ",
                     (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    }
    /* 0x1332 = NtUserCallHwnd (win32u), 0x18 = NtAllocateVirtualMemory (ntdll) — оба опознаны
     * в 2811 как концы рокового промежутка. */
    /* ★ 2816: добавлен 0x11ef (NtGdiGetDCDword). 2815 показала числами, что фатален не
     * «чужой писавший», а СДВИГ esp: 721 виток шёл на esp=016bf914, последний — на 016bf958
     * (+0x44), и то же смещение [esp+0x40] попало ровно на живой кадр 016bf998. Теперь ловим
     * СМЕНУ esp у этого вызова (триггер — само событие, не первые N) и печатаем адрес
     * возврата со стека: он назовёт, кто вызвал виток на новом уровне. */
    if (num != 0x1332 && num != 0x18 && num != 0x11ef) return;
    /* ★ 2814 — ПОТОЛОК СЪЕЛ РОВНО ТО, РАДИ ЧЕГО ЗОНД ПИСАН. В d2813-esp-p2 промежуток события
     * назван как [выход 0018 .. вход 1332], то есть 1332 через этот путь ПРОХОДИТ, а строк
     * зонда для него ноль: первые 24 печати израсходовали 0018 на 36,5 с. Записанный урок
     * проекта — «триггером должно быть САМО событие, а не первые N» — я знала и нарушила.
     * Теперь 1332 печатается ВСЕГДА и потолком не ограничен; потолок оставлен только для
     * рядовых 0018. */
    /* ★ 2826: для 0x18 триггер теперь ПО САМОМУ СОБЫТИЮ — `ebp` равен спорному адресу.
     * 2825 нашла у меня логический пробел: «кадр живой» было доказано на входе в 11ef (T1),
     * а смена значения происходит на T2 = T1 + 2 мс, и между ними `get_pixel_formats` успевает
     * вернуться. `0x18` (calloc) зовётся ИЗНУТРИ её кадра, поэтому его ВЫХОД — последняя точка,
     * где кадр заведомо ещё жив. Печать на этой точке разводит «запись в живой кадр» и
     * «переиспользование мёртвого». Окно по esp оставлено как было, к нему добавлено условие
     * по ebp, потолок на него не действует. */
    if (num == 0x18 && shown >= 24)
    {
        if (!esp_ok)
        {
            if (!macrunner_peek_i386_sp( &esp, &ebp )) { esp = ebp = 0; esp_ok = FALSE; }
            else esp_ok = TRUE;
        }
        if (!(esp_ok &&
              (ebp == MACRUNNER_ESP_PROBE_FRAME ||
               (esp >= MACRUNNER_ESP_PROBE_FRAME - 0x98 &&
                esp <= MACRUNNER_ESP_PROBE_FRAME + 0xe8)))) return;
    }
    if (!esp_ok && !macrunner_peek_i386_sp( &esp, &ebp ))
    {
        /* ★ Молчание больше НЕ двусмысленно: в 2813 нельзя было отличить «esp вне окна» от
         * «область CPU не прочиталась» — оба молчали одинаково. Теперь второе печатается. */
        MESSAGE( "macrunner-esp2813: %s num=%04lx ОБЛАСТЬ-CPU-НЕ-ПРОЧИТАНА поток=%04lx\n",
                 gde, (unsigned long)num,
                 (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
        return;
    }
    shown++;
    if (num == 0x11ef)
    {
        static ULONG last_esp;
        static LONG seen11ef;
        MESSAGE( "macrunner-esp2816: %s num=11ef esp=%08lx ebp=%08lx memory=NOT_ENABLED\n",
                 gde, (unsigned long)esp, (unsigned long)ebp );
        return;
    }
    MESSAGE( "macrunner-esp2813: %s num=%04lx esp=%08lx ebp=%08lx кадр=%08lx разн_esp=%ld "
             "разн_ebp=%ld поток=%04lx\n",
             gde, (unsigned long)num, (unsigned long)esp, (unsigned long)ebp,
             (unsigned long)MACRUNNER_ESP_PROBE_FRAME,
             (long)(LONG)(esp - MACRUNNER_ESP_PROBE_FRAME),
             (long)(LONG)(ebp - MACRUNNER_ESP_PROBE_FRAME),
             (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
}

static void macrunner_svc_enter( ULONG num )
{
    unsigned i = macrunner_svc_index();

    macrunner_svc_slot[i].num = num;
    macrunner_svc_slot[i].depth++;
    macrunner_svc_slot[i].live++;
    /* ★ 2771: выборка и на ВХОДЕ. d2768 показал `в_полёте2674=65` незакрытых входов — значит
     * `leave` зовётся не на всех путях, и одна выборка на выход реже, чем «каждый вызов».
     * Пара вход/выход разделяет: изменилось между выходом N и входом N+1 — писал ГОСТЬ;
     * между входом N и выходом N — писала ХОЗЯЙСКАЯ сторона этого вызова. */
    if (macrunner_frame_watch_enter_enabled())
        macrunner_frame_watch( macrunner_svc_slot[i].num, macrunner_svc_slot[i].depth, "вход" );
    macrunner_esp_probe( num, "вход" );
}

/* ★ ЛЕСТНИЦА 2674 — ПАРНЫЙ ВЫХОД. 2618 сама назвала свою границу: табличка ставится на
 * ВХОДЕ и не очищается, поэтому `посл_вызов=0x18` значит «последний ВОШЕДШИЙ», а не «мы
 * сейчас внутри него». Без пары нельзя отличить «обратный вызов выдан ИЗ выделения памяти»
 * от «выделение давно вернулось, а запись осталась». `live` считает незакрытые входы. */
/* ★ MacRunner, лейн ЛЕСТНИЦА, итерация 2767 — СТОРОЖ ДВУХ СЛОВ КАДРА.
 *
 * ЗАЧЕМ. 2763-2766: кадр гостевой `_get_pixel_formats` (opengl32+0xa15d9, ebp=016bf998) к
 * моменту доставки обратного вызова УЖЕ содержит {описатель GDI, 0000000d} вместо сохранённого
 * ebp и обратного адреса, и функция штатным эпилогом `add esp,0x20; pop esi/edi/ebx/ebp; ret`
 * уходит по адресу 0x0000000d. Шесть регистров отказа сошлись с этим побайтно. Обратный вызов
 * пару не писал (кадр испорчен уже на входе), unix-сторона тоже не писала (зонд 2715: 8 из 8
 * `изменился=0`). Кто пишет — неизвестно.
 *
 * ПОЧЕМУ СВОЙ, А НЕ ГОТОВЫЙ (2766, проверено по коду, а не по имени):
 *   MACRUNNER_HB_TRACE_MEM_WATCH   — весь static в hb_interpreter.c, под JIT слеп;
 *   MACRUNNER_HB_TRACE_GUEST_WRITE — зовётся лишь из hb_memory_write, а в этих прогонах
 *                                    включены все четыре гейта прямой памяти, и записи JIT
 *                                    идут мимо; записи хозяина туда не заходят вовсе.
 * Ноль от них означал бы «не по моему пути», а не «никто не писал».
 *
 * УСТРОЙСТВО. Стоит на ВОЗВРАТЕ ИЗ КАЖДОГО системного вызова (`macrunner_svc_leave`) и
 * сравнивает два слова по фиксированному гостевому адресу. Печатает ТОТ вызов, после которого
 * они изменились.
 *   - Печать ПО СОБЫТИЮ (урок 2612: потолок морит редкое событие голодом): всегда, когда
 *     второе слово стало 0000000d — то есть ровно смертельный узор; плюс первые 8 любых
 *     изменений для обстановки. Слот стека переписывается часто, поэтому без узора был бы потоп.
 *   - Заводится ЛЕНИВО: страницы гостевого стека в начале прогона ещё нет, а __TRY в этом файле
 *     не используется. Раз в 64 вызова спрашиваем NtQueryVirtualMemory, пока не MEM_COMMIT.
 *   - Адрес зашит: он одинаков в 34 прогонах (esp=016bf9a0, ebx=016bf9a4, [ebp+4]=0000000d —
 *     34 из 34). Строка «заведён» печатает начальные значения, так что подмена адреса видна.
 */
#define MACRUNNER_FRAME_WATCH_ADDR_DEFAULT 0x016bf998

/* ★ MacRunner 23.08, лейн ЛЕСТНИЦА, итерация 2808 — АДРЕС СТОРОЖА ЗАДАЁТСЯ СНАРУЖИ.
 * 2807 нашёл, куда его надо нацелить: слот кеша `TEB32+0xb70` = гостевой 0x7f000b70, где
 * запись живёт меньше миллисекунды. Прежде адрес был `#define`, то есть каждая новая цель
 * стоила пересборки и раскладки в два диста. Читаем ЗНАЧЕНИЕ шестнадцатеричным, пустое или
 * нечитаемое — умолчание. Печать одна на процесс: иначе активность пришлось бы брать на веру. */
static ULONG macrunner_frame_watch_addr(void)
{
    static ULONG cached;
    static int parsed;   /* нельзя судить по cached: 0 — законное значение «выключен» */

    if (!parsed)
    {
        parsed = 1;
        UNICODE_STRING name = RTL_CONSTANT_STRING( L"MACRUNNER_WOW64_FRAME_WATCH_ADDR" );
        WCHAR value[24] = { 0 };
        UNICODE_STRING val;
        ULONG got = 0;
        unsigned i = 0;

        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        if (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND)
        {
            if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) i = 2;
            for (; value[i]; i++)
            {
                WCHAR c = value[i];
                ULONG d;

                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else { got = 0; break; }
                got = got * 16 + d;
            }
        }
        /* ★★★★★★ 03.09.2026 — УМОЛЧАНИЯ БОЛЬШЕ НЕТ, И ЭТО ЛЕЧЕНИЕ.
         *
         * Здесь стоял зашитый гостевой адрес 0x016bf998 — он имел смысл для ОДНОЙ
         * мишени в августе. Сторож читал его на КАЖДОМ выходе из системного вызова
         * и без всякого гейта (вызов «выход» гейтован не был). На другой мишени по
         * этому адресу лежит что угодно: установщик GTA Vice City умирал в
         * `macrunner_frame_watch+0x190`, разыменовав 0x330303030 — это байты '0','0',
         * '0','0', то есть кусок строки, принятый за указатель. Установка вставала
         * ровно после «Created temporary directory», и это списывали на движок.
         *
         * Прибор без явно заданного адреса не имеет цели и не должен работать.
         * Ноль означает «выключен», и оба места вызова это уважают. */
        cached = got ? got : 0;
        MESSAGE( "macrunner-gate: MACRUNNER_WOW64_FRAME_WATCH_ADDR=%08lx%s\n",
                 (unsigned long)cached, cached ? "" : " (не задан — сторож ВЫКЛЮЧЕН)" );
    }
    return cached;
}

#define MACRUNNER_FRAME_WATCH_ADDR macrunner_frame_watch_addr()

static void macrunner_frame_watch( ULONG num, ULONG depth, const char *gde )
{
    static LONG armed;            /* 0 — ещё не завёлся, 1 — сторожит */
    /* Нет адреса — нет цели: выходим ДО любого чтения памяти гостя. Разбор у
     * macrunner_frame_watch_addr. */
    if (!MACRUNNER_FRAME_WATCH_ADDR) return;
    static ULONG prev[2];
    static LONG probes, hits;
    /* ★ 2809: ЛЕВЫЙ КОНЕЦ ПРОМЕЖУТКА. 2808 назвал только правый — вызов, на входе в который
     * изменение замечено. Между ним и предыдущей выборкой лежит всё, что и делает запись
     * или обнуление. Помню, какой вызов и какая сторона были в прошлой выборке — тогда
     * промежуток назван с обоих концов. Потолок поднят с 8 до 64: витков 722, восемь мало. */
    static ULONG prev_num;
    static const char *prev_gde = "нет";
    const ULONG *w;
    ULONG cur[2];

    if (!armed)
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T len = 0;

        NTSTATUS qs;
        static int reported;

        if (++probes & 63) return;
        qs = NtQueryVirtualMemory( GetCurrentProcess(),
                                   guest32_host_ptr( MACRUNNER_FRAME_WATCH_ADDR ),
                                   MemoryBasicInformation, &mbi, sizeof(mbi), &len );
        /* ★ MacRunner 23.08, лейн ЛЕСТНИЦА, итерация 2809 — ПОЧЕМУ СТОРОЖ МОЛЧАЛ.
         * d2808: оба гейта доставлены (`ADDR=7f000b70`, `ENTER=1`), а строк сторожа НОЛЬ —
         * значит он не завёлся, и молчала именно эта проверка. Гипотеза: зеркало TEB32
         * создано mmap-ом мимо учёта wine, поэтому `NtQueryVirtualMemory` отвечает MEM_FREE,
         * хотя unix-сторона читает и пишет по этому адресу каждый вызов (2807: 12 из 12).
         * Ровно так проект уже обжигался с `macrunner-hb-vmprobe`. Печатаю ОТВЕТ запроса —
         * догадку заменяю числом — и даю обход `MACRUNNER_WOW64_FRAME_WATCH_FORCE`. */
        if (!reported++)
            MESSAGE( "macrunner-кадр-сторож2767: ЗАПРОС адрес=%08lx хост=%p статус=%08lx "
                     "state=%08lx protect=%08lx alloc=%p тип=%08lx\n",
                     (unsigned long)MACRUNNER_FRAME_WATCH_ADDR,
                     guest32_host_ptr( MACRUNNER_FRAME_WATCH_ADDR ), (unsigned long)qs,
                     (unsigned long)(qs ? 0 : mbi.State), (unsigned long)(qs ? 0 : mbi.Protect),
                     qs ? NULL : mbi.AllocationBase, (unsigned long)(qs ? 0 : mbi.Type) );
        if (!macrunner_frame_watch_force())
        {
            if (qs) return;
            if (mbi.State != MEM_COMMIT) return;
        }
        w = guest32_host_ptr( MACRUNNER_FRAME_WATCH_ADDR );
        {
            SIZE_T copied = 0;
            NTSTATUS status = NtReadVirtualMemory( NtCurrentProcess(), w, prev, sizeof(prev), &copied );
            if (status || copied != sizeof(prev))
            {
                MESSAGE( "macrunner-frame-watch: state=READ_FAILED status=%08lx bytes=%Iu\n", status, copied );
                return;
            }
        }
        armed = 1;
        MESSAGE( "macrunner-кадр-сторож2767: ЗАВЕДЁН адрес=%08lx начальные=%08lx %08lx "
                 "проб=%ld\n", (unsigned long)MACRUNNER_FRAME_WATCH_ADDR,
                 (unsigned long)prev[0], (unsigned long)prev[1], (long)probes );
        return;
    }

    w = guest32_host_ptr( MACRUNNER_FRAME_WATCH_ADDR );
    {
        SIZE_T copied = 0;
        NTSTATUS status = NtReadVirtualMemory( NtCurrentProcess(), w, cur, sizeof(cur), &copied );
        if (status || copied != sizeof(cur))
        {
            MESSAGE( "macrunner-frame-watch: state=READ_FAILED status=%08lx bytes=%Iu\n", status, copied );
            return;
        }
    }
    if (cur[0] == prev[0] && cur[1] == prev[1])
    {
        prev_num = num;
        prev_gde = gde;
        return;
    }
    hits++;
    if (cur[1] == 0x0000000d || hits <= 64)
        MESSAGE( "macrunner-кадр-сторож2767: n=%ld узор=%d промежуток=[%s %08lx .. %s %08lx] "
                 "адрес=%08lx было=%08lx %08lx стало=%08lx %08lx глубина=%lu поток=%04lx\n",
                 (long)hits, cur[1] == 0x0000000d,
                 prev_gde, (unsigned long)prev_num, gde, (unsigned long)num,
                 (unsigned long)MACRUNNER_FRAME_WATCH_ADDR,
                 (unsigned long)prev[0], (unsigned long)prev[1],
                 (unsigned long)cur[0], (unsigned long)cur[1],
                 (unsigned long)depth,
                 (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    prev[0] = cur[0];
    prev[1] = cur[1];
    prev_num = num;
    prev_gde = gde;
}

static void macrunner_svc_leave( void )
{
    unsigned i = macrunner_svc_index();

    if (macrunner_svc_slot[i].live) macrunner_svc_slot[i].live--;
    macrunner_frame_watch( macrunner_svc_slot[i].num, macrunner_svc_slot[i].depth, "выход" );
    macrunner_esp_probe( macrunner_svc_slot[i].num, "выход" );
}

static ULONG macrunner_svc_live( void )
{
    return macrunner_svc_slot[macrunner_svc_index()].live;
}

static ULONG macrunner_svc_current( ULONG *depth )
{
    unsigned i = macrunner_svc_index();

    if (depth) *depth = macrunner_svc_slot[i].depth;
    return macrunner_svc_slot[i].num;
}

static NTSTATUS (WINAPI *pBTCpuGetContext)(HANDLE,HANDLE,void *,void *);
static BOOLEAN  (WINAPI *pBTCpuIsProcessorFeaturePresent)(UINT);
static void     (WINAPI *pBTCpuProcessInit)(void);
static NTSTATUS (WINAPI *pBTCpuSetContext)(HANDLE,HANDLE,void *,void *);
static void     (WINAPI *pBTCpuThreadInit)(void);
static void     (WINAPI *pBTCpuSimulate)(void) __attribute__((used));
static void *   (WINAPI *p__wine_get_unix_opcode)(void);
static void *   (WINAPI *pKiRaiseUserExceptionDispatcher)(void);
void     (WINAPI *pBTCpuFlushInstructionCache2)( const void *, SIZE_T ) = NULL;
void     (WINAPI *pBTCpuFlushInstructionCacheHeavy)( const void *, SIZE_T ) = NULL;
NTSTATUS (WINAPI *pBTCpuNotifyMapViewOfSection)( void *, void *, void *, SIZE_T, ULONG, ULONG ) = NULL;
void     (WINAPI *pBTCpuNotifyMemoryAlloc)( void *, SIZE_T, ULONG, ULONG, BOOL, NTSTATUS ) = NULL;
void     (WINAPI *pBTCpuNotifyMemoryDirty)( void *, SIZE_T ) = NULL;
void     (WINAPI *pBTCpuNotifyMemoryFree)( void *, SIZE_T, ULONG, BOOL, NTSTATUS ) = NULL;
void     (WINAPI *pBTCpuNotifyMemoryProtect)( void *, SIZE_T, ULONG, BOOL, NTSTATUS ) = NULL;
void     (WINAPI *pBTCpuNotifyProcessExecuteFlagsChange)( ULONG ) = NULL;
void     (WINAPI *pBTCpuNotifyReadFile)( HANDLE, void *, SIZE_T, BOOL, NTSTATUS ) = NULL;
void     (WINAPI *pBTCpuNotifyUnmapViewOfSection)( void *, BOOL, NTSTATUS ) = NULL;
NTSTATUS (WINAPI *pBTCpuResetToConsistentState)( EXCEPTION_POINTERS * ) = NULL;
void     (WINAPI *pBTCpuUpdateProcessorInformation)( SYSTEM_CPU_INFORMATION * ) = NULL;
void     (WINAPI *pBTCpuProcessTerm)( HANDLE, BOOL, NTSTATUS ) = NULL;
void     (WINAPI *pBTCpuThreadTerm)( HANDLE, LONG ) = NULL;
NTSTATUS (WINAPI *pBTCpuSuspendLocalThread)( HANDLE, ULONG * ) = NULL;

BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, void *reserved )
{
    if (reason == DLL_PROCESS_ATTACH) LdrDisableThreadCalloutsForDll( inst );
    return TRUE;
}

void __cdecl DECLSPEC_NORETURN __wine_spec_unimplemented_stub( const char *module, const char *function )
{
    EXCEPTION_RECORD record;

    record.ExceptionCode    = EXCEPTION_WINE_STUB;
    record.ExceptionFlags   = EXCEPTION_NONCONTINUABLE;
    record.ExceptionRecord  = NULL;
    record.ExceptionAddress = __wine_spec_unimplemented_stub;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = (ULONG_PTR)module;
    record.ExceptionInformation[1] = (ULONG_PTR)function;
    for (;;) RtlRaiseException( &record );
}

static void DECLSPEC_NORETURN stub_syscall( const char *name )
{
    __wine_spec_unimplemented_stub( "ntdll", name );
}

#define SYSCALL_STUB(name) NTSTATUS WINAPI wow64_ ## name( UINT *args ) { stub_syscall( #name ); }
ALL_SYSCALL_STUBS

static EXCEPTION_RECORD *exception_record_32to64( const EXCEPTION_RECORD32 *rec32 )
{
    EXCEPTION_RECORD *rec;
    unsigned int i;

    rec = Wow64AllocateTemp( sizeof(*rec) );
    rec->ExceptionCode = rec32->ExceptionCode;
    rec->ExceptionFlags = rec32->ExceptionFlags;
    rec->ExceptionRecord = rec32->ExceptionRecord ? exception_record_32to64( guest32_host_ptr(rec32->ExceptionRecord) ) : NULL;
    rec->ExceptionAddress = ULongToPtr( rec32->ExceptionAddress );
    rec->NumberParameters = rec32->NumberParameters;
    for (i = 0; i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
        rec->ExceptionInformation[i] = rec32->ExceptionInformation[i];
    return rec;
}


static void exception_record_64to32( EXCEPTION_RECORD32 *rec32, const EXCEPTION_RECORD *rec )
{
    unsigned int i;

    rec32->ExceptionCode    = rec->ExceptionCode;
    rec32->ExceptionFlags   = rec->ExceptionFlags;
    rec32->ExceptionRecord  = PtrToUlong( rec->ExceptionRecord );
    rec32->ExceptionAddress = PtrToUlong( rec->ExceptionAddress );
    rec32->NumberParameters = rec->NumberParameters;
    for (i = 0; i < rec->NumberParameters; i++)
        rec32->ExceptionInformation[i] = rec->ExceptionInformation[i];
}


static BOOL macrunner_get_reset_i386_context( I386_CONTEXT *ctx )
{
    WOW64_CPURESERVED *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];
    WOW64_CPU_AREA_INFO info;

    if (!ctx || !cpu || !(cpu->Flags & WOW64_CPURESERVED_FLAG_RESET_STATE)) return FALSE;
    if (RtlWow64GetCpuAreaInfo( cpu, 0, &info )) return FALSE;
    if (info.Machine != IMAGE_FILE_MACHINE_I386) return FALSE;

    *ctx = *(I386_CONTEXT *)info.Context;
    return TRUE;
}


static NTSTATUS get_context_return_value( void *wow_context )
{
    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        return ((I386_CONTEXT *)wow_context)->Eax;
    case IMAGE_FILE_MACHINE_ARMNT:
        return ((ARM_CONTEXT *)wow_context)->R0;
    }
    return 0;
}

static BOOL macrunner_trace_ntcontinue_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','T','R','A','C','E','_',
             'N','T','C','O','N','T','I','N','U','E',0};
        WCHAR value[8];
        UNICODE_STRING name, val;

        name.Buffer = (WCHAR *)nameW;
        name.Length = sizeof(nameW) - sizeof(WCHAR);
        name.MaximumLength = sizeof(nameW);
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND;
    }
    return enabled;
}


/**********************************************************************
 *           call_user_exception_dispatcher
 */
static void __attribute__((used)) call_user_exception_dispatcher( EXCEPTION_RECORD32 *rec, void *ctx32_ptr,
                                                                  void *ctx64_ptr )
{
    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        {
            /* stack layout when calling 32-bit KiUserExceptionDispatcher */
            struct exc_stack_layout32
            {
                ULONG              rec_ptr;       /* 000 */
                ULONG              context_ptr;   /* 004 */
                EXCEPTION_RECORD32 rec;           /* 008 */
                I386_CONTEXT       context;       /* 058 */
            } *stack;
            I386_CONTEXT ctx = { CONTEXT_I386_ALL };
            CONTEXT_EX *context_ex, *src_ex = NULL;
            ULONG esp, flags, context_length;

            C_ASSERT( offsetof(struct exc_stack_layout32, context) == 0x58 );

            if (!macrunner_get_reset_i386_context( &ctx ))
                pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );

            if (ctx32_ptr)
            {
                I386_CONTEXT *ctx32 = ctx32_ptr;

                if ((ctx32->ContextFlags & CONTEXT_I386_XSTATE) == CONTEXT_I386_XSTATE)
                    src_ex = (CONTEXT_EX *)(ctx32 + 1);
            }
            else if (native_machine == IMAGE_FILE_MACHINE_AMD64)
            {
                AMD64_CONTEXT *ctx64 = ctx64_ptr;

                if ((ctx64->ContextFlags & CONTEXT_AMD64_FLOATING_POINT) == CONTEXT_AMD64_FLOATING_POINT)
                    memcpy( ctx.ExtendedRegisters, &ctx64->FltSave, sizeof(ctx.ExtendedRegisters) );
                if ((ctx64->ContextFlags & CONTEXT_AMD64_XSTATE) == CONTEXT_AMD64_XSTATE)
                    src_ex = (CONTEXT_EX *)(ctx64 + 1);
            }

            flags = ctx.ContextFlags;
            if (src_ex) flags |= CONTEXT_I386_XSTATE;

            RtlGetExtendedContextLength( flags, &context_length );

            esp = LOWORD(ctx.SegSs) != ss32_sel ? NtCurrentTeb32()->SystemReserved1[0] : ctx.Esp;
            stack = (struct exc_stack_layout32 *)guest32_host_ptr( (esp - offsetof(struct exc_stack_layout32, context) - context_length) & ~3 );
            stack->rec_ptr     = PtrToUlong( &stack->rec );
            stack->context_ptr = PtrToUlong( &stack->context );
            stack->rec         = *rec;
            stack->context     = ctx;
            RtlInitializeExtendedContext( &stack->context, flags, &context_ex );
            if (src_ex) RtlCopyExtendedContext( context_ex, WOW64_CONTEXT_XSTATE, src_ex );

            /* adjust Eip for breakpoints in software emulation (hardware exceptions already adjust Rip) */
            if (rec->ExceptionCode == EXCEPTION_BREAKPOINT && (wow64info->CpuFlags & WOW64_CPUFLAGS_SOFTWARE))
                stack->context.Eip--;

            ctx.Esp = PtrToUlong( stack );
            ctx.Eip = pLdrSystemDllInitBlock->pKiUserExceptionDispatcher;
            ctx.EFlags &= ~(0x100|0x400|0x40000);
            ctx.ContextFlags = CONTEXT_I386_CONTROL;
#if defined(__APPLE__) && defined(__aarch64__)
            /* Detect i386 exception re-delivery loop: ESP drops by ~0x340 per
             * iteration while EIP stays at KiUserExceptionDispatcher.
             * Cap at 3 consecutive decreasing-ESP deliveries → terminate. */
            {
                static __thread ULONG macrunner_wow64_last_esp;
                static __thread int   macrunner_wow64_loop_count;
                if (macrunner_wow64_last_esp && ctx.Esp < macrunner_wow64_last_esp)
                {
                    if (++macrunner_wow64_loop_count >= 3)
                    {
                        MESSAGE( "macrunner: i386 exception dispatch loop "
                             "(eip=%08x esp %08x < prev %08x count %d), terminating\n",
                             ctx.Eip, ctx.Esp, macrunner_wow64_last_esp,
                             macrunner_wow64_loop_count );
                        NtTerminateProcess( GetCurrentProcess(), 1 );
                    }
                }
                else
                    macrunner_wow64_loop_count = 0;
                macrunner_wow64_last_esp = ctx.Esp;
            }
#endif
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );

            TRACE( "exception %08lx dispatcher %08lx stack %08lx eip %08lx\n",
                   rec->ExceptionCode, ctx.Eip, ctx.Esp, stack->context.Eip );
        }
        break;

    case IMAGE_FILE_MACHINE_ARMNT:
        {
            struct stack_layout
            {
                ARM_CONTEXT        context;
                EXCEPTION_RECORD32 rec;
            } *stack;
            ARM_CONTEXT ctx = { CONTEXT_ARM_ALL };

            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            stack = (struct stack_layout *)(ULONG_PTR)(ctx.Sp & ~3) - 1;
            stack->rec = *rec;
            stack->context = ctx;

            ctx.R0 = PtrToUlong( &stack->rec );     /* first arg for KiUserExceptionDispatcher */
            ctx.R1 = PtrToUlong( &stack->context ); /* second arg for KiUserExceptionDispatcher */
            ctx.Sp = PtrToUlong( stack );
            ctx.Pc = pLdrSystemDllInitBlock->pKiUserExceptionDispatcher;
            if (ctx.Pc & 1) ctx.Cpsr |= 0x20;
            else ctx.Cpsr &= ~0x20;
            ctx.ContextFlags = CONTEXT_ARM_FULL;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );

            TRACE( "exception %08lx dispatcher %08lx stack %08lx pc %08lx\n",
                   rec->ExceptionCode, ctx.Pc, ctx.Sp, stack->context.Sp );
        }
        break;
    }
}


/**********************************************************************
 *           call_raise_user_exception_dispatcher
 */
static void __attribute__((used)) call_raise_user_exception_dispatcher( ULONG code )
{
    NtCurrentTeb32()->ExceptionCode = code;

    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        {
            I386_CONTEXT ctx;

            ctx.ContextFlags = CONTEXT_I386_CONTROL;
            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            ctx.Esp -= sizeof(ULONG);
            *(ULONG *)guest32_host_ptr( ctx.Esp ) = ctx.Eip;
            ctx.Eip = (ULONG_PTR)pKiRaiseUserExceptionDispatcher;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
        }
        break;

    case IMAGE_FILE_MACHINE_ARMNT:
        {
            ARM_CONTEXT ctx;

            ctx.ContextFlags = CONTEXT_ARM_CONTROL;
            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            ctx.Pc = (ULONG_PTR)pKiRaiseUserExceptionDispatcher;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
        }
        break;
    }
}


/* based on RtlRaiseException: call NtRaiseException with context setup to return to caller */
void WINAPI raise_exception( EXCEPTION_RECORD32 *rec32, void *ctx32,
                             BOOL first_chance, EXCEPTION_RECORD *rec );
#ifdef __aarch64__
__ASM_GLOBAL_FUNC( raise_exception,
                   "sub sp, sp, #0x390\n\t"    /* sizeof(context) */
                   ".seh_stackalloc 0x390\n\t"
                   "stp x29, x30, [sp, #-48]!\n\t"
                   ".seh_save_fplr_x 48\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler raise_exception_handler, @except\n\t"
                   "stp x0, x1, [sp, #16]\n\t"
                   "stp x2, x3, [sp, #32]\n\t"
                   "add x0, sp, #48\n\t"
                   "bl RtlCaptureContext\n\t"
                   "add x1, sp, #48\n\t"       /* context */
                   "adr x2, 1f\n\t"            /* return address */
                   "str x2, [x1, #0x108]\n\t"  /* context->Pc */
                   "ldp x2, x0, [sp, #32]\n\t" /* first_chance, rec */
                   "bl NtRaiseException\n"
                   "raise_exception_ret:\n\t"
                   "ldp x0, x1, [sp, #16]\n\t" /* rec32, ctx32 */
                   "add x2, sp, #48\n\t"       /* context */
                   "bl call_user_exception_dispatcher\n"
                   "1:\tnop\n\t"
                   "ldp x29, x30, [sp], #48\n\t"
                   "add sp, sp, #0x390\n\t"
                   "ret" )
__ASM_GLOBAL_FUNC( raise_exception_handler,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   ".seh_endprologue\n\t"
                   "ldr w4, [x0, #4]\n\t"      /* record->ExceptionFlags */
                   "tst w4, #6\n\t"            /* EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND */
                   "b.ne 1f\n\t"
                   "mov x2, x0\n\t"            /* rec */
                   "mov x0, x1\n\t"            /* frame */
                   "adr x1, raise_exception_ret\n\t"
                   "bl RtlUnwind\n"
                   "1:\tmov w0, #1\n\t"        /* ExceptionContinueSearch */
                   "ldp x29, x30, [sp], #16\n\t"
                   "ret" )
#else
__ASM_GLOBAL_FUNC( raise_exception,
                   "sub $0x4d8,%rsp\n\t"       /* sizeof(context) + alignment */
                   ".seh_stackalloc 0x4d8\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler raise_exception_handler, @except\n\t"
                   "movq %rcx,0x4e0(%rsp)\n\t"
                   "movq %rdx,0x4e8(%rsp)\n\t"
                   "movq %r8,0x4f0(%rsp)\n\t"
                   "movq %r9,0x4f8(%rsp)\n\t"
                   "movq %rsp,%rcx\n\t"
                   "call RtlCaptureContext\n\t"
                   "movq %rsp,%rdx\n\t"        /* context */
                   "leaq 1f(%rip),%rax\n\t"    /* return address */
                   "movq %rax,0xf8(%rdx)\n\t"  /* context->Rip */
                   "movq 0x4f8(%rsp),%rcx\n\t" /* rec */
                   "movq 0x4f0(%rsp),%r8\n\t"  /* first_chance */
                   "call NtRaiseException\n"
                   "raise_exception_ret:\n\t"
                   "mov 0x4e0(%rsp),%rcx\n\t"  /* rec32 */
                   "mov 0x4e8(%rsp),%rdx\n\t"  /* ctx32 */
                   "movq %rsp,%r8\n\t"         /* context */
                   "call call_user_exception_dispatcher\n"
                   "1:\tnop\n\t"
                   "add $0x4d8,%rsp\n\t"
                   "ret" )
__ASM_GLOBAL_FUNC( raise_exception_handler,
                   "sub $0x28,%rsp\n\t"
                   ".seh_stackalloc 0x28\n\t"
                   ".seh_endprologue\n\t"
                   "movq %rcx,%r8\n\t"         /* rec */
                   "movq %rdx,%rcx\n\t"        /* frame */
                   "leaq raise_exception_ret(%rip),%rdx\n\t"
                   "call RtlUnwind\n\t"
                   "int3" )
#endif


/**********************************************************************
 *           wow64_NtAddAtom
 */
NTSTATUS WINAPI wow64_NtAddAtom( UINT *args )
{
    const WCHAR *name = get_ptr( &args );
    ULONG len = get_ulong( &args );
    RTL_ATOM *atom = get_ptr( &args );

    return NtAddAtom( name, len, atom );
}


/**********************************************************************
 *           wow64_NtAllocateLocallyUniqueId
 */
NTSTATUS WINAPI wow64_NtAllocateLocallyUniqueId( UINT *args )
{
    LUID *luid = get_ptr( &args );

    return NtAllocateLocallyUniqueId( luid );
}

/**********************************************************************
 *           wow64_NtAllocateReserveObject
 */
NTSTATUS WINAPI wow64_NtAllocateReserveObject( UINT *args )
{
    ULONG *handle_ptr = get_ptr( &args );
    OBJECT_ATTRIBUTES32 *attr32 = get_ptr( &args );
    MEMORY_RESERVE_OBJECT_TYPE type = get_ulong( &args );
    NTSTATUS status;

    struct object_attr64 attr;
    HANDLE handle = 0;

    status = NtAllocateReserveObject( &handle, objattr_32to64( &attr, attr32 ), type );
    put_handle( handle_ptr, handle );
    return status;
}

/**********************************************************************
 *           wow64_NtAllocateUuids
 */
NTSTATUS WINAPI wow64_NtAllocateUuids( UINT *args )
{
    ULARGE_INTEGER *time = get_ptr( &args );
    ULONG *delta = get_ptr( &args );
    ULONG *sequence = get_ptr( &args );
    UCHAR *seed = get_ptr( &args );

    return NtAllocateUuids( time, delta, sequence, seed );
}


/***********************************************************************
 *           wow64_NtCallbackReturn
 */
NTSTATUS WINAPI wow64_NtCallbackReturn( UINT *args )
{
    void *ret_ptr = get_ptr( &args );
    ULONG ret_len = get_ulong( &args );
    NTSTATUS status = get_ulong( &args );

    struct user_callback_frame *frame = NtCurrentTeb()->TlsSlots[WOW64_TLS_USERCALLBACKDATA];

    if (!frame) return STATUS_NO_CALLBACK_ACTIVE;

    MESSAGE( "macrunner-wow64: NtCallbackReturn enter frame=%p ret_ptr=%p ret_len=%lu status=%08lx\n",
             frame, ret_ptr, ret_len, status );
    *frame->ret_ptr = ret_ptr;
    *frame->ret_len = ret_len;
    frame->status = status;
#ifdef __aarch64__
    if (native_machine == IMAGE_FILE_MACHINE_ARM64 && current_machine == IMAGE_FILE_MACHINE_I386)
    {
        TEB *teb = NtCurrentTeb();
        __asm__ volatile( "mov x18, %0" :: "r"(teb) : "memory" );
        macrunner_wow64_longjmp_direct( frame->jmpbuf, 1 );
    }
#endif
    longjmp( frame->jmpbuf, 1 );
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           wow64_NtClose
 */
NTSTATUS WINAPI wow64_NtClose( UINT *args )
{
    HANDLE handle = get_handle( &args );

    return NtClose( handle );
}


/**********************************************************************
 *           wow64_NtContinueEx
 */
NTSTATUS WINAPI wow64_NtContinueEx( UINT *args )
{
    void *context = get_ptr( &args );
    ULONG_PTR cont_arg = get_ulong( &args );
    KCONTINUE_ARGUMENT *cont_args = (KCONTINUE_ARGUMENT *)cont_arg;
    NTSTATUS status;
    struct user_apc_frame *frame;
    BOOL alertable;

    if (current_machine == IMAGE_FILE_MACHINE_I386 && context)
        context = guest32_host_ptr( (ULONG_PTR)context );
    if (current_machine == IMAGE_FILE_MACHINE_I386 && cont_arg > 0xff)
        cont_args = guest32_host_ptr( cont_arg );

    status = get_context_return_value( context );
    frame = NtCurrentTeb()->TlsSlots[WOW64_TLS_APCLIST];

    if (macrunner_trace_ntcontinue_enabled())
        MESSAGE( "macrunner-wow64-ntcontinue: enter context=%p cont_arg=%08Ix cont_args=%p status=%08lx frame=%p\n",
                 context, cont_arg, cont_args, status, frame );
    pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, context );
    if (macrunner_trace_ntcontinue_enabled())
        MESSAGE( "macrunner-wow64-ntcontinue: after-setcontext context=%p frame=%p\n", context, frame );

    while (frame && frame->wow_context != context) frame = frame->prev_frame;
    NtCurrentTeb()->TlsSlots[WOW64_TLS_APCLIST] = frame ? frame->prev_frame : NULL;
    if (macrunner_trace_ntcontinue_enabled())
        MESSAGE( "macrunner-wow64-ntcontinue: after-frame-search frame=%p apclist=%p\n",
                 frame, NtCurrentTeb()->TlsSlots[WOW64_TLS_APCLIST] );
    if (frame) NtContinueEx( frame->context, cont_args );

    if (cont_arg > 0xff)
        alertable = cont_args->ContinueFlags & KCONTINUE_FLAG_TEST_ALERT;
    else
        alertable = !!cont_arg;

    if (macrunner_trace_ntcontinue_enabled())
        MESSAGE( "macrunner-wow64-ntcontinue: before-test-alert alertable=%u cont_args=%p\n",
                 alertable, cont_args );
    if (alertable) NtTestAlert();
    if (macrunner_trace_ntcontinue_enabled())
        MESSAGE( "macrunner-wow64-ntcontinue: return status=%08lx\n", status );
    return status;
}


/**********************************************************************
 *           wow64_NtContinue
 */
NTSTATUS WINAPI wow64_NtContinue( UINT *args )
{
    return wow64_NtContinueEx( args );
}


/**********************************************************************
 *           wow64_NtDeleteAtom
 */
NTSTATUS WINAPI wow64_NtDeleteAtom( UINT *args )
{
    RTL_ATOM atom = get_ulong( &args );

    return NtDeleteAtom( atom );
}


/**********************************************************************
 *           wow64_NtFindAtom
 */
NTSTATUS WINAPI wow64_NtFindAtom( UINT *args )
{
    const WCHAR *name = get_ptr( &args );
    ULONG len = get_ulong( &args );
    RTL_ATOM *atom = get_ptr( &args );

    return NtFindAtom( name, len, atom );
}


/**********************************************************************
 *           wow64_NtGetContextThread
 */
NTSTATUS WINAPI wow64_NtGetContextThread( UINT *args )
{
    HANDLE handle = get_handle( &args );
    WOW64_CONTEXT *context = get_ptr( &args );

    if (current_machine == IMAGE_FILE_MACHINE_I386 && context)
        context = guest32_host_ptr( (ULONG_PTR)context );

    return RtlWow64GetThreadContext( handle, context );
}


/**********************************************************************
 *           wow64_NtGetCurrentProcessorNumber
 */
NTSTATUS WINAPI wow64_NtGetCurrentProcessorNumber( UINT *args )
{
    return NtGetCurrentProcessorNumber();
}


/**********************************************************************
 *           wow64_NtQueryDefaultLocale
 */
NTSTATUS WINAPI wow64_NtQueryDefaultLocale( UINT *args )
{
    BOOLEAN user = get_ulong( &args );
    LCID *lcid = get_ptr( &args );

    return NtQueryDefaultLocale( user, lcid );
}


/**********************************************************************
 *           wow64_NtQueryDefaultUILanguage
 */
NTSTATUS WINAPI wow64_NtQueryDefaultUILanguage( UINT *args )
{
    LANGID *lang = get_ptr( &args );

    return NtQueryDefaultUILanguage( lang );
}


/**********************************************************************
 *           wow64_NtQueryInformationAtom
 */
NTSTATUS WINAPI wow64_NtQueryInformationAtom( UINT *args )
{
    RTL_ATOM atom = get_ulong( &args );
    ATOM_INFORMATION_CLASS class = get_ulong( &args );
    void *info = get_ptr( &args );
    ULONG len = get_ulong( &args );
    ULONG *retlen = get_ptr( &args );

    if (class != AtomBasicInformation) FIXME( "class %u not supported\n", class );
    return NtQueryInformationAtom( atom, class, info, len, retlen );
}


/**********************************************************************
 *           wow64_NtQueryInstallUILanguage
 */
NTSTATUS WINAPI wow64_NtQueryInstallUILanguage( UINT *args )
{
    LANGID *lang = get_ptr( &args );

    return NtQueryInstallUILanguage( lang );
}


/**********************************************************************
 *           wow64_NtRaiseException
 */
NTSTATUS WINAPI wow64_NtRaiseException( UINT *args )
{
    EXCEPTION_RECORD32 *rec32 = get_ptr( &args );
    void *context32 = get_ptr( &args );
    BOOL first_chance = get_ulong( &args );

    if (current_machine == IMAGE_FILE_MACHINE_I386)
    {
        if (rec32) rec32 = guest32_host_ptr( (ULONG_PTR)rec32 );
        if (context32) context32 = guest32_host_ptr( (ULONG_PTR)context32 );
    }

    pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, context32 );
    raise_exception( rec32, context32, first_chance, exception_record_32to64( rec32 ));
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           wow64_NtSetContextThread
 */
NTSTATUS WINAPI wow64_NtSetContextThread( UINT *args )
{
    HANDLE handle = get_handle( &args );
    WOW64_CONTEXT *context = get_ptr( &args );

    if (current_machine == IMAGE_FILE_MACHINE_I386 && context)
        context = guest32_host_ptr( (ULONG_PTR)context );

    return RtlWow64SetThreadContext( handle, context );
}


/**********************************************************************
 *           wow64_NtSetDebugFilterState
 */
NTSTATUS WINAPI wow64_NtSetDebugFilterState( UINT *args )
{
    ULONG component_id = get_ulong( &args );
    ULONG level = get_ulong( &args );
    BOOLEAN state = get_ulong( &args );

    return NtSetDebugFilterState( component_id, level, state );
}


/**********************************************************************
 *           wow64_NtSetDefaultLocale
 */
NTSTATUS WINAPI wow64_NtSetDefaultLocale( UINT *args )
{
    BOOLEAN user = get_ulong( &args );
    LCID lcid = get_ulong( &args );

    return NtSetDefaultLocale( user, lcid );
}


/**********************************************************************
 *           wow64_NtSetDefaultUILanguage
 */
NTSTATUS WINAPI wow64_NtSetDefaultUILanguage( UINT *args )
{
    LANGID lang = get_ulong( &args );

    return NtSetDefaultUILanguage( lang );
}


/**********************************************************************
 *           wow64_NtWow64IsProcessorFeaturePresent
 */
NTSTATUS WINAPI wow64_NtWow64IsProcessorFeaturePresent( UINT *args )
{
    UINT feature = get_ulong( &args );

    return pBTCpuIsProcessorFeaturePresent && pBTCpuIsProcessorFeaturePresent( feature );
}


/**********************************************************************
 *           init_image_mapping
 */
void init_image_mapping( HMODULE module )
{
    ULONG *ptr = RtlFindExportedRoutineByName( module, "Wow64Transition" );
    ULONG transition = PtrToUlong( pBTCpuGetBopCode() );
    NTSTATUS status;

    if (!ptr) return;

    status = write_guest32_output( ptr, &transition, sizeof(transition) );
    if (status)
        ERR( "failed to patch Wow64Transition %p status=%08lx\n", ptr, status );
}


/**********************************************************************
 *           load_64bit_module
 */
static HMODULE load_64bit_module( const WCHAR *name )
{
    NTSTATUS status;
    HMODULE module;
    UNICODE_STRING str;
    WCHAR path[MAX_PATH];
    UNICODE_STRING val_str, name_str = RTL_CONSTANT_STRING( L"WINEWOW6432BPREFIXMODE" );
    const WCHAR *dir = get_machine_wow64_dir( IMAGE_FILE_MACHINE_TARGET_HOST );

    /* CW HACK 20810: In Wow64/32-bit-bottle mode, load 64-bit DLLs by name rather than full path */
    val_str.MaximumLength = 0;
    if (RtlQueryEnvironmentVariable_U( NULL, &name_str, &val_str ) != STATUS_VARIABLE_NOT_FOUND)
    {
        RtlInitUnicodeString( &str, name );
    }
    else
    {
        swprintf( path, MAX_PATH, L"%s\\%s", dir, name );
        RtlInitUnicodeString( &str, path );
    }

    MESSAGE( "macrunner-wow64: load_64bit_module enter name_ptr=%p dir_ptr=%p str_ptr=%p full_path=%u\n",
             name, dir, str.Buffer, str.Buffer == path );
    if ((status = LdrLoadDll( dir, 0, &str, &module )))
    {
        MESSAGE( "macrunner-wow64: load_64bit_module failed name_ptr=%p status=%08lx\n",
                 name, status );
        ERR( "failed to load dll %lx\n", status );
        NtTerminateProcess( GetCurrentProcess(), status );
    }
    MESSAGE( "macrunner-wow64: load_64bit_module done name_ptr=%p module=%p\n",
             name, module );
    return module;
}


/**********************************************************************
 *           get_cpu_dll_name
 */
static const WCHAR *get_cpu_dll_name(void)
{
    static ULONG buffer[32];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW;
    const WCHAR *ret;
    HANDLE key;
    ULONG size;

    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        RtlInitUnicodeString( &nameW, L"\\Registry\\Machine\\Software\\Microsoft\\Wow64\\x86" );
        ret = (native_machine == IMAGE_FILE_MACHINE_ARM64 ? L"xtajit.dll" : L"wow64cpu.dll");
        break;
    case IMAGE_FILE_MACHINE_ARMNT:
        RtlInitUnicodeString( &nameW, L"\\Registry\\Machine\\Software\\Microsoft\\Wow64\\arm" );
        ret = L"wowarmhw.dll";
        break;
    default:
        ERR( "unsupported machine %04x\n", current_machine );
        RtlExitUserProcess( 1 );
    }
    InitializeObjectAttributes( &attr, &nameW, OBJ_CASE_INSENSITIVE, 0, NULL );
    if (NtOpenKey( &key, KEY_READ | KEY_WOW64_64KEY, &attr )) return ret;
    RtlInitUnicodeString( &nameW, L"" );
    size = sizeof(buffer) - sizeof(WCHAR);
    if (!NtQueryValueKey( key, &nameW, KeyValuePartialInformation, buffer, size, &size ) && info->Type == REG_SZ)
    {
        ((WCHAR *)info->Data)[info->DataLength / sizeof(WCHAR)] = 0;
        ret = (WCHAR *)info->Data;
    }
    NtClose( key );
    return ret;
}


/**********************************************************************
 *           create_cross_process_work_list
 */
static NTSTATUS create_cross_process_work_list( WOW64INFO *wow64info )
{
    SIZE_T map_size = 0x4000;
    LARGE_INTEGER size;
    NTSTATUS status;
    HANDLE section;
    CROSS_PROCESS_WORK_LIST *list = NULL;
    CROSS_PROCESS_WORK_ENTRY *end;
    UINT i;

    size.QuadPart = map_size;
    status = NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, &size, PAGE_READWRITE, SEC_COMMIT, 0 );
    if (status) return status;
    status = WINE_NT_MAP_VIEW( section, GetCurrentProcess(), (void **)&list, default_zero_bits, 0, NULL,
                               &map_size, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE );
    if (status)
    {
        NtClose( section );
        return status;
    }

    end = (CROSS_PROCESS_WORK_ENTRY *)((char *)list + map_size);
    for (i = 0; list->entries + i + 1 <= end; i++)
        RtlWow64PushCrossProcessWorkOntoFreeList( &list->free_list, &list->entries[i] );

    wow64info->SectionHandle = (ULONG_PTR)section;
    wow64info->CrossProcessWorkList = (ULONG_PTR)list;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           process_init
 */
static DWORD WINAPI process_init( RTL_RUN_ONCE *once, void *param, void **context )
{
    PEB32 *peb32;
    HMODULE module;
    UNICODE_STRING str = RTL_CONSTANT_STRING( L"ntdll.dll" );
    SYSTEM_BASIC_INFORMATION info;
    ULONG *p__wine_syscall_dispatcher, *p__wine_unix_call_dispatcher;
    const SYSTEM_SERVICE_TABLE *psdwhwin32;

    RtlWow64GetProcessMachines( GetCurrentProcess(), &current_machine, &native_machine );
    MESSAGE( "macrunner-wow64: process_init enter current=%04x native=%04x\n",
             current_machine, native_machine );
    if (!current_machine) current_machine = native_machine;
    args_alignment = (current_machine == IMAGE_FILE_MACHINE_I386) ? sizeof(ULONG) : sizeof(ULONG64);
    process_heap = GetProcessHeap();
    NtQuerySystemInformation( SystemEmulationBasicInformation, &info, sizeof(info), NULL );
    highest_user_address = (ULONG_PTR)info.HighestUserAddress;
    default_zero_bits = (ULONG_PTR)info.HighestUserAddress | 0x7fffffff;
    NtQueryInformationProcess( GetCurrentProcess(), ProcessWow64Information, &peb32, sizeof(peb32), NULL );
    /* Итерация 1267, лейн ЛЕСТНИЦА — вторая половина зонда корня C2.
     * `init_peb` (ntdll, env.c:1953) заполняет свой PEB32 и кладёт туда ProcessParameters.
     * Здесь мы получаем PEB32 от ядра. Если адреса разойдутся — гость смотрит не на тот блок,
     * и это и есть корень восьми отказов «wrong ImagePathName ptr 0». Печать за тем же гейтом. */
    {
        /* Окружение читаем `RtlQueryEnvironmentVariable_U`, а НЕ `getenv`: это сторона PE, CRT
         * здесь нет, и сборка падает на `call to undeclared function 'getenv'` (проверено).
         * Идиома взята у соседнего гейта этого же файла (строка 251). */
        static const WCHAR nameW[] = L"MACRUNNER_HB_WOW64_PARAMS_PROBE";
        UNICODE_STRING name, val;
        WCHAR value[8];

        name.Buffer = (WCHAR *)nameW;
        name.Length = sizeof(nameW) - sizeof(WCHAR);
        name.MaximumLength = sizeof(nameW);
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        if (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND)
            MESSAGE( "macrunner-hb-wow64peb: process_init peb32=%p ProcessParameters=%08x "
                     "ImageBase=%08x\n",
                     peb32, (unsigned)peb32->ProcessParameters,
                     (unsigned)peb32->ImageBaseAddress );
    }
    wow64info = (WOW64INFO *)(peb32 + 1);
    wow64info->NativeSystemPageSize = 0x1000;
    wow64info->NativeMachineType    = native_machine;
    wow64info->EmulatedMachineType  = current_machine;
    NtCurrentTeb()->TlsSlots[WOW64_TLS_WOW64INFO] = wow64info;

#define GET_PTR(name) p ## name = RtlFindExportedRoutineByName( module, #name )

    LdrGetDllHandle( NULL, 0, &str, &module );
    GET_PTR( LdrSystemDllInitBlock );

    module = load_64bit_module( get_cpu_dll_name() );
    MESSAGE( "macrunner-wow64: cpu module=%p\n", module );
    GET_PTR( BTCpuGetBopCode );
    GET_PTR( BTCpuGetContext );
    GET_PTR( BTCpuIsProcessorFeaturePresent );
    GET_PTR( BTCpuProcessInit );
    GET_PTR( BTCpuThreadInit );
    GET_PTR( BTCpuResetToConsistentState );
    GET_PTR( BTCpuSetContext );
    GET_PTR( BTCpuSimulate );
    GET_PTR( BTCpuFlushInstructionCache2 );
    GET_PTR( BTCpuFlushInstructionCacheHeavy );
    GET_PTR( BTCpuNotifyMapViewOfSection );
    GET_PTR( BTCpuNotifyMemoryAlloc );
    GET_PTR( BTCpuNotifyProcessExecuteFlagsChange );
    GET_PTR( BTCpuNotifyMemoryDirty );
    GET_PTR( BTCpuNotifyMemoryFree );
    GET_PTR( BTCpuNotifyMemoryProtect );
    GET_PTR( BTCpuNotifyReadFile );
    GET_PTR( BTCpuNotifyUnmapViewOfSection );
    GET_PTR( BTCpuUpdateProcessorInformation );
    GET_PTR( BTCpuProcessTerm );
    GET_PTR( BTCpuThreadTerm );
    GET_PTR( BTCpuSuspendLocalThread );
    GET_PTR( __wine_get_unix_opcode );
    MESSAGE( "macrunner-wow64: cpu exports bop=%p init=%p thread=%p simulate=%p\n",
             pBTCpuGetBopCode, pBTCpuProcessInit, pBTCpuThreadInit, pBTCpuSimulate );

    MESSAGE( "macrunner-wow64: before load wow64win.dll\n" );
    module = load_64bit_module( L"wow64win.dll" );
    MESSAGE( "macrunner-wow64: after load wow64win.dll module=%p\n", module );
    MESSAGE( "macrunner-wow64: before sdwhwin32 export\n" );
    GET_PTR( sdwhwin32 );
    MESSAGE( "macrunner-wow64: after sdwhwin32 export ptr=%p\n", psdwhwin32 );
    syscall_tables[1] = *psdwhwin32;
    MESSAGE( "macrunner-wow64: after win32 syscall table copy\n" );

    MESSAGE( "macrunner-wow64: before BTCpuProcessInit\n" );
    pBTCpuProcessInit();
    MESSAGE( "macrunner-wow64: after BTCpuProcessInit\n" );

    module = (HMODULE)(ULONG_PTR)pLdrSystemDllInitBlock->ntdll_handle;
    init_image_mapping( module );
    GET_PTR( KiRaiseUserExceptionDispatcher );
    GET_PTR( __wine_syscall_dispatcher );
    GET_PTR( __wine_unix_call_dispatcher );

    *p__wine_syscall_dispatcher = PtrToUlong( pBTCpuGetBopCode() );
    *p__wine_unix_call_dispatcher = PtrToUlong( p__wine_get_unix_opcode() );

    if (wow64info->CpuFlags & WOW64_CPUFLAGS_SOFTWARE) create_cross_process_work_list( wow64info );

    if (current_machine == IMAGE_FILE_MACHINE_I386)
    {
        I386_CONTEXT ctx = { CONTEXT_I386_CONTROL };
        RtlWow64GetThreadContext( GetCurrentThread(), &ctx );
        ss32_sel = ctx.SegSs;
    }

    init_file_redirects();
    MESSAGE( "macrunner-wow64: process_init done machine=%04x ss32=%04x\n",
             current_machine, ss32_sel );
    return TRUE;

#undef GET_PTR
}


/**********************************************************************
 *           thread_init
 */
static void thread_init(void)
{
    if (native_machine == IMAGE_FILE_MACHINE_ARM64 && current_machine == IMAGE_FILE_MACHINE_I386)
    {
        /* ★★★★ ПАКЕТ-2 (договор T5) — БАЗА АРЕНЫ ЕСТЬ СОБСТВЕННОСТЬ HyperBridge.
         *
         * Прибор БЕЗУСЛОВНЫЙ и печатает старшие биты TEB32 на ОБЕИХ руках. Это не
         * украшение: у руки fex он и есть доказательство тождества «гостевой VA ==
         * хозяйский VA». Ноль в старших битах — тождество держится; ненулевое —
         * тождество нарушено, и тогда недействителен вывод, а не прогон. */
        ULONG_PTR mr_hi = (ULONG_PTR)NtCurrentTeb32() & ~(ULONG_PTR)0xffffffff;

        if (macrunner_wow64_paket2_mute( "T5-base" ))
        {
            static unsigned int mr_n;
            if (mr_n++ < 8)
                MESSAGE( "macrunner-paket2-pe: family=T5-base teb32=%p vysokie_bity=%Ix "
                         "(0 = tozhdestvo derzhitsya)\n", NtCurrentTeb32(), mr_hi );
        }
        else
        {
            macrunner_wow64_guest32_base = mr_hi;
            NtCurrentTeb()->TlsSlots[MACRUNNER_WOW64_TLS_GUEST32_BASE] =
                (void *)macrunner_wow64_guest32_base;
        }
    }

    MESSAGE( "macrunner-wow64: thread_init enter machine=%04x teb32=%p bop=%p\n",
             current_machine, NtCurrentTeb32(), pBTCpuGetBopCode );
    NtCurrentTeb32()->WOW32Reserved = PtrToUlong( pBTCpuGetBopCode() );
    NtCurrentTeb()->TlsSlots[WOW64_TLS_WOW64INFO] = wow64info;
    if (pBTCpuThreadInit) pBTCpuThreadInit();
    MESSAGE( "macrunner-wow64: after BTCpuThreadInit\n" );

    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1225 — ПЕРЕЧИТАТЬ БАЗУ ПОСЛЕ BTCpuThreadInit.
     *
     * Выше (в начале этой же функции) база выведена маской из адреса TEB32. Это верно только
     * когда TEB32 лежит ВНУТРИ зеркала guest32; у 32-битного ребёнка, порождённого 64-битным
     * процессом, он лежит в хозяйской области, и маска даёт чужое число — замер 1224:
     * взято 0x7ff00000000 вместо настоящего 0xd00000000, запись начального контекста уходила
     * в неотображённую память и ребёнок падал по c0000005.
     *
     * `BTCpuThreadInit` (unix-сторона xtajit) кладёт в тот же слот TLS НАСТОЯЩУЮ базу — она там
     * и создаётся. Перечитываем её здесь, ДО первого перевода гостевого адреса.
     * Там, где базы совпадают, правка ничего не меняет и молчит. */
    if (native_machine == IMAGE_FILE_MACHINE_ARM64 && current_machine == IMAGE_FILE_MACHINE_I386 &&
        !macrunner_wow64_paket2_mute( "T5-base-fix" ))
    {
        ULONG_PTR real = (ULONG_PTR)NtCurrentTeb()->TlsSlots[MACRUNNER_WOW64_TLS_GUEST32_BASE];

        real &= ~(ULONG_PTR)0xffffffff;
        if (real && real != macrunner_wow64_guest32_base)
        {
            MESSAGE( "macrunner-wow64-base-fix: было=%Ix стало=%Ix teb32=%p\n",
                     macrunner_wow64_guest32_base, real, NtCurrentTeb32() );
            macrunner_wow64_guest32_base = real;
        }
    }

    /* update initial context to jump to 32-bit LdrInitializeThunk (cf. 32-bit call_init_thunk) */
    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        {
            I386_CONTEXT *ctx_ptr, ctx = { CONTEXT_I386_FULL };
            ULONG *stack;

            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            MESSAGE( "macrunner-wow64: thread_init i386 context eip=%08lx esp=%08lx ldr=%08llx\n",
                     ctx.Eip, ctx.Esp, (ULONGLONG)pLdrSystemDllInitBlock->pLdrInitializeThunk );
            ctx_ptr = (I386_CONTEXT *)guest32_host_ptr( ctx.Esp ) - 1;
            *ctx_ptr = ctx;
            stack = (ULONG *)ctx_ptr;
            *(--stack) = 0;
            *(--stack) = 0;
            *(--stack) = 0;
            *(--stack) = PtrToUlong( ctx_ptr );
            *(--stack) = 0xdeadbabe;
            ctx.Esp = PtrToUlong( stack );
            ctx.Eip = pLdrSystemDllInitBlock->pLdrInitializeThunk;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            MESSAGE( "macrunner-wow64: thread_init i386 set eip=%08lx esp=%08lx ctx_ptr=%p\n",
                     ctx.Eip, ctx.Esp, ctx_ptr );
        }
        break;

    case IMAGE_FILE_MACHINE_ARMNT:
        {
            ARM_CONTEXT *ctx_ptr, ctx = { CONTEXT_ARM_FULL };

            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            ctx_ptr = (ARM_CONTEXT *)ULongToPtr( ctx.Sp & ~15 ) - 1;
            *ctx_ptr = ctx;

            ctx.R0 = PtrToUlong( ctx_ptr );
            ctx.Sp = PtrToUlong( ctx_ptr );
            ctx.Pc = pLdrSystemDllInitBlock->pLdrInitializeThunk;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
        }
        break;

    default:
        ERR( "not supported machine %x\n", current_machine );
        NtTerminateProcess( GetCurrentProcess(), STATUS_INVALID_IMAGE_FORMAT );
    }
}


/**********************************************************************
 *           free_temp_data
 */
static void free_temp_data(void)
{
    struct mem_header *next, *mem;
    HANDLE heap = process_heap ? process_heap : GetProcessHeap();

    for (mem = NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST]; mem; mem = next)
    {
        next = mem->next;
        RtlFreeHeap( heap, 0, mem );
    }
    NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] = NULL;
}


/**********************************************************************
 *           wow64_syscall
 */
#ifdef __aarch64__
NTSTATUS wow64_syscall( UINT *args, ULONG_PTR thunk, TEB *teb );
__ASM_GLOBAL_FUNC( wow64_syscall,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler wow64_syscall_handler, @except\n"
                   "mov x18, x2\n\t"
                   "blr x1\n\t"
                   "b 1f\n"
                   "wow64_syscall_ret:\n\t"
                   "eor w1, w0, #0xc0000000\n\t"
                   "cmp w1, #8\n\t"                /* STATUS_INVALID_HANDLE */
                   "b.ne 1f\n\t"
                   "bl call_raise_user_exception_dispatcher\n"
                   "1:\tldp x29, x30, [sp], #16\n\t"
                   "ret" )
__ASM_GLOBAL_FUNC( wow64_syscall_handler,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   ".seh_endprologue\n\t"
                   "ldr w4, [x0, #4]\n\t"          /* record->ExceptionFlags */
                   "tst w4, #6\n\t"                /* EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND */
                   "b.ne 1f\n\t"
                   "mov x2, x0\n\t"                /* record */
                   "mov x0, x1\n\t"                /* frame */
                   "adr x1, wow64_syscall_ret\n\t" /* target */
                   "ldr w3, [x2]\n\t"              /* retval = record->ExceptionCode */
                   "bl RtlUnwind\n\t"
                   "1:\tmov w0, #1\n\t"            /* ExceptionContinueSearch */
                   "ldp x29, x30, [sp], #16\n\t"
                   "ret" )
#else
NTSTATUS wow64_syscall( UINT *args, ULONG_PTR thunk, TEB *teb );
__ASM_GLOBAL_FUNC( wow64_syscall,
                   "subq $0x28, %rsp\n\t"
                   ".seh_stackalloc 0x28\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler wow64_syscall_handler, @except\n\t"
                   "call *%rdx\n\t"
                   "jmp 1f\n"
                   "wow64_syscall_ret:\n\t"
                   "cmpl $0xc0000008,%eax\n\t"     /* STATUS_INVALID_HANDLE */
                   "jne 1f\n\t"
                   "movl %eax,%ecx\n\t"
                   "call call_raise_user_exception_dispatcher\n"
                   "1:\taddq $0x28, %rsp\n\t"
                   "ret" )
__ASM_GLOBAL_FUNC( wow64_syscall_handler,
                   "subq $0x28,%rsp\n\t"
                   ".seh_stackalloc 0x28\n\t"
                   ".seh_endprologue\n\t"
                   "movl (%rcx),%r9d\n\t"          /* retval = rec->ExceptionCode */
                   "movq %rcx,%r8\n\t"             /* rec */
                   "movq %rdx,%rcx\n\t"            /* frame */
                   "leaq wow64_syscall_ret(%rip),%rdx\n\t"
                   "call RtlUnwind\n\t"
                   "int3" )
#endif


/**********************************************************************
 *           Wow64SystemServiceEx  (wow64.@)
 */
/* ★★★★★ ИТЕРАЦИЯ 67 — ГДЕ ИМЕННО ПОРТИТСЯ `WowTebOffset`.
 *
 * Что уже измерено (65-66):
 *   - смена РОВНО ОДНА за прогон, всегда 0x2000 -> 0xAA64, три прогона подряд;
 *   - 0xAA64 = IMAGE_FILE_MACHINE_ARM64, а НЕ данные файла и не число байт: значение
 *     постоянно при разных базах гостя (0x3.., 0xB..) и разных номерах вызова
 *     (20178 / 40439 / 11911);
 *   - поле LONG, старшая половина была 0 и осталась 0 -> запись 16-битная, то есть
 *     `X->Machine = <ARM64>` по указателю, уехавшему на teb+0x180C;
 *   - обе версии про NtReadFile ОТВЕРГНУТЫ замером: ни `io32`, ни `buffer` в TEB
 *     не попадают ни разу (0 из 72 682).
 *
 * Дальше гадать нечем — надо ЗАЖАТЬ запись между точками. Одна сверка на точку,
 * печать только при изменении, поэтому journal не растёт. */
/* ★ ИТЕРАЦИЯ 73 — ОКРЕСТНОСТЬ ПОЛЯ, а не только оно само.
 *
 * В блоке, где по замерам происходит порча, НЕ ОСТАЛОСЬ пишущих операторов:
 * все отвергнуты замером или временем (итерации 71-72). Значит либо пишет
 * не этот код, либо это вообще не точечное присваивание, а блочная запись.
 * Различает одно: поедут ли СОСЕДНИЕ байты. Печатаем три слова от TEB+0x1800:
 * TxnScopeContext (0x1800), LockCount+WowTebOffset (0x1808), ResourceRetValue (0x1810). */
static const char *mr_wowoff_okrest( TEB *teb )
{
    /* UTF-8 diagnostic text is 181 bytes + NUL (eight words and nz in 0..8). */
    static char buf[256];
    /* ★ ИТЕРАЦИЯ 86 — ШИРЕ, ЧЕМ ТРИ СЛОВА.
     *
     * Замер 73 показал: едут ровно 4 байта, три соседних слова нули. Замер 77 я
     * истолковал как «там живёт чужая переменная». Но нули ВОКРУГ этому противоречат:
     * гостевой стек или куча дали бы плотные ненулевые данные. Смотрим 64 байта
     * (0x17E0..0x1820): если всё вокруг нули, версия про гостевую переменную слабеет,
     * и запись скорее прицельная. */
    const ULONG64 *w = (const ULONG64 *)((const char *)teb + 0x17e0);
    unsigned mr_i, mr_nz = 0;
    for (mr_i = 0; mr_i < 8; mr_i++) if (w[mr_i]) mr_nz++;
    snprintf( buf, sizeof(buf), "окрест[17e0..1820]=%016llx %016llx %016llx %016llx %016llx %016llx "
             "%016llx %016llx ненулевых=%u",
             (unsigned long long)w[0], (unsigned long long)w[1], (unsigned long long)w[2],
             (unsigned long long)w[3], (unsigned long long)w[4], (unsigned long long)w[5],
             (unsigned long long)w[6], (unsigned long long)w[7], mr_nz );
    buf[sizeof(buf) - 1] = 0;
    return buf;
}

/* ★★★★★ ИТЕРАЦИЯ 89 — ЗАЩИТА СТРАНИЦЫ TEB ТОЛЬКО НА ВРЕМЯ ИСПОЛНЕНИЯ ГОСТЯ.
 *
 * Двадцать итераций не закрыт вопрос «хозяин или гость». Все писатели, называющие поле
 * по имени, оправданы замером (87: 59 записей, все 0x2000); сканы по константе исчерпаны
 * (74); блочная запись исключена (73); вокруг поля 56 байт нулей (86). Осталась запись
 * промахнувшимся указателем, и она СИСТЕМАТИЧЕСКАЯ: за прогон бьёт дважды в те же 4 байта.
 *
 * Опыт: снимать право записи на `выход-сервиса` и возвращать на `вход-сервиса`. Между
 * ними исполняется ГОСТЬ. Порча при снятых правах -> писал гость, и `macrunner-vhf-probe`
 * напечатает pc. Порча только при возвращённых -> писал хозяин.
 *
 * Гейт с умолчанием 0, потолок циклов, счётчик в конце — иначе поломку не отличить от
 * находки. Готового сторожа в движке нет: GUARD_PAGE_DELIVERY меняет доставку отказа,
 * JIT_WATCH_STORE помечен в памяти как слепой к i386 (итерация 88). */
static int mr_teb_guard_on( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        static const WCHAR nameW[] = L"MACRUNNER_WOW64_TEB_GUARD";
        WCHAR value[4] = { 0 };
        UNICODE_STRING name, val;
        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value; val.Length = 0; val.MaximumLength = sizeof(value);
        cached = 0;
        if (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND
            && value[0] && value[0] != '0')
            cached = (value[0] == '2') ? 2 : (value[0] == '3') ? 3 : 1;
    }
    return cached;
}

static void mr_teb_guard( int protect )
{
    static unsigned mr_cycles;
    TEB *teb = NtCurrentTeb();
    void *addr;
    SIZE_T size = 0x4000;
    ULONG old = 0;

    __asm__ __volatile__( "" : "+r"(teb) );
    if (!teb || !mr_teb_guard_on()) return;
    if (mr_cycles > 4000000u) return;
    /* ★★★★★ ИТЕРАЦИЯ 96 — ЗАЩИЩАЕМ ЦЕЛУЮ ХОЗЯЙСКУЮ СТРАНИЦУ 16 КБ, А НЕ 4 КБ.
     *
     * Итерация 95 нашла корень: `get_host_page_vprot` ОБЪЕДИНЯЕТ права четырёх
     * подстраниц (замер: хозяйская 0x4000, гостевая 0x1000, кратность 4), поэтому
     * защита 4 КБ теряется, если сосед записываем. Проверяем это опытом: берём весь
     * выровненный кусок 0x4000 от начала TEB. TEB лежит по гостевому 0x1F0000 —
     * кратно 16 КБ, значит выравнивать нечего.
     *
     * Ожидание: mach должен показать r--, а контрольная запись — упасть. Оба исхода
     * самоподписывающиеся. */
    addr = (char *)teb;
    if (protect) mr_cycles++;
    {
        NTSTATUS mr_st = NtProtectVirtualMemory( GetCurrentProcess(), &addr, &size,
                                                 protect ? PAGE_READONLY : PAGE_READWRITE, &old );
        /* ★★★★★ ИТЕРАЦИЯ 91 — ЧТО РЕАЛЬНО СТОИТ НА СТРАНИЦЕ.
         *
         * Итерация 90: запись под PAGE_READONLY прошла, отказа нет — прибор слеп.
         * Две причины дают одно и то же наблюдение, и различает их один запрос:
         *   Protect == PAGE_READONLY, а запись проходит -> права не доносятся до
         *       настоящего отображения (память заведена мимо учёта wine);
         *   Protect == PAGE_READWRITE -> wine прав не применил, чинить надо путь
         *       смены прав, а не отображение.
         * Печатаем и статус вызова, и то, что отвечает разметка. Первые 4 цикла. */
        if (mr_cycles <= 4 && protect)
        {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T got = 0;
            void *chk = (char *)teb + 0x180c;
            NTSTATUS q = NtQueryVirtualMemory( GetCurrentProcess(), chk,
                                               MemoryBasicInformation, &mbi, sizeof(mbi), &got );
            MESSAGE( "macrunner-wow64-teb-права: цикл=%u статус_защиты=%08lx прежние=%08lx "
                     "запрос=%08lx СТАЛО=%08lx база_обл=%p размер=%Ix\n",
                     mr_cycles, (unsigned long)mr_st, (unsigned long)old,
                     (unsigned long)q, (unsigned long)mbi.Protect,
                     mbi.BaseAddress, (SIZE_T)mbi.RegionSize );
        }
    }
    if (mr_cycles == 1 && protect)
        MESSAGE( "macrunner-wow64-teb-сторож: ВКЛЮЧЁН addr=%p прежние_права=%08lx\n",
                 addr, (unsigned long)old );
    /* ★★★★★ ИТЕРАЦИЯ 90 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ПРИБОРА.
     *
     * Итерация 89 дала «отказов по адресу TEB ноль» и предварительный вывод «писал
     * хозяин». Но ноль засчитывается только у прибора, про который ДОКАЗАНО, что он
     * показал бы ненулевое. Здесь это не доказано: защита могла не действовать вовсе
     * (та же память через другое окно — у нас так уже бывало, итерация 84).
     *
     * Контроль: при `MACRUNNER_WOW64_TEB_GUARD=2` один раз за прогон пишем в поле
     * САМИ, сразу после снятия прав. Исход самоподписывающийся:
     *   отказ -> в журнале «контроль-до» и vhf-probe с НАШИМ pc: прибор годен;
     *   нет отказа -> в журнале «контроль-после» и зонд увидит смену на 0xDEADBEEF:
     *                 прибор СЛЕП, и все выводы итерации 89 снимаются. */
    /* ★★★★★ ИТЕРАЦИЯ 93 — КОНТРОЛЬ НА ОБЫЧНОЙ ПАМЯТИ.
     *
     * Итерация 92: на странице гостевой арены mach отвечает `rw-` после успешного
     * PAGE_READONLY, то есть mprotect туда не доходит. Осталось опровергающее условие:
     * а доходит ли он до ОБЫЧНОЙ памяти? Прежний прогон дал по PE-модулям смешанную
     * картину (r-- в двух случаях, rw- в двух), и по ней судить нельзя — там разные
     * размеры и разные области.
     *
     * Чистый опыт: сами берём страницу БЕЗ гостевого адреса (значит вне арены), сами
     * ставим PAGE_READONLY, сами пишем. Исход самоподписывающийся:
     *   запись прошла  -> путь смены прав ломан ВООБЩЕ, дефект шире арены;
     *   отказ          -> для обычной памяти права работают, дефект локализован в арене.
     * Режим 3, отдельный от режима 2, чтобы не мешать другим замерам. */
    if (protect && mr_teb_guard_on() == 3)
    {
        static int mr_ord_done;
        if (!mr_ord_done)
        {
            void *mr_a = NULL;
            SIZE_T mr_sz = 0x1000;
            ULONG mr_old = 0;
            NTSTATUS mr_s1, mr_s2;
            mr_ord_done = 1;
            mr_s1 = NtAllocateVirtualMemory( GetCurrentProcess(), &mr_a, 0, &mr_sz,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if (!mr_s1 && mr_a)
            {
                volatile ULONG *mr_p = (volatile ULONG *)mr_a;
                void *mr_pa = mr_a;
                *mr_p = 0x11111111u;
                mr_s2 = NtProtectVirtualMemory( GetCurrentProcess(), &mr_pa, &mr_sz,
                                                PAGE_READONLY, &mr_old );
                MESSAGE( "macrunner-обычная-до: адрес=%p выделение=%08lx защита=%08lx "
                         "прежние=%08lx — сейчас пишу\n",
                         mr_a, (unsigned long)mr_s1, (unsigned long)mr_s2,
                         (unsigned long)mr_old );
                *mr_p = 0x22222222u;
                MESSAGE( "macrunner-обычная-после: запись ПРОШЛА, значение=%08lx\n",
                         (unsigned long)*mr_p );
            }
            else MESSAGE( "macrunner-обычная-ОТКАЗ-выделения: статус=%08lx\n",
                          (unsigned long)mr_s1 );
        }
    }
    if (protect && mr_teb_guard_on() == 2)
    {
        static int mr_ctl_done;
        if (!mr_ctl_done)
        {
            volatile ULONG *mr_p = (volatile ULONG *)((char *)teb + 0x180c);
            mr_ctl_done = 1;
            MESSAGE( "macrunner-wow64-teb-контроль-до: пишу 0xDEADBEEF по %p\n", (void *)mr_p );
            *mr_p = 0xDEADBEEFu;
            MESSAGE( "macrunner-wow64-teb-контроль-после: запись ПРОШЛА, значение=%08lx\n",
                     (unsigned long)*mr_p );
        }
    }
}

static void mr_wowoff_probe( const char *where, unsigned num )
{
    struct mr_wowoff_slot { void *teb; LONG off; };
    static struct mr_wowoff_slot mr_wowoff_tab[16];
    static unsigned mr_wowoff_used;
    TEB *teb = NtCurrentTeb();
    LONG now;
    unsigned i;

    /* ★ ИТЕРАЦИЯ 70 — КОНТРОЛЬ НА РЕМАТЕРИАЛИЗАЦИЮ x18.
     *
     * `NtCurrentTeb()` разворачивается в чтение x18, компилятор считает его чистым и
     * ВПРАВЕ пересчитать при каждом использовании. На macOS ядро чистит x18 при
     * sigreturn — и тогда одно и то же имя `teb` даёт в разных местах разные адреса.
     * В журнале это уже видно: строка НАЧАЛО печатает `teb=0000000000000000`, хотя
     * проверку `if (!teb) return;` выше пройти с нулём невозможно.
     *
     * Если так, то и «смена WowTebOffset» может быть не порчей памяти, а чтением ДРУГОГО
     * TEB. Барьер запрещает пересчёт: значение фиксируется в регистре один раз. */
    __asm__ __volatile__( "" : "+r"(teb) );
    if (!teb) return;
    now = teb->WowTebOffset;

    for (i = 0; i < mr_wowoff_used; i++)
        if (mr_wowoff_tab[i].teb == teb) break;

    if (i == mr_wowoff_used)
    {
        if (mr_wowoff_used >= 16) return;
        mr_wowoff_tab[i].teb = teb;
        mr_wowoff_tab[i].off = now;
        mr_wowoff_used++;
        MESSAGE( "macrunner-wow64-wowoff-НАЧАЛО: точка=%s teb=%p off=%08lx num=%08x %s\n",
                 where, teb, (unsigned long)(ULONG)now, num, mr_wowoff_okrest( teb ) );
        /* ★★★★★ ИТЕРАЦИЯ 75 — ЛЕЖИТ ЛИ ХОЗЯЙСКИЙ TEB В ГОСТЕВОЙ ПАМЯТИ.
         *
         * Гостевое окно 4 ГБ и хозяйский TEB делят одну базу: при базе 0x300000000 TEB
         * лежит по 0x3001F0000, то есть по ГОСТЕВОМУ линейному адресу 0x1F0000. Если эта
         * область гостю доступна на запись, то промах любого гостевого указателя рушит
         * TEB — и никакого хозяйского оператора для порчи WowTebOffset не нужно. Это
         * объясняло бы, почему писателя не нашли ни сканы по коду (итерации 73-74), ни
         * зонды по пути wow64 (71-72).
         *
         * Спрашиваем разметку про сам адрес поля. Один раз за нить, стоимость нулевая. */
        {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T got = 0;
            void *addr = (char *)teb + 0x180c;
            NTSTATUS st = NtQueryVirtualMemory( GetCurrentProcess(), addr,
                                                MemoryBasicInformation, &mbi, sizeof(mbi), &got );
            /* ★ ИТЕРАЦИЯ 78 — ЧЬЁ ЭТО ВЫДЕЛЕНИЕ. `AllocationBase` отвечает на вопрос,
             * который восемь итераций решался зондами: если начало выделения совпадает
             * с TEB — область хозяйская; если лежит ниже и захватывает TEB — она общая
             * с гостем, и тогда порча не чья-то ошибка, а следствие разметки. */
            MESSAGE( "macrunner-wow64-teb-разметка: адрес=%p гостевой=%08lx статус=%08lx "
                     "база=%p начало_выделения=%p размер=%Ix состояние=%08lx права=%08lx "
                     "тип=%08lx защита_нач=%08lx teb=%p teb32=%p\n",
                     addr, (unsigned long)(ULONG)(ULONG_PTR)addr, (unsigned long)st,
                     mbi.BaseAddress, mbi.AllocationBase, (SIZE_T)mbi.RegionSize,
                     (unsigned long)mbi.State, (unsigned long)mbi.Protect,
                     (unsigned long)mbi.Type, (unsigned long)mbi.AllocationProtect,
                     teb, NtCurrentTeb32() );
            /* ★ ИТЕРАЦИЯ 82 — ЕСТЬ ЛИ МЕСТО НИЖЕ БАЗЫ ОКНА.
             *
             * Решение из итерации 80: вынести блок TEB ниже базы гостевого окна. Гость
             * формирует только адреса вида `база | L`, поэтому адрес ниже базы он
             * выразить не может; смещение при этом остаётся малым и укладывается в
             * знаковый LONG. Итерация 81 проверила, что вывод базы это переживёт.
             * Осталась последняя дешёвая граница: свободно ли там место. */
            {
                ULONG_PTR mr_base = (ULONG_PTR)NtCurrentTeb32() & ~(ULONG_PTR)0xffffffff;
                static const SIZE_T mr_probes[] = { 0x10000, 0x100000, 0x1000000 };
                unsigned mr_k;
                for (mr_k = 0; mr_k < 3; mr_k++)
                {
                    MEMORY_BASIC_INFORMATION m2;
                    SIZE_T g2 = 0;
                    void *a2 = (void *)(mr_base - mr_probes[mr_k]);
                    NTSTATUS s2 = NtQueryVirtualMemory( GetCurrentProcess(), a2,
                                                        MemoryBasicInformation, &m2, sizeof(m2), &g2 );
                    MESSAGE( "macrunner-wow64-ниже-базы: смещение=-%Ix адрес=%p статус=%08lx "
                             "начало_выделения=%p размер=%Ix состояние=%08lx тип=%08lx\n",
                             mr_probes[mr_k], a2, (unsigned long)s2, m2.AllocationBase,
                             (SIZE_T)m2.RegionSize, (unsigned long)m2.State,
                             (unsigned long)m2.Type );
                }
            }
        }
    }
    else if (mr_wowoff_tab[i].off != now)
    {
        MESSAGE( "macrunner-wow64-wowoff-СМЕНА: точка=%s teb=%p было=%08lx стало=%08lx num=%08x %s\n",
                 where, teb, (unsigned long)(ULONG)mr_wowoff_tab[i].off,
                 (unsigned long)(ULONG)now, num, mr_wowoff_okrest( teb ) );
        mr_wowoff_tab[i].off = now;
    }
}



NTSTATUS WINAPI Wow64SystemServiceEx( UINT num, UINT *args )
{
    NTSTATUS status;
    UINT id = num & 0xfff;
    const SYSTEM_SERVICE_TABLE *table = &syscall_tables[(num >> 12) & 3];
    BOOL macrunner_trace_syscall = (num == 0x23 || num == 0x3d);

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: НЕВОЗМОЖНЫЙ НОМЕР НАДО ОТВЕРГАТЬ, А НЕ МАСКИРОВАТЬ.
     *
     * Проверка ниже смотрит только на `id`, то есть на младшие 12 бит, и на выбранную
     * таблицу. Старшие биты при этом ОТБРАСЫВАЮТСЯ молча. Из-за этого номер 0xc0000005
     * (а это STATUS_ACCESS_VIOLATION, не номер вызова) превращается в id=5, таблица 0 —
     * и проходит проверку как совершенно законный wow64_NtCallbackReturn. А тот не
     * возвращается: он делает длинный переход в кадр Wow64KiUserCallbackDispatcher.
     * Если кадра нет или он несвежий, управление уходит в произвольный адрес.
     *
     * Именно это и есть стена ступени 1, измеренная 10.08: гость переходит по адресу
     * 0x056af130, там шестнадцать нулей (проверено дампом байтов), права страницы
     * чтение-запись без исполнения, дальше 4096 одинаковых отказов выборки инструкции —
     * и HyperBridge отказывается продолжать. Адрес детерминированный: два прогона с
     * разными базами гостя дали одно и то же гостевое смещение.
     *
     * Номер вызова WOW64 занимает биты 0-11 (id) и 12-13 (таблица). Всё, что выше
     * 0x3fff, номером быть не может. Отвергаем и НАЗЫВАЕМ вызывающего — иначе мы лечим
     * симптом, не зная источника. */
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ПАРНЫЙ СЧЁТЧИК к `macrunner-disp` в xtajit.
     * Больше входов здесь, чем там, означает вход в диспетчер МИМО нашего пути. */
    {
        static LONG macrunner_wssex_seq;
        ULONG seq = InterlockedIncrement( &macrunner_wssex_seq );

        /* Keep the existing probe cheap and bounded: first 64, then 64
         * checkpoints. The retained n is exact; omitted per-call rows are
         * explicitly DROPPED, never evidence of absent syscalls. */
        if (seq <= 64 || (seq <= 0x400000 && !(seq & 0xffff)))
            MESSAGE( "macrunner-wssex: n=%u num=%08x policy=BOUNDED\n", seq, num );
        if (seq == 0x400001)
            MESSAGE( "macrunner-wssex: state=DROPPED n=%u per_call_budget=128\n", seq );
    /* ★ MacRunner 2026-09-02 — КТО КРУТИТ NtUserWindowFromDC (режим H). Зонд в handle_bop_context xtajit видел 8 вызовов
     * из миллионов: спин идёт не через тот путь. Здесь видны ВСЕ системные вызовы. Гостевая цепочка возврата по ebp,
     * адреса проверены до разыменования (урок delay-caller). Первые 8 и каждая 2000-я (h-4: спин начался за ~13 тыс. вызовов до alarm, 20000-я не наступила); глубина 14 кадров —
     * 6 обрывались на wined3d_context_gl_cleanup_resources, ниже уровня петли (hfix-on-1). */
    if (num == 0x15fd && pBTCpuGetContext)
    {
        static unsigned int wfdc_n;
        unsigned int wn = ++wfdc_n;
        if (wn <= 8 || !(wn % 2000))
        {
            I386_CONTEXT c = { CONTEXT_I386_FULL };
            if (!pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &c ))
            {
                ULONG fp = c.Ebp;
                char buf[480];
                int pos = 0;
                unsigned d;
                for (d = 0; d < 14 && fp; d++)
                {
                    const ULONG *fr;
                    if (fp < 0x10000 || (fp & 3) || fp > 0xfffffff0u) break;
                    fr = guest32_host_ptr( fp );
                    if (!fr) break;
                    pos += snprintf( buf + pos, sizeof(buf) - pos, " [%u]=%08lx", d, (unsigned long)fr[1] );
                    if ((size_t)pos >= sizeof(buf)) break;
                    fp = fr[0];
                }
                MESSAGE( "macrunner-wow64: wfdc-chain n=%u eip=%08lx esp=%08lx tid=%04lx кадры:%s\n",
                         wn, (unsigned long)c.Eip, (unsigned long)c.Esp,
                         (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread, buf );
            }
        }
    }

        mr_teb_guard( 0 );   /* гость отработал — вернуть право записи */
        mr_wowoff_probe( "вход-сервиса", num );
    }
    /* ★ MacRunner, лейн ЛЕСТНИЦА, итерация 2618 — В КАКОМ СИСТЕМНОМ ВЫЗОВЕ ВЫДАН
     * ОБРАТНЫЙ ВЫЗОВ ОКОННОЙ ПРОЦЕДУРЫ.
     *
     * 2617 переформулировал аномалию: у 47 здоровых обратных вызовов контекст гостя
     * указывает внутрь переходника системного вызова (00270000), а у больного — на
     * возврат из `call [eax]`, то есть гость как будто ВНЕ системного вызова.
     * Проверить это можно только назвав вызов, внутри которого хозяин отправляет
     * обратный вызов. Пишем «текущий вызов» в табличку по потокам и читаем её в
     * диспетчере обратных вызовов.
     *
     * Табличка, а не одна переменная и не TLS: потоков здесь два (замер 2614 —
     * 00e0 и 012c), TLS в этом PE-модуле заводить рискованно, а одна общая переменная
     * дала бы ровно то предположение об одном потоке, на котором я уже обжигался. */
    macrunner_svc_enter( num );
    mr_wowoff_probe( "после-svc-enter", num );
    /* ★ 26.08: контекст ПЕРВОГО уровня — тот, где гость стоит на трамплине. Вложенные
     * вызовы его не перетирают: обратному вызову нужна именно внешняя граница.
     * Снимаем здесь, а не в macrunner_svc_enter: там pBTCpuGetContext ещё не объявлен. */
    if (macrunner_nested_cb_ctx() && current_machine == IMAGE_FILE_MACHINE_I386 && pBTCpuGetContext)
    {
        unsigned si = macrunner_svc_index();
        if (macrunner_svc_slot[si].live == 1)
        {
            I386_CONTEXT c = { CONTEXT_I386_FULL };
            if (!pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &c ))
            {
                macrunner_svc_slot[si].entry_ctx32   = c;
                macrunner_svc_slot[si].has_entry_ctx = 1;
            }
        }
    }
    mr_wowoff_probe( "после-ctx", num );
    if (num >= 0x4000)
    {
        static unsigned int macrunner_bogus_n;

        if (macrunner_bogus_n++ < 8)
            MESSAGE( "macrunner-wow64-bogus-service: n=%u num=%08x args=%p caller=%p "
                     "— не номер системного вызова, отказываю вместо маскирования\n",
                     macrunner_bogus_n, num, args, __builtin_return_address(0) );
        macrunner_svc_leave();
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    if (id >= table->ServiceLimit || !table->ServiceTable[id])
    {
        ERR( "unsupported syscall %04x\n", num );
        macrunner_svc_leave();
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    mr_wowoff_probe( "после-проверок", num );
    mr_wowoff_probe( "после-проверок-ДУБЛЬ", num );
    /* ★★★★ ПАКЕТ-2 (договор T5) — БАЗА АРЕНЫ НЕ НАЗНАЧАЕТСЯ ПРИ ВЛАДЕЛЬЦЕ FEX.
     *
     * Ниже на КАЖДОМ системном вызове переписывается глобальная `macrunner_wow64_guest32_base`
     * — та самая, через которую `guest32_host_ptr()` склеивает каждый 32-битный указатель.
     * Для FEX это не просто лишнее: тождество «гостевой VA == хозяйский VA» после такой
     * записи перестаёт держаться, и отказ будет тихим — указатель правдоподобен, старшие
     * биты чужие.
     *
     * ★ Спрашиваем ОДИН РАЗ на процесс, а не на вызов: ответ селектора по построению
     * неизменен (пакет 1 кеширует его и не даёт переиграть из гостя), а место — горячий
     * путь системного вызова, и линейный поиск по таблице семей здесь был бы платой ни за
     * что. Одной строки прибора на руку достаточно: она доказывает и достижимость места,
     * и сторону, которую оно взяло. */
    {
        static int mr_paket2_muted = -1;
        if (mr_paket2_muted < 0)
            mr_paket2_muted = macrunner_wow64_paket2_mute( "T5-base-syscall" ) ? 1 : 0;
        if (mr_paket2_muted) goto mr_paket2_skip_base;
    }
    if (native_machine == IMAGE_FILE_MACHINE_ARM64 && current_machine == IMAGE_FILE_MACHINE_I386)
    {
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: БАЗУ БРАТЬ ИЗ TEB32, А НЕ ИЗ `args`.
         *
         * Здесь стояло безусловное `base = args & ~0xffffffff`, и это ГЛОБАЛЬНАЯ на процесс
         * переменная, через которую guest32_host_ptr() склеивает КАЖДЫЙ 32-битный указатель
         * (wow64_private.h:102). Проверки, что `args` вообще указывает в гостевую область,
         * не было никакой. Один системный вызов с негодным `args` отравляет базу — и дальше
         * все указатели получают чужие старшие биты.
         *
         * Ровно это и намерено на стене ступени 1: memmove отказывает по адресу
         * 0xb1be2a7f_8ba11000 — младшие 32 бита правдоподобны, старшие мусор, а верной
         * базой в том прогоне была 0x0000000b (teb32=0x0000000B001F2000).
         *
         * thread_init() строкой 1074 уже берёт базу из NtCurrentTeb32() — это правильный
         * источник, просто он тут не использовался. Предпочитаем его, `args` оставляем
         * запасным на случай, когда TEB32 ещё не заведён.
         *
         * Гейт MACRUNNER_WOW64_BASE_FROM_TEB32, умолчание ВКЛ (=0 возвращает прежнее
         * поведение для A/B): выключенные по умолчанию гейты в этом проекте уже терялись. */
        static int prefer_teb32 = -1;
        ULONG_PTR from_args = (ULONG_PTR)args & ~(ULONG_PTR)0xffffffff;
        TEB32 *teb32 = NtCurrentTeb32();
        ULONG_PTR from_teb = teb32 ? ((ULONG_PTR)teb32 & ~(ULONG_PTR)0xffffffff) : 0;
        ULONG_PTR base;

        if (prefer_teb32 < 0)
        {
            static const WCHAR nameW[] =
                {'M','A','C','R','U','N','N','E','R','_','W','O','W','6','4','_',
                 'B','A','S','E','_','F','R','O','M','_','T','E','B','3','2',0};
            WCHAR value[4] = { 0 };
            UNICODE_STRING name, val;

            RtlInitUnicodeString( &name, nameW );
            val.Buffer = value;
            val.Length = 0;
            val.MaximumLength = sizeof(value);
            /* ★★★★★ ИТЕРАЦИЯ 77 — ЕДИНСТВЕННЫЙ ВЫЗОВ В ЭТОМ ОТРЕЗКЕ, И ОН РАЗОВЫЙ.
             *
             * Порча `WowTebOffset` (0x2000 -> 0xAA64) случается РОВНО ОДИН раз за прогон
             * и обнаруживается всегда между `после-проверок-ДУБЛЬ` и `до-обработчика`.
             * Пишущих операторов в этом отрезке нет (итерации 71-74, все отвергнуты
             * замером). Осталось единственное, что тут вообще ВЫЗЫВАЕТСЯ, — этот запрос
             * окружения, и он тоже происходит РОВНО ОДИН раз за процесс: `prefer_teb32`
             * инициализируется единожды.
             *
             * Совпадение «один раз за прогон» с «один раз за процесс» само по себе ничего
             * не доказывает — нужно сравнить МОМЕНТЫ. Печатаем момент запроса; если он
             * совпадает с моментом смены, кандидат становится первым за десять итераций,
             * у которого сходится и подпись, и время. */
            {
                LONG mr_do = NtCurrentTeb()->WowTebOffset;
                prefer_teb32 = (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) ==
                                STATUS_VARIABLE_NOT_FOUND || value[0] != '0');
                MESSAGE( "macrunner-wow64-envquery: num=%08x wowoff_до=%08lx wowoff_после=%08lx "
                         "val_len=%u prefer=%d\n", num, (unsigned long)(ULONG)mr_do,
                         (unsigned long)(ULONG)NtCurrentTeb()->WowTebOffset,
                         (unsigned)val.Length, prefer_teb32 );
            }
        }

        base = (prefer_teb32 && from_teb) ? from_teb : from_args;

        /* Безусловный зонд: расхождение — это и есть отравление, показать его прямо. */
        if (from_teb && from_args != from_teb)
        {
            static unsigned int mismatch_n;
            if (mismatch_n++ < 8)
                MESSAGE( "macrunner-wow64-base-mismatch: n=%u num=%08x args_base=%Ix "
                         "teb32_base=%Ix взято=%Ix\n",
                         mismatch_n, num, from_args, from_teb, base );
        }

        macrunner_wow64_guest32_base = base;
        /* ★ ИТЕРАЦИЯ 72 — ЕДИНСТВЕННОЕ НЕИЗМЕРЕННОЕ В ЭТОМ БЛОКЕ.
         *
         * `NtCurrentTeb()` разворачивается в чтение x18 и считается компилятором чистым,
         * поэтому он ВПРАВЕ пересчитать его прямо здесь. Рематериализация в этом модуле
         * ДОКАЗАНА (итерация 70: печать выдавала teb=0, хотя проверку на ноль пройти с
         * нулём нельзя), а macOS чистит x18 при sigreturn. Тогда запись слота уходит по
         * адресу от ЧУЖОГО значения x18 — и это единственный оператор блока, который
         * вообще куда-то пишет.
         *
         * Барьер фиксирует указатель один раз. Это не вызов функции: четыре вызова,
         * добавленные в этот блок в итерации 68, обрушили прогон с 72 682 до 550. */
        {
            TEB *mr_t = NtCurrentTeb();
            __asm__ __volatile__( "" : "+r"(mr_t) );
            mr_t->TlsSlots[MACRUNNER_WOW64_TLS_GUEST32_BASE] = (void *)base;
        }
    }
mr_paket2_skip_base:            /* ПАКЕТ-2 (T5): сюда уходит рука, где владелец не HyperBridge */
    if (macrunner_trace_syscall)
        MESSAGE( "macrunner-wow64: Wow64SystemServiceEx enter num=%08x args=%p thunk=%p templist=%p\n",
                 num, args, (void *)table->ServiceTable[id], NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] );
    mr_wowoff_probe( "до-обработчика", num );
    status = wow64_syscall( args, table->ServiceTable[id], NtCurrentTeb() );
    mr_wowoff_probe( "после-обработчика", num );
    if (macrunner_trace_syscall)
        MESSAGE( "macrunner-wow64: Wow64SystemServiceEx after-syscall num=%08x status=%08lx templist=%p\n",
                 num, status, NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] );
    free_temp_data();
    if (macrunner_trace_syscall)
        MESSAGE( "macrunner-wow64: Wow64SystemServiceEx leave num=%08x status=%08lx templist=%p\n",
                 num, status, NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] );
    macrunner_svc_leave();
    mr_wowoff_probe( "выход-сервиса", num );
    mr_teb_guard( 1 );   /* дальше исполняется гость — снять право записи */
    return status;
}


/**********************************************************************
 *           cpu_simulate
 */
#ifdef __aarch64__
extern void DECLSPEC_NORETURN cpu_simulate(void);
__ASM_GLOBAL_FUNC( cpu_simulate,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler cpu_simulate_handler, @except\n"
                   ".Lcpu_simulate_loop:\n\t"
                   "adrp x16, pBTCpuSimulate\n\t"
                   "ldr x16, [x16, :lo12:pBTCpuSimulate]\n\t"
                   "blr x16\n\t"
                   "b .Lcpu_simulate_loop" )
__ASM_GLOBAL_FUNC( cpu_simulate_handler,
                   "stp x29, x30, [sp, #-48]!\n\t"
                   ".seh_save_fplr_x 48\n\t"
                   "stp x19, x20, [sp, #16]\n\t"
                   ".seh_save_regp x19, 16\n\t"
                   ".seh_endprologue\n\t"
                   "mov x19, x0\n\t"            /* record */
                   "mov x20, x1\n\t"            /* frame */
                   "ldr w4, [x0, #4]\n\t"       /* record->ExceptionFlags */
                   "tst w4, #6\n\t"             /* EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND */
                   "b.ne 1f\n\t"
                   "stp x0, x2, [sp, #32]\n\t"  /* record, context */
                   "add x0, sp, #32\n\t"
                   "bl Wow64PassExceptionToGuest\n\t"
                   "mov x0, x20\n\t"            /* frame */
                   "adr x1, .Lcpu_simulate_loop\n\t" /* target */
                   "mov x2, x19\n\t"            /* record */
                   "bl RtlUnwind\n\t"
                   "1:\tmov w0, #1\n\t"         /* ExceptionContinueSearch */
                   "ldp x19, x20, [sp, #16]\n\t"
                   "ldp x29, x30, [sp], #48\n\t"
                   "ret" )
#else
extern void DECLSPEC_NORETURN cpu_simulate(void);
__ASM_GLOBAL_FUNC( cpu_simulate,
                   "subq $0x28, %rsp\n\t"
                   ".seh_stackalloc 0x28\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler cpu_simulate_handler, @except\n\t"
                   ".Lcpu_simulate_loop:\n\t"
                   "call *pBTCpuSimulate(%rip)\n\t"
                   "jmp .Lcpu_simulate_loop" )
__ASM_GLOBAL_FUNC( cpu_simulate_handler,
                   "subq $0x38, %rsp\n\t"
                   ".seh_stackalloc 0x38\n\t"
                   ".seh_endprologue\n\t"
                   "movq %rcx,%rsi\n\t"         /* record */
                   "movq %rcx,0x20(%rsp)\n\t"
                   "movq %rdx,%rdi\n\t"         /* frame */
                   "movq %r8,0x28(%rsp)\n\t"    /* context */
                   "leaq 0x20(%rsp),%rcx\n\t"
                   "call Wow64PassExceptionToGuest\n\t"
                   "movq %rdi,%rcx\n\t"         /* frame */
                   "leaq .Lcpu_simulate_loop(%rip), %rdx\n\t"  /* target */
                   "movq %rsi,%r8\n\t"          /* record */
                   "call RtlUnwind\n\t"
                   "int3" )
#endif


/**********************************************************************
 *           Wow64AllocateTemp  (wow64.@)
 *
 * FIXME: probably not 100% compatible.
 */
void * WINAPI Wow64AllocateTemp( SIZE_T size )
{
    struct mem_header *mem;
    HANDLE heap = process_heap ? process_heap : GetProcessHeap();

    if (!(mem = RtlAllocateHeap( heap, 0, offsetof( struct mem_header, data[size] ))))
        return NULL;
    mem->next = NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST];
    NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] = mem;
    return mem->data;
}


/**********************************************************************
 *           Wow64ApcRoutine  (wow64.@)
 */
void WINAPI Wow64ApcRoutine( ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3, CONTEXT *context )
{
    struct user_apc_frame frame;

    frame.prev_frame = NtCurrentTeb()->TlsSlots[WOW64_TLS_APCLIST];
    frame.context    = context;
    NtCurrentTeb()->TlsSlots[WOW64_TLS_APCLIST] = &frame;

    /* cf. 32-bit call_user_apc_dispatcher */
    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        {
            /* stack layout when calling 32-bit KiUserApcDispatcher */
            struct apc_stack_layout32
            {
                ULONG             func;          /* 000 */
                UINT              arg1;          /* 004 */
                UINT              arg2;          /* 008 */
                UINT              arg3;          /* 00c */
                UINT              alertable;     /* 010 */
                I386_CONTEXT      context;       /* 014 */
                CONTEXT_EX32      xctx;          /* 2e0 */
                UINT              unk2[4];       /* 2f8 */
            } *stack;
            I386_CONTEXT ctx = { CONTEXT_I386_FULL };

            C_ASSERT( offsetof(struct apc_stack_layout32, context) == 0x14 );
            C_ASSERT( sizeof(struct apc_stack_layout32) == 0x308 );

            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );

            stack = (struct apc_stack_layout32 *)guest32_host_ptr( ctx.Esp & ~3 ) - 1;
            stack->func      = arg1 >> 32;
            stack->arg1      = arg1;
            stack->arg2      = arg2;
            stack->arg3      = arg3;
            stack->alertable = TRUE;
            stack->context   = ctx;
            stack->xctx.Legacy.Offset = -(LONG)sizeof(stack->context);
            stack->xctx.Legacy.Length = sizeof(stack->context);
            stack->xctx.All.Offset    = -(LONG)sizeof(stack->context);
            stack->xctx.All.Length    = sizeof(stack->context) + sizeof(stack->xctx);
            stack->xctx.XState.Offset = 25;
            stack->xctx.XState.Length = 0;

            ctx.Esp = PtrToUlong( stack );
            ctx.Eip = pLdrSystemDllInitBlock->pKiUserApcDispatcher;
            frame.wow_context = &stack->context;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            cpu_simulate();
        }
        break;

    case IMAGE_FILE_MACHINE_ARMNT:
        {
            struct apc_stack_layout
            {
                ULONG       func;
                ULONG       align[3];
                ARM_CONTEXT context;
            } *stack;
            ARM_CONTEXT ctx = { CONTEXT_ARM_FULL };

            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            stack = (struct apc_stack_layout *)ULongToPtr( ctx.Sp & ~15 ) - 1;
            stack->func = arg1 >> 32;
            stack->context = ctx;
            ctx.Sp = PtrToUlong( stack );
            ctx.Pc = pLdrSystemDllInitBlock->pKiUserApcDispatcher;
            ctx.R0 = PtrToUlong( &stack->context );
            ctx.R1 = arg1;
            ctx.R2 = arg2;
            ctx.R3 = arg3;
            frame.wow_context = &stack->context;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            cpu_simulate();
        }
        break;
    }
}


/**********************************************************************
 *           Wow64KiUserCallbackDispatcher  (wow64.@)
 */
/* Гейт приборов диспетчера обратных вызовов. Умолчание ВКЛ — поведение прежнее.
 * Читаем ОДИН раз: RtlQueryEnvironmentVariable здесь дешевле getenv (libc не линкуется,
 * модуль собран с -nodefaultlibs), а на горячем пути значение уже закешировано. */
static int macrunner_wow64_cb_trace(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        UNICODE_STRING name, value;
        WCHAR buf[8];
        static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','W','O','W','6','4',
                                      '_','C','B','_','T','R','A','C','E',0};
        RtlInitUnicodeString( &name, nameW );
        value.Buffer = buf;
        value.Length = 0;
        value.MaximumLength = sizeof(buf);
        if (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) && value.Length >= sizeof(WCHAR))
            cached = (buf[0] != '0');
        else
            cached = 1;   /* умолчание: приборы ВКЛЮЧЕНЫ, поведение прежнее */
    }
    return cached;
}

NTSTATUS WINAPI Wow64KiUserCallbackDispatcher( ULONG id, void *args, ULONG len,
                                               void **ret_ptr, ULONG *ret_len )
{
    WOW64_CPURESERVED *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];
    TEB32 *teb32 = NtCurrentTeb32();
    ULONG teb_frame;
    /* ★★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — РАЗЛИЧИТЕЛЬ ДВУХ ВЕРСИЙ ОДНОЙ СТЕНЫ.
     *
     * Установщик menuGEO умирает единственным c0000005 в ЭПИЛОГЕ этой функции:
     *   wow64.dll+0x32660 = Wow64KiUserCallbackDispatcher+0x7f4
     *   b900035c = `str w28,[x26]`,  x26=0xaa64  ->  запись `teb32->Tib.ExceptionList`
     * Место опознано подписью места вызова, не догадкой о базе. После отказа ноль
     * гостевых вызовов — он терминальный.
     *
     * ЭТО ТА ЖЕ СТЕНА, что у Heroes III и UT99 (комментарий ниже, 29.08): у них
     * wow64.dll+0x337cc, `ldrb w25,[x22]` — ЧТЕНИЕ того же поля на ВХОДЕ.
     *
     * Счёт сужает причину: `resumed` 194 раза, `leave` 193 — портится ОДИН раз из 194,
     * а не постоянно. Отсюда две версии:
     *   (а) NtCurrentTeb32() отдал мусор на входе;
     *   (б) значение испорчено переходом longjmp: `teb32` локальная и НЕ volatile,
     *       компилятор держит её в x26 — регистре, который восстанавливает longjmp,
     *       а по языку значение такой переменной после longjmp НЕОПРЕДЕЛЕНО.
     *
     * Различитель: копия входа в volatile (её longjmp обязан сохранить) против
     * обычной переменной и против свежего вызова. Печать в эпилоге ДО записи. */
    TEB32 * volatile teb32_vhod = teb32;

    /* ★★★★★★ MacRunner 2026-08-29 — ИНВАРИАНТ ВСЕХ ИСТОЧНИКОВ ПЕРЕД ЧТЕНИЕМ TEB32.
     *
     * ОБЩИЙ блокер Heroes III и UT99: обе выводят по 3 кадра и замирают НАВСЕГДА
     * (60 с и 180 с дают одинаковые 1075 и ~1305 вызовов гостя). Падает ровно здесь —
     * `wow64.dll+0x337cc`, инструкция `ldrb w25,[x22]`, то есть первое же чтение
     * `teb32->Tib.ExceptionList`.
     *
     * Что известно замером:
     *   vhf-probe: addr=0x50036fff8 pc=0x6ffffaee37cc site=bus
     *   vhf-probe-vm: vm_base=0x500280000 vm_size=f0000 prot=0   ← У ОБЛАСТИ НЕТ ПРАВ
     * При базе окна 0x500000000 адрес 0x50036fff8 — это ГОСТЕВОЙ 0x36fff8, ровно 8 байт
     * перед трамплином 0x370000, тогда как настоящий TEB32 гостя лежит по 0x1F2000.
     * Значит NtCurrentTeb32() вернул НЕ ТОТ адрес.
     *
     * Версия «виноват собственный прибор» ОПРОВЕРГНУТА парным замером на одном двоичном:
     * с MACRUNNER_WOW64_CB_TRACE=1 и =0 числа совпадают (1075/3 кадра/SIGBUS=1).
     *
     * Печатаем ВСЕ источники разом, ДО обращения, — иначе по одному снимку не отличить
     * «TEB не тот» от «область снята». Приём тот же, что уже снял ложный корень за один
     * прогон (память invariant-vseh-istochnikov-srazu). */
    {
        static LONG inv_n;
        const TEB *teb64 = NtCurrentTeb();
        const ULONG *slot = (const ULONG *)((const char *)teb64 + 0x180c);
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T got = 0;
        NTSTATUS qs;

        qs = NtQueryVirtualMemory( GetCurrentProcess(), teb32, MemoryBasicInformation,
                                   &mbi, sizeof(mbi), &got );
        if (++inv_n <= 16)
            MESSAGE( "macrunner-wow64-ИНВАРИАНТ-teb32: n=%ld id=%lu teb64=%p поле180c=%08lx "
                     "teb32=%p | запрос=%08lx база=%p размер=%Ix права=%lx состояние=%lx\n",
                     (long)inv_n, id, teb64, (unsigned long)*slot, teb32,
                     (unsigned long)qs, mbi.BaseAddress, (ULONG_PTR)mbi.RegionSize,
                     (unsigned long)mbi.Protect, (unsigned long)mbi.State );

        /* ★ НЕ ЧИТАЕМ ПО НЕГОДНОМУ УКАЗАТЕЛЮ. Прежде здесь стояло безусловное
         * `teb32->Tib.ExceptionList`, и негодный teb32 убивал поток обратного вызова
         * SIGBUS'ом — после чего игра не делала НИ ОДНОГО вызова до конца прогона.
         * Отказ в этой точке неотличим для гостя от «окно перестало отвечать», поэтому
         * лучше продолжить с нулевым кадром, чем потерять поток целиком. */
        if (qs || !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        {
            static LONG bad_n;
            if (++bad_n <= 8)
                MESSAGE( "macrunner-wow64-TEB32-НЕГОДЕН: n=%ld id=%lu teb32=%p права=%lx — "
                         "кадр берём нулевым, поток не роняем\n",
                         (long)bad_n, id, teb32, (unsigned long)mbi.Protect );
            teb_frame = 0;
        }
        else teb_frame = teb32->Tib.ExceptionList;
    }
    struct user_callback_frame frame;
    USHORT flags = cpu->Flags;

    frame.prev_frame = NtCurrentTeb()->TlsSlots[WOW64_TLS_USERCALLBACKDATA];
    frame.temp_list  = NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST];
    frame.ret_ptr    = ret_ptr;
    frame.ret_len    = ret_len;

    NtCurrentTeb()->TlsSlots[WOW64_TLS_USERCALLBACKDATA] = &frame;
    NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] = NULL;
    MESSAGE( "macrunner-wow64: CallbackDispatcher enter id=%lu len=%lu frame=%p prev=%p flags=%04x\n",
             id, len, &frame, frame.prev_frame, flags );

    /* ★ MacRunner 2026-08-22, лейн ЛЕСТНИЦА, итерация 2676 — КТО ЗОВЁТ СО СТОРОНЫ ХОЗЯИНА.
     *
     * К этой точке привели пять итераций, и каждая закрывала подозреваемого:
     *   2613  контекст снят уже ПОСЛЕ `ret 0x10` — доказано дизассемблированием и стеком;
     *   2617  две копии контекста НЕ расходятся (0 из 125) — несимметрия отпала;
     *   2674  гость при больном вызове НЕ внутри НИ ОДНОГО системного вызова
     *         (esp контекста = пост-возвратный esp вызова 0x11ef, а не esp вызова 0x18);
     *   2675  `control=0` не встречается ни разу (0 из 4567) — механизм 2614 отпал.
     * Осталось единственное: кто и откуда шлёт оконный обратный вызов в такой момент.
     * Ответ даёт только обратная трасса ХОЗЯИНА — со стороны гостя её не видно.
     *
     * Печать сужена по `id==4` (оконная процедура): их за прогон единицы, тогда как
     * id=15 приходит десятками, а без сужения зонд утопит журнал и повлияет на явление —
     * ровно это случилось в 827 (155 тысяч строк, прогон не дошёл до окна).
     * Имя модуля берём `LdrFindEntryForAddress`: голый адрес пришлось бы разрешать вручную
     * по базам из других строк, а это ровно тот ручной шаг, на котором я уже ошибалась,
     * сравнивая `pc` с выводом `nm` без учёта сдвига образа. */
    /* ★★★★★★ MacRunner 2026-08-29 — ПРИБОРЫ ЭТОЙ ФУНКЦИИ ПОД ГЕЙТОМ.
     *
     * Общий блокер Heroes III и UT99 (обе выводят 3 кадра и замирают навсегда) падает
     * по адресу wow64.dll+0x337cc = Wow64KiUserCallbackDispatcher+0x1930, и рядом с этой
     * точкой в дизассемблере стоит `Wow64KiUserCallbackDispatcher.hexd` — массив ИЗ ЭТОГО
     * ЖЕ блока приборов. То есть подозреваемый — собственная отладочная печать, а не
     * механизм возврата. Судить об этом чтением кода нельзя: компилятор объединяет общие
     * части, и «блок под id==4» может исполняться иначе, чем читается.
     *
     * Поэтому приборы получают гейт, и вопрос решается ЗАМЕРОМ НА ОДНОМ ДВОИЧНОМ:
     * MACRUNNER_WOW64_CB_TRACE=0 гасит их целиком. Умолчание — ВКЛЮЧЕНО, чтобы поведение
     * без переменной не менялось (память gate-default-must-match-between-engine-and-test).
     * Пять ложных дефектов за день уже были следствием собственных приборов. */
    if (id == 4 && macrunner_wow64_cb_trace())
    {
        static LONG bt_n;
        LONG bk = InterlockedIncrement( &bt_n );
        /* ★ 2677: уровни 2-3 добавлены после того, как уровень 1 разрешился в
         * `ntdll.so!KeUserModeCallback+0x230` — штатный подъём из юникса в пользовательский
         * режим. Он сам по себе ничего не объясняет; интересен ЕГО вызывающий, то есть
         * функция win32u, которая решила прогнать оконную процедуру. Именно она назовёт
         * настоящий источник, независимо от таблички «последний вошедший вызов», у которой
         * 2618 сама признала границу. */
        /* ★ ОТКАТ 2677: уровни 2-3 УБРАНЫ. Со сборкой уровней 0-1 прогон доходил до 57,7 с
         * (98 167 строк); с уровнями 2-3 он умирал на 20-й секунде ещё в раннем пуске
         * (526 строк, ноль диспетчеризаций), и различие было только в них.
         * `__builtin_return_address` глубже первого уровня официально ненадёжен, и здесь это
         * подтвердилось поведением. Глубину брать иначе — не этим средством. */
        void *ra[2];
        unsigned r;

        ra[0] = __builtin_return_address(0);
        ra[1] = NULL; /* 0091: diagnostic stack walking must not dereference a caller frame. */
        for (r = 0; r < 2; r++)
        {
            LDR_DATA_TABLE_ENTRY *mod = NULL;
            char name[40] = "(нет)";
            ULONG_PTR rva = 0;

            if (ra[r] && !LdrFindEntryForAddress( ra[r], &mod ) && mod)
            {
                /* имя узкой строкой вручную: wine/debug.h в этом модуле не линкуется
                 * (-nodefaultlibs), а %s с WCHAR молча напечатал бы мусор */
                unsigned c = mod->BaseDllName.Length / sizeof(WCHAR);
                unsigned q;

                if (c > sizeof(name) - 1) c = sizeof(name) - 1;
                for (q = 0; q < c; q++)
                {
                    WCHAR w = mod->BaseDllName.Buffer[q];
                    name[q] = (w > 0 && w < 128) ? (char)w : '?';
                }
                name[c] = 0;
                rva = (ULONG_PTR)ra[r] - (ULONG_PTR)mod->DllBase;
            }
            MESSAGE( "macrunner-wow64-кто2677: n=%ld id=4 уровень=%u адрес=%p модуль=%s rva=%Ix\n",
                     (long)bk, r, ra[r], name, rva );
        }

        /* ★ ЛЕСТНИЦА 2678 — ЧТО ПЕРЕДАЁТСЯ.
         * 2677 закрыла направление «дело в зовущем»: у больного вызова трасса та же, что у
         * 47 здоровых, 48 из 48 с одного адреса. Значит различитель — в содержимом.
         * Разметку `args` не угадываю (её знает wow64win, и ошибка в поле увела бы в сторону):
         * печатаю СЫРЫЕ слова целиком, `len` за прогон равен 44, то есть 11 слов.
         * Сравнение больного с 47 здоровыми делается потом по журналу, а не гипотезой. */
        /* ★ ЛЕСТНИЦА 2680 — ХОЗЯЙСКАЯ ТРАССА ПРАВИЛЬНЫМ СРЕДСТВОМ.
         * 2679 нашла различитель: у 47 из 48 обратных вызовов гость стоит в переходнике
         * системного вызова (`сохр_eip=00270000`), у одного — в коде user32 за `call [eax]`,
         * и следом отказ. Остался вопрос ПОЧЕМУ доставка приходит вне переходника, а ответ на
         * него — в хозяйском стеке выше `KeUserModeCallback`.
         * В 2677 я лезла туда `__builtin_return_address(2..3)` и УБИЛА прогон (умирал на 20-й
         * секунде вместо 57,7). Здесь `RtlCaptureStackBackTrace` — она для этого и сделана.
         * Уровни 0-1 из 2677 оставлены рядом НЕТРОНУТЫМИ: если захват вернёт ноль кадров,
         * прежние — доказанные — числа никуда не денутся, и «прибор молчит» не будет
         * неотличимо от «явления нет». */
        {
            void *fr[10];
            USHORT got = RtlCaptureStackBackTrace( 0, 10, fr, NULL );
            USHORT q;

            MESSAGE( "macrunner-wow64-стек2680: n=%ld id=4 кадров=%u\n", (long)bk, got );
            for (q = 0; q < got; q++)
            {
                LDR_DATA_TABLE_ENTRY *mod = NULL;
                char nm[40] = "(нет)";
                ULONG_PTR rva = 0;

                if (!LdrFindEntryForAddress( fr[q], &mod ) && mod)
                {
                    unsigned c = mod->BaseDllName.Length / sizeof(WCHAR), z;

                    if (c > sizeof(nm) - 1) c = sizeof(nm) - 1;
                    for (z = 0; z < c; z++)
                    {
                        WCHAR wc = mod->BaseDllName.Buffer[z];
                        nm[z] = (wc > 0 && wc < 128) ? (char)wc : '?';
                    }
                    nm[c] = 0;
                    rva = (ULONG_PTR)fr[q] - (ULONG_PTR)mod->DllBase;
                }
                MESSAGE( "macrunner-wow64-стек2680: n=%ld кадр=%u адрес=%p модуль=%s rva=%Ix\n",
                         (long)bk, q, fr[q], nm, rva );
            }
        }

        {
            /* ★ ПОПРАВКА 2678: было `sprintf` — прогон умирал `Killed: 9` на 0,23 с, ещё на
             * wineboot. Модуль собран с `-nodefaultlibs`, и тянуть сюда libc нельзя.
             * Складываем строку вручную, шестнадцатеричными полубайтами. */
            MESSAGE( "macrunner-wow64-что2678: n=%ld id=4 len=%lu args=%p memory=NOT_ENABLED\n",
                     (long)bk, len, args );
        }
    }

    /* cf. 32-bit KeUserModeCallback */
    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        {
            /* stack layout when calling 32-bit KiUserCallbackDispatcher */
            struct callback_stack_layout32
            {
                ULONG             eip;           /* 000 */
                ULONG             id;            /* 004 */
                ULONG             args;          /* 008 */
                ULONG             len;           /* 00c */
                ULONG             unk[2];        /* 010 */
                ULONG             esp;           /* 018 */
                BYTE              args_data[0];  /* 01c */
            } *stack;
            I386_CONTEXT orig_ctx, ctx = { CONTEXT_I386_FULL };
            /* ★ ПОПРАВКА 2618: снимать «какой вызов в полёте» НА ВХОДЕ, а не на возврате.
             * Первая редакция читала табличку в момент возврата — и получала vyzov=5
             * (NtCallbackReturn) у ВСЕХ обратных вызовов, здоровых и больного одинаково:
             * к тому времени гость уже выдал свой NtCallbackReturn и затёр запись.
             * Прибор отвечал не на тот вопрос, который я задал. */
            ULONG svc_entry_num, svc_entry_seq = 0;

            C_ASSERT( sizeof(struct callback_stack_layout32) == 0x1c );

            svc_entry_num = macrunner_svc_current( &svc_entry_seq );
            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            /* ★★★ 26.08 — ВЛОЖЕННЫЙ ОБРАТНЫЙ ВЫЗОВ БЕРЁТ КОНТЕКСТ ВХОДА В СИСТЕМНЫЙ ВЫЗОВ.
             *
             * Текущий контекст годится, только если гость стоит на трамплине (eip 0x270000):
             * так входит 51 обратный вызов из 52 за прогон Diablo. Единственный, который
             * приходит ИЗНУТРИ обработки системного вызова, получает точку после прошлого
             * возврата — и восстановление такого контекста уводит гостя на чужой кадр.
             *
             * Признак вложенности — `live` слота: он больше нуля, пока системный вызов
             * не отдан обратно. Подменяем ТОЛЬКО контекст восстановления (`orig_ctx`);
             * `ctx`, по которому кладётся блок вызова на стек гостя, остаётся текущим —
             * блок обязан лечь там, где гость стоит сейчас, иначе затрём его живой кадр. */
            orig_ctx = ctx;
            /* ★★★★★ MacRunner 2026-08-28 — ПРИЗНАК ВХОДА: С ТРАМПЛИНА ИЛИ ИЗНУТРИ.
             *
             * Комментарий ниже называет верный критерий, но в деле он не
             * использовался: решение принималось по `cbret_mismatch`, то есть по
             * расхождению eip уже ПРИ ВОЗВРАТЕ. Это следствие, а не причина.
             *
             * Замер по журналам: все 9301 обратных вызова идут через трамплин
             * `0x00270000`. Вход НЕ с трамплина — и есть тот самый вложенный
             * случай (1 из 52), которому чужой кадр и достаётся.
             *
             * Запоминаем признак здесь, на входе, где он достоверен. */
            {
                const BOOL vhod_s_tramplina = (ctx.Eip == 0x00270000);
                frame.macrunner_cb_from_trampoline = vhod_s_tramplina;
                if (!vhod_s_tramplina)
                {
                    static LONG vlozh;
                    if (++vlozh <= 8)
                        MESSAGE( "macrunner-obrvyzov-vlozhennyj: n=%ld id=%lu vhod_eip=%08lx (не трамплин)\n",
                                 (long)vlozh, id, (unsigned long)ctx.Eip );
                }
            }
            {
                unsigned si = macrunner_svc_index();
                /* ★★★★ ПАКЕТ-2 (договор T1) — ПОДМЕНА КОНТЕКСТА ВОССТАНОВЛЕНИЯ.
                 * Вторая половина той же семьи: здесь `orig_ctx` заменяется контекстом
                 * ВХОДА в системный вызов. Для HyperBridge это лечение вложенного случая
                 * (1 из 52 у Diablo), для FEX — подмена его собственного сохранённого
                 * состояния. Проверка стоит ПЕРВОЙ намеренно: гейт `NESTED_CB_CTX` по
                 * умолчанию 0, и стой она после него, счётчик на руке fex остался бы
                 * нулевым — «погашено» стало бы неотличимо от «гейт и так закрыт». */
                if (!macrunner_wow64_paket2_mute( "T1-cb-entry" ) &&
                    macrunner_nested_cb_ctx() == 1 &&
                    macrunner_svc_slot[si].has_entry_ctx &&
                    macrunner_svc_slot[si].entry_ctx32.Eip != ctx.Eip)
                {
                    static LONG подмен;
                    orig_ctx = macrunner_svc_slot[si].entry_ctx32;
                    if (++подмен <= 8)
                        MESSAGE( "macrunner-вложенный-обрвызов: n=%ld id=%lu live=%lu "
                                 "текущий_eip=%08lx текущий_esp=%08lx -> вход_eip=%08lx вход_esp=%08lx\n",
                                 (long)подмен, id, (unsigned long)macrunner_svc_slot[si].live,
                                 (unsigned long)ctx.Eip, (unsigned long)ctx.Esp,
                                 (unsigned long)orig_ctx.Eip, (unsigned long)orig_ctx.Esp );
                }
            }

            stack = guest32_host_ptr( (ctx.Esp - offsetof(struct callback_stack_layout32,args_data[len])) & ~15 );

            /* ★★★★★★ MacRunner 2026-08-29 — БЛОК ОБЯЗАН ЛЕЧЬ В ОТОБРАЖЁННУЮ ПАМЯТЬ.
             *
             * Адрес блока считается от `ctx.Esp` и НЕ ПРОВЕРЯЛСЯ. Комментарий итерации 2812
             * прямо говорит: «ctx.Esp не отражает настоящую вершину гостевого стека». Если
             * он указывает у нижней границы области, блок уходит ЗА неё, и первая же запись
             * убивает поток SIGBUS'ом.
             *
             * Замер (Heroes III и UT99, 29.08): обе игры выводят ровно 3 кадра и замирают
             * НАВСЕГДА — 60 с и 180 с дают одинаковые 1075 и ~1305 вызовов гостя. Отказ:
             *   vhf-probe: addr=0x30036fff8 pc=wow64.dll+0x33948 site=bus
             *   vhf-probe-vm: vm_base=0x300280000 vm_size=f0000 prot=0  ← ПРАВ НЕТ
             * Один отказ за прогон — и больше ни одного вызова гостя до конца.
             *
             * Спрашиваем карту памяти ДВИЖКА, а не гадаем: она знает, что отображено гостю.
             * Не влезло — обратный вызов не доставляем (возвращаем STATUS_STACK_OVERFLOW,
             * ровно то, что Windows отдаёт в этом случае), но ПОТОК НЕ РОНЯЕМ: потеря одного
             * обратного вызова стоит кадра, потеря потока — всей игры. */
            {
                const ULONG blok = (ULONG)(ULONG_PTR)((const char *)stack - (const char *)guest32_host_ptr( 0 ));
                const ULONG nuzhno = (ULONG)offsetof( struct callback_stack_layout32, args_data[len] );
                MEMORY_BASIC_INFORMATION mbi;
                SIZE_T got = 0;
                NTSTATUS qs = NtQueryVirtualMemory( GetCurrentProcess(), stack,
                                                    MemoryBasicInformation, &mbi, sizeof(mbi), &got );
                const ULONG_PTR konec = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                const int godno = !qs
                        && (mbi.State == MEM_COMMIT)
                        && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))
                        && ((ULONG_PTR)stack + nuzhno <= konec);

                if (!godno)
                {
                    static LONG oo;
                    if (++oo <= 8)
                        MESSAGE( "macrunner-обрвызов-БЛОК-ВНЕ-ПАМЯТИ: n=%ld id=%lu len=%lu esp=%08lx "
                                 "блок=%08lx нужно=%lu | запрос=%08lx база=%p размер=%Ix права=%lx сост=%lx\n",
                                 (long)oo, id, len, (unsigned long)ctx.Esp, (unsigned long)blok,
                                 (unsigned long)nuzhno, (unsigned long)qs, mbi.BaseAddress,
                                 (ULONG_PTR)mbi.RegionSize, (unsigned long)mbi.Protect,
                                 (unsigned long)mbi.State );
                    NtCurrentTeb()->TlsSlots[WOW64_TLS_USERCALLBACKDATA] = frame.prev_frame;
                    NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] = frame.temp_list;
                    return STATUS_STACK_OVERFLOW;
                }
            }

            stack->eip  = ctx.Eip;
            stack->id   = id;
            stack->args = PtrToUlong( stack->args_data );
            stack->len  = len;
            stack->esp  = ctx.Esp;
            memcpy( stack->args_data, args, len );

            /* ★★★ MacRunner 23.08, лейн ЛЕСТНИЦА, итерация 2812 — КУДА ЛОЖИТСЯ БЛОК ОБРАТНОГО ВЫЗОВА.
             * 2810-2811 (два побайтово одинаковых прогона): живой кадр по гостевому 016bf998
             * — сохранённый ebp 016bf9b8 и обратный адрес 778f0eba внутрь opengl32 — заменяется
             * парой {1801005b, 0000000d} в промежутке [выход NtAllocateVirtualMemory ..
             * вход NtUserCallHwnd], после чего идут NtCallbackReturn и NtRaiseException.
             * Пара читается как аргументы NtUserCallHwnd: {дескриптор, код 13}. Если так, то
             * блок обратного вызова кладётся ПОВЕРХ живого кадра, потому что `ctx.Esp`, из
             * которого он отсчитывается, не отражает настоящую вершину гостевого стека.
             * Печатаю адреса, а не догадки: вершину, куда лёг блок, где начались данные
             * аргументов и первые два слова. Событие важнее потолка — при попадании в
             * 016bf998 печать безусловна (урок 2612: потолок морит редкое). */
            {
                static LONG cb_n, cb_hit;
                ULONG guest_stack = PtrToUlong( stack );
                ULONG guest_args  = PtrToUlong( stack->args_data );
                const ULONG *w = (const ULONG *)stack->args_data;
                LONG k = ++cb_n;
                int popal = (guest_args <= 0x016bf998 && 0x016bf998 < guest_args + len);

                if (k <= 12 || (popal && cb_hit++ < 24))
                    MESSAGE( "memory=NOT_ENABLED macrunner-обрвызов2812: n=%ld id=%lu len=%lu esp_до=%08lx "
                             "блок=%08lx данные=%08lx попал_в_016bf998=%d w0=%08lx w1=%08lx\n",
                             (long)k, (unsigned long)id, (unsigned long)len,
                             (unsigned long)orig_ctx.Esp, (unsigned long)guest_stack,
                             (unsigned long)guest_args, popal,
                             (unsigned long)(len >= 4 ? 0 : 0),
                             (unsigned long)(len >= 8 ? 0 : 0) );
            }
            ctx.Esp = PtrToUlong( stack );
            ctx.Eip = pLdrSystemDllInitBlock->pKiUserCallbackDispatcher;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );

            /* MacRunner 2026-08-13, лейн ЛЕСТНИЦА, итерация 827 — ДВА АДРЕСА ВОЗВРАТА.
             * Итерация 826 установила: после возврата из обратного вызова оконной процедуры
             * (id=4) гость исполняет по адресу ВНУТРИ кадра (`pc=кадр+0x16c`), 4096 раз без
             * продвижения, при `exec=НЕТ`. Разделить «неверный адрес поставили мы» и «гость
             * его испортил» можно только напечатав ОБА: тот, что сохранён для возврата, и тот,
             * с которого гость продолжил. Печать безусловная и ограничена по числу — гейт тут
             * бесполезен, событие редкое и решает исход. */
            static LONG cb_n;
            {
                LONG k = InterlockedIncrement( &cb_n );
                /* Итерация 829: печать СУЖЕНА. В 827 я снял потолок для id=4 — и прибор стал
                 * влиять на явление: 77 680 вызовов дали 155 тысяч строк, прогон замедлился и
                 * за 413 с не дошёл даже до создания окна (в d829 с тем же гейтом окно было).
                 * Оставляю начало и редкую выборку; РЕШАЮЩИЙ признак (несовпадение адресов)
                 * печатается безусловно в самом возврате — там его ничто не топит. */
                /* ★ МacRunner 2026-08-22, ЛЕСТНИЦА 2673 — ВКЛЮЧАЕТ СОБЫТИЕ, А НЕ СЧЁТ.
                 * 2613 оставила открытым ровно один вопрос: КТО продвигает контекст за
                 * `ret 0x10` — xtajit через BTCpuGetContext, завершение блока JIT или сам
                 * путь обратного вызова. Различить можно единственным числом: чему равен
                 * `сохр_eip` В МОМЕНТ ВХОДА в диспетчер. Если он уже 77xx15d9 (возврат из
                 * `call [eax]`), контекст пришёл устаревшим ИЗ BTCpuGetContext, и путь
                 * обратного вызова ни при чём; если 00270000 — портит что-то после.
                 * До сих пор этого числа не было: печать входа стоит под потолком k<=8, а
                 * больной вызов приходит 48-м. Потолок по счёту редкое событие морит голодом —
                 * мой же урок за 22.08. Признак больного известен из 2618 и именной:
                 * последний вошедший системный вызов = 0x18 (NtAllocateVirtualMemory),
                 * единственный такой за прогон из 28. По нему и включаю. */
                /* ★ 2679: печать входа открыта для ВСЕХ id=4. Аргументы трёх WM_NCHITTEST (n=43, 46, 48)
                 * оказались побайтно одинаковыми, а смертелен только последний — значит различитель
                 * в состоянии гостя, и сравнивать надо `сохр_eip`/`посл_вызов` у всех трёх.
                 * Раньше печатались только k<=8 и признак 0x18, поэтому у n=43 и n=46 записи нет.
                 * id=4 за прогон 48 штук — журнал это выдерживает (id=15 идут сотнями, их не трогаю). */
                if (k <= 8 || id == 4 || svc_entry_num == 0x18)
                {
                    /* ★ ЛЕСТНИЦА 2713 — ДВА СЛОВА ПО EBP, СНЯТЫЕ НА ВХОДЕ.
                     * 2712 свела арифметику отказа: esp при отказе = сохр_ebp + 8 (016bf9a0 =
                     * 016bf998 + 8), ebp = HDC 1801005b, eip = 0000000d. Это подпись
                     * ЗАВЕРШЁННОГО эпилога `leave; ret`: гость прочитал [ebp] и [ebp+4] и ушёл
                     * по тому, что там лежало. Значит вопрос не «кто снял 52 байта», а
                     * «кто записал {HDC, 0000000d} в кадр гостя».
                     * Зонд 2612 печатает 8 слов ОТ ESP, а нужные лежат по ebp = esp+0x2c —
                     * это слова 11 и 12, мимо ровно на три слова.
                     * Снимаю их на ВХОДЕ и на ВЫХОДЕ. Испорчены уже на входе -> писал не
                     * обратный вызов, и вся нить обратных вызовов не при чём. */
                    /* 0091: EBP may be a scalar HWND, not a readable frame pointer. */
                    MESSAGE( "macrunner-wow64-cb32: n=%ld id=%lu saved_eip=%08lx "
                             "saved_esp=%08lx saved_ebp=%08lx saved_eax=%08lx memory=NOT_ENABLED\n",
                             (long)k, id, (unsigned long)orig_ctx.Eip,
                             (unsigned long)orig_ctx.Esp, (unsigned long)orig_ctx.Ebp,
                             (unsigned long)orig_ctx.Eax );
                }
            }

            if (!setjmp( frame.jmpbuf ))
                cpu_simulate();
            else
            {
                MESSAGE( "macrunner-wow64: CallbackDispatcher resumed id=%lu status=%08lx ret_ptr=%p ret_len=%p\n",
                         id, frame.status, ret_ptr ? *ret_ptr : NULL, ret_len ? *ret_len : 0 );
                /* 2612: признак «этот возврат ТОТ САМЫЙ» выносим наружу — зонд ниже обязан
                 * сработать именно на нём, а не на первых попавшихся. */
                int cbret_mismatch = 0;
                ULONG cbret_cur_eax = 0, cbret_cur_esp = 0;
                ULONG cbret_cur_eip = 0;
                {
                    I386_CONTEXT cur = { CONTEXT_I386_FULL };
                    pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &cur );
                    static LONG bad_n;
                    cbret_mismatch = (cur.Eip != orig_ctx.Eip);
                    cbret_cur_eip = cur.Eip;
                    cbret_cur_eax = cur.Eax;   /* 2612: гость СРАЗУ делает test eax,eax */
                    cbret_cur_esp = cur.Esp;
                    if (cur.Eip != orig_ctx.Eip || cb_n <= 8 || !(cb_n % 5000))
                        MESSAGE( "macrunner-wow64-cb32: возврат id=%lu гость_eip=%08lx гость_esp=%08lx "
                                 "восстановим_eip=%08lx восстановим_esp=%08lx совпало=%d n_плохих=%ld\n",
                                 id, (unsigned long)cur.Eip, (unsigned long)cur.Esp,
                                 (unsigned long)orig_ctx.Eip, (unsigned long)orig_ctx.Esp,
                                 cur.Eip == orig_ctx.Eip,
                                 (long)(cur.Eip != orig_ctx.Eip ? InterlockedIncrement( &bad_n ) : bad_n) );
                }
                  /* ★★★ 26.08, режим 2 — НЕ ВОССТАНАВЛИВАТЬ ПРИ РАСХОЖДЕНИИ.
                   *
                   * Режим 1 (подменить orig_ctx контекстом входа в системный вызов) отказ
                   * на 0x0D убирает — но возвращает гостя в уже обработанный вызов, и
                   * прогон виснет на бюджете. Здесь пробуем не мешать вовсе: если гость к
                   * моменту возврата стоит не там, где вошёл, оставляем его на месте. */
                  /* ★★★★ ПАКЕТ-2 (договор T1) — ПАРА «СОХРАНИТЬ/ВОССТАНОВИТЬ» ПРИНАДЛЕЖИТ
                   * ВЛАДЕЛЬЦУ CPU, А НЕ НАШЕЙ ЭВРИСТИКЕ.
                   *
                   * Две ветви ниже при определённых условиях НЕ ЗОВУТ `pBTCpuSetContext`
                   * вовсе — то есть обратный вызов возвращается, а контекст гостя остаётся
                   * тем, каким его оставил обработчик. Для HyperBridge это лечение
                   * измеренного дефекта (мусор `eip=0x0000000D` со стека) и остаётся.
                   *
                   * У FEX договор штатный и полный: `F:WOW64/Module.cpp:560-567,685-690,
                   * 693-746,770-776` динамически выделяет BOP и держит СВОЙ контекст,
                   * сохраняя и восстанавливая его сам. Пропуск восстановления с нашей
                   * стороны для него — это пропущенный `BTCpuSetContext(saved)`, то есть
                   * ровно «ТИХИЙ: неверные EIP/ESP/регистры после callback» из аудита.
                   *
                   * ★ И отдельно про сам признак: `EIP == 0x270000` — АДРЕС ТРАМПЛИНА
                   * HyperBridge. Его постоянство не доказано даже для HB (аудит говорит это
                   * прямо), а у FEX трамплин ВЫДЕЛЯЕТСЯ ДИНАМИЧЕСКИ, значит совпадение с
                   * 0x270000 там либо никогда, либо случайно. Оба исхода одинаково негодны
                   * как основание решения.
                   *
                   * ГРАНИЦА: на руке hb условия ТОЖДЕСТВЕННЫ прежним (`mr_hb_cb` там TRUE),
                   * поэтому поведение HyperBridge побайтово прежнее. */
                  const BOOL mr_hb_cb = !macrunner_wow64_paket2_mute( "T1-cb-return" );

                  if (mr_hb_cb && macrunner_nested_cb_ctx() == 2 && cbret_mismatch)
                  {
                      static LONG пропущено;
                      if (++пропущено <= 8)
                          MESSAGE( "macrunner-obrvyzov-bez-vosstanovleniya: n=%ld id=%lu "
                                   "ostavlen_eip=%08lx vmesto_eip=%08lx\n",
                                   (long)пропущено, id,
                                   (unsigned long)cbret_cur_eip, (unsigned long)orig_ctx.Eip );
                  }
                  /* ★★★★★ MacRunner 2026-08-28 — РЕШАЕМ ПО ПРИЗНАКУ ВХОДА, А НЕ ПО СЛЕДСТВИЮ.
                   *
                   * Прежде решение принималось по `cbret_mismatch` — расхождению eip уже при
                   * ВОЗВРАТЕ. Это следствие: к тому моменту чужой кадр уже взят. Верный признак
                   * снимается на ВХОДЕ и лежит в кадре: пришёл ли гость с трамплина.
                   *
                   * Замер, объясняющий цену: `eip = 0x0000000D` — самое частое событие движка
                   * (318 случаев из 393 «не удалось получить код i386», 51 % прогонов). Это мусор
                   * со стека, взятый при восстановлении чужого кадра. Прибор `macrunner-cbret-svc`
                   * показывал рассогласование прямо: вошли на системном вызове 0x18 (счёт 3227),
                   * вернулись на 0x05 (счёт 3230), `sovpalo=0`.
                   *
                   * Правило теперь соответствует замеру (все 9301 возврата идут через трамплин):
                   * вошёл с трамплина — восстанавливаем сохранённый контекст; вошёл изнутри
                   * обработки системного вызова — не трогаем, гость уже на своём кадре.
                   *
                   * MACRUNNER_WOW64_NESTED_CB_CTX=3 возвращает прежнее поведение (всегда
                   * восстанавливать) для парного замера. */
                  else if (mr_hb_cb && macrunner_nested_cb_ctx() != 3 &&
                           !frame.macrunner_cb_from_trampoline)
                  {
                      static LONG ostavleno;
                      if (++ostavleno <= 8)
                          MESSAGE( "macrunner-obrvyzov-vlozhennyj-ne-vosstanavlivaem: n=%ld id=%lu "
                                   "tekushchij_eip=%08lx sohranennyj_eip=%08lx\n",
                                   (long)ostavleno, id,
                                   (unsigned long)cbret_cur_eip, (unsigned long)orig_ctx.Eip );
                  }
                  else
                      pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &orig_ctx );

                /* MacRunner, лейн ЛЕСТНИЦА, итерация 2612 — ВО ЧТО ГОСТЬ ВОЗВРАЩАЕТСЯ.
                 *
                 * Замер 2611: после снятия стены пиксельных форматов гость доходит до
                 * возврата из оконной процедуры (id=4 = NtUserCallWinProc) и через мгновение
                 * уходит исполнять по адресу 0x0000000d. При отказе ebp равен HDC
                 * (1801005b), а esp на 0x34 больше восстановленного — то есть кадр гостя
                 * разъехался. Чем именно — по журналу не видно: там печатались только
                 * адреса, а не то, что по ним лежит.
                 *
                 * Печатаем РОВНО это: слова стека от точки возврата и первые байты кода,
                 * в который гость сейчас войдёт. Зонд БЕЗУСЛОВНЫЙ (гейт превратил бы его
                 * в лотерею) и ограничен по числу: возврат id=4 за прогон случается
                 * единицами, а id=15 — десятками, поэтому потолок общий и низкий.
                 *
                 * Печать через MESSAGE: в ЭТОМ файле она доказана — строки cb32 из неё
                 * дошли до журнала прогона 2611 (правило проекта про ERR() к ней не
                 * относится, там канал ошибок wine, а не MESSAGE). */
                {
                    /* ★ ПОПРАВКА 2612 (мой же урок «маркер за условием — лотерея»).
                     * Первая редакция считала ОДНИМ счётчиком на все id с потолком 12.
                     * Замер: за прогон печатались 48 строк, ВСЕ id=15 (LoadImage) на 46-й
                     * секунде, а нужный id=4 (CallWinProc) приходит на 68-й — к тому времени
                     * потолок исчерпан, и зонд молчал в ЧЕТЫРЁХ прогонах подряд.
                     * Счётчик теперь СВОЙ на каждый id: редкое событие больше не голодает
                     * из-за частого. */
                    static LONG probe_n[32];
                    LONG k = (id < 32) ? InterlockedIncrement( &probe_n[id] ) : 999;

                    /* ★ ВТОРАЯ ПОПРАВКА 2612. Счётчик по id всё равно голодал: шесть первых
                     * id=4 на 69,73 с — ШТАТНЫЕ (возврат в переходник 00270000, ebp — адрес
                     * стека), а нужный, с несовпадением, приходит ПОЗЖЕ и в потолок не попал.
                     * Потолок по счёту вообще не годится как признак редкого события: печать
                     * теперь включается САМИМ событием. */
                    if (k <= 6 || cbret_mismatch)
                    {
                        MESSAGE( "macrunner-cbret: n=%ld id=%lu eip=%08lx esp=%08lx "
                                 "ebp=%08lx eax=%08lx memory=NOT_ENABLED\n",
                                 (long)k, id, (unsigned long)orig_ctx.Eip,
                                 (unsigned long)orig_ctx.Esp, (unsigned long)orig_ctx.Ebp,
                                 (unsigned long)orig_ctx.Eax );
                        {
                            ULONG d = 0, sv = macrunner_svc_current( &d );

                            /* ★ 26.08: печатаем ТЕКУЩИЙ eip. Признак несовпадения считается
                             * как (cur.Eip != orig_ctx.Eip), но в журнал шёл только orig —
                             * по нему казалось, будто «совпадает», хотя mismatch стоял. */
                            MESSAGE( "macrunner-cbret-tek: n=%ld id=%lu tek_eip=%08lx tek_esp=%08lx "
                                     "sohr_eip=%08lx sohr_esp=%08lx\n",
                                     (long)k, id, (unsigned long)cbret_cur_eip,
                                     (unsigned long)cbret_cur_esp,
                                     (unsigned long)orig_ctx.Eip, (unsigned long)orig_ctx.Esp );
                            MESSAGE( "macrunner-cbret-svc: n=%ld id=%lu vhod_vyzov=%08lx "
                                     "vhod_schet=%lu vozvrat_vyzov=%08lx schet=%lu sovpalo=%d\n",
                                     (long)k, id, (unsigned long)svc_entry_num,
                                     (unsigned long)svc_entry_seq, (unsigned long)sv,
                                     (unsigned long)d, !cbret_mismatch );
                        }
                    }
                }
            }
        }
        break;

    case IMAGE_FILE_MACHINE_ARMNT:
        {
            ARM_CONTEXT orig_ctx, ctx = { CONTEXT_ARM_FULL };
            void *args_data;

            pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );
            orig_ctx = ctx;

            args_data = ULongToPtr( (ctx.Sp - len) & ~15 );
            memcpy( args_data, args, len );

            ctx.R0 = id;
            ctx.R1 = PtrToUlong( args_data );
            ctx.R2 = len;
            ctx.Sp = PtrToUlong( args_data );
            ctx.Pc = pLdrSystemDllInitBlock->pKiUserCallbackDispatcher;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx );

            if (!setjmp( frame.jmpbuf ))
                cpu_simulate();
            else
                pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &orig_ctx );
        }
        break;
    }

    /* ★ ИТЕРАЦИЯ 64 — ВСЕ ИСТОЧНИКИ РАЗОМ, приём назван в комментарии 29.08 выше.
     *
     * Замер 63: `вход == сейчас == свежий` во всех 251 обращении -> longjmp значение НЕ
     * портит. Но 186 значений из 251 были `0x3001FAA64` — НЕ выровнено на страницу, а TEB
     * обязан быть выровнен. По коду NtCurrentTeb32() для i386 это `teb + WowTebOffset`,
     * значит испорчено одно из двух слагаемых. Печатаем ОБА, плюс pid/tid — без них не
     * различить два ПОТОКА от двух ПРОЦЕССОВ. ClientId берём из TEB: импорт не нужен. */
    {
        TEB *mr_teb = NtCurrentTeb();
        ULONG_PTR mr_t = (ULONG_PTR)mr_teb;
        LONG mr_off = mr_teb->WowTebOffset;
        MESSAGE( "macrunner-wow64-teb32: pid=%04x tid=%04x id=%lu teb32=%p teb=%p "
                 "wowoff=%08lx сумма=%p ровно_teb=%d ровно_off=%d ровно_teb32=%d расход=%d\n",
                 (unsigned)(ULONG_PTR)mr_teb->ClientId.UniqueProcess,
                 (unsigned)(ULONG_PTR)mr_teb->ClientId.UniqueThread,
                 id, teb32, mr_teb, (unsigned long)(ULONG)mr_off,
                 (void *)(mr_t + (ULONG_PTR)mr_off),
                 (int)((mr_t & 0xfff) == 0), (int)((mr_off & 0xfff) == 0),
                 (int)(((ULONG_PTR)teb32 & 0xfff) == 0),
                 (int)(teb32 != teb32_vhod) );
    }
    teb32->Tib.ExceptionList = teb_frame;
    NtCurrentTeb()->TlsSlots[WOW64_TLS_USERCALLBACKDATA] = frame.prev_frame;
    NtCurrentTeb()->TlsSlots[WOW64_TLS_TEMPLIST] = frame.temp_list;
    cpu->Flags = flags;
    MESSAGE( "macrunner-wow64: CallbackDispatcher leave id=%lu status=%08lx\n", id, frame.status );
    return frame.status;
}


/**********************************************************************
 *           Wow64LdrpInitialize  (wow64.@)
 */
void WINAPI Wow64LdrpInitialize( CONTEXT *context )
{
    static RTL_RUN_ONCE init_done;

    MESSAGE( "macrunner-wow64: Wow64LdrpInitialize enter context=%p\n", context );
    RtlRunOnceExecuteOnce( &init_done, process_init, NULL, NULL );
    MESSAGE( "macrunner-wow64: Wow64LdrpInitialize after process_init\n" );
    thread_init();
    MESSAGE( "macrunner-wow64: Wow64LdrpInitialize before cpu_simulate\n" );
    cpu_simulate();
}


/**********************************************************************
 *           Wow64PrepareForException  (wow64.@)
 */
#ifdef __x86_64__
__ASM_GLOBAL_FUNC( Wow64PrepareForException,
                   "sub $0x38,%rsp\n\t"
                   "mov %rcx,%r10\n\t"           /* rec */
                   "movw %cs,%ax\n\t"
                   "cmpw %ax,0x38(%rdx)\n\t"     /* context->SegCs */
                   "je 1f\n\t"                   /* already in 64-bit mode? */
                   /* copy arguments to 64-bit stack */
                   "mov %rsp,%rsi\n\t"
                   "movl $0x5c0,%ecx\n"          /* cf. KiUserExceptionDispatcher */
                   "movl 0x4d4(%rdx),%edi\n\t"   /* context_ex->All.Length */
                   "cmp %edi,%ecx\n\t"
                   "cmovl %edi,%ecx\n\t"         /* max( 0x5c0, context_ex->All.Length ) */
                   "add %rdx,%rcx\n\t"
                   "sub %rsi,%rcx\n\t"           /* stack size */
                   "sub %rcx,%r14\n\t"           /* reserve same size on 64-bit stack */
                   "and $~0x0f,%r14\n\t"
                   "mov %r14,%rdi\n\t"
                   "shr $3,%rcx\n\t"
                   "rep; movsq\n\t"
                   /* update arguments to point to the new stack */
                   "mov %r14,%rax\n\t"
                   "sub %rsp,%rax\n\t"
                   "add %rax,%r10\n\t"           /* rec */
                   "add %rax,%rdx\n\t"           /* context */
                   /* switch to 64-bit stack */
                   "mov %r14,%rsp\n"
                   /* build EXCEPTION_POINTERS structure and call BTCpuResetToConsistentState */
                   "1:\tlea 0x20(%rsp),%rcx\n\t" /* pointers */
                   "mov %r10,(%rcx)\n\t"         /* rec */
                   "mov %rdx,8(%rcx)\n\t"        /* context */
                   "mov " __ASM_NAME("pBTCpuResetToConsistentState") "(%rip),%rax\n\t"
                   "call *%rax\n\t"
                   "add $0x38,%rsp\n\t"
                   "ret" )
#else
static BOOL macrunner_wow64_i386_guest_exec_permitted( ULONG pc, void **host_ptr,
                                                       ULONG *state_ptr, ULONG *protect_ptr )
{
    MEMORY_BASIC_INFORMATION info;
    void *host;

    host = guest32_host_ptr( pc );
    if (host_ptr) *host_ptr = host;
    if (!host) return FALSE;
    if (NtQueryVirtualMemory( GetCurrentProcess(), host, MemoryBasicInformation,
                              &info, sizeof(info), NULL ))
        return FALSE;

    if (state_ptr) *state_ptr = info.State;
    if (protect_ptr) *protect_ptr = info.Protect;
    if (info.State != MEM_COMMIT) return FALSE;
    /* Pre-DEP: i386 guest has no hardware NX. Treat all committed non-NOACCESS
     * pages as executable so BTCpu can translate code from heap/stack/data
     * sections (common in Win9x/XP-era games like Diablo). */
    if ((info.Protect & 0xff) == PAGE_NOACCESS) return FALSE;
    return TRUE;
}

static BOOL macrunner_wow64_i386_mask_native_guest_seh( void **old_exception_list )
{
    struct seh_frame32
    {
        ULONG prev;
        ULONG handler;
    };
    TEB *teb = NtCurrentTeb();
    TEB32 *teb32 = NtCurrentTeb32();
    ULONG_PTR frame, guest32_base;
    const struct seh_frame32 *frame32;

    if (old_exception_list) *old_exception_list = NULL;
    if (native_machine != IMAGE_FILE_MACHINE_ARM64 || current_machine != IMAGE_FILE_MACHINE_I386)
        return FALSE;
    /* ★★★★ ПАКЕТ-2 (договор T10) — МАСКИРОВКА ГОСТЕВОГО SEH ПРИНАДЛЕЖИТ HyperBridge.
     * Функция подменяет `Tib.ExceptionList` на ~0 на время обработки, и делает это по
     * признаку «кадр лежит в ВЫСОКОЙ арене guest32» — то есть по нашей адресной модели,
     * которой у FEX нет. Гейт стоит ПОСЛЕ проверки пары машин: тогда счётчик считает
     * ровно i386-случаи, а не все исключения процесса. */
    if (macrunner_wow64_paket2_mute( "T10-mask-seh" )) return FALSE;
    if (!teb || !teb32 || !teb->Tib.ExceptionList ||
        teb->Tib.ExceptionList == (void *)~(ULONG_PTR)0)
        return FALSE;

    frame = (ULONG_PTR)teb->Tib.ExceptionList;
    guest32_base = (ULONG_PTR)teb32 & ~(ULONG_PTR)0xffffffff;
    if (!guest32_base || frame < guest32_base || frame > guest32_base + 0xffffffffu - sizeof(*frame32))
        return FALSE;

    frame32 = (const struct seh_frame32 *)frame;
    MESSAGE( "memory=NOT_ENABLED macrunner-wow64: mask native guest32 seh frame=%p handler=%08lx prev=%08lx\n",
             (void *)frame, 0, 0 );
    if (old_exception_list) *old_exception_list = teb->Tib.ExceptionList;
    teb->Tib.ExceptionList = (void *)~(ULONG_PTR)0;
    return TRUE;
}

static BOOL macrunner_wow64_i386_native_exec_fault( EXCEPTION_RECORD *rec, CONTEXT *context,
                                                    I386_CONTEXT *ctx )
{
    ULONG_PTR pc;
    void *host = NULL;
    ULONG state = 0, protect = 0;

    if (native_machine != IMAGE_FILE_MACHINE_ARM64 || current_machine != IMAGE_FILE_MACHINE_I386)
        return FALSE;
    if (!rec || rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        rec->NumberParameters < 2 || rec->ExceptionInformation[0] != EXCEPTION_EXECUTE_FAULT)
        return FALSE;
    /* ★★★★ ПАКЕТ-2 (договор T10) — ВОССТАНОВЛЕНИЕ ПОСЛЕ ОТКАЗА ИСПОЛНЕНИЯ.
     *
     * Ниже мы читаем гостевой PC, СТАВИМ гостю новый `Eip` и вызывающий немедленно уходит
     * в `cpu_simulate()` — то есть НОВАЯ СИМУЛЯЦИЯ НАЧИНАЕТСЯ ДО `BTCpuResetToConsistentState`.
     * Для FEX это прямое вторжение в его собственный порядок: `F:WOW64/Module.cpp:866-950`
     * восстанавливает и контекст отказа, и `EntryContext` сам, внутри Reset. Исход тихий —
     * отказ превращается в чужую симуляцию, дальше возможен круг или AV.
     *
     * ★ Это НЕ уже закрытый крючок N3 в unix-половине: тот в `dlls/ntdll/unix`, этот —
     * отдельный, в PE-половине WOW64, и до пакета 2 он оставался открытым.
     *
     * Гейт стоит ПОСЛЕ отсева по виду отказа: счётчик обязан считать именно отказы
     * исполнения, иначе число ничего не значит. */
    if (macrunner_wow64_paket2_mute( "T10-exec-fault" )) return FALSE;

    pc = rec->ExceptionInformation[1] ? rec->ExceptionInformation[1] : (ULONG_PTR)rec->ExceptionAddress;
    if (!pc || pc > 0xffffffffu || pc != (ULONG_PTR)rec->ExceptionAddress)
        return FALSE;

    if (!macrunner_wow64_i386_guest_exec_permitted( (ULONG)pc, &host, &state, &protect ))
    {
        MESSAGE( "macrunner-wow64: native guest32 execute skip nonexec pc=%08lx host=%p "
                 "state=%08lx protect=%08lx native_pc=%p native_sp=%p\n",
                 (ULONG)pc, host, state, protect,
                 context ? (void *)(ULONG_PTR)context->Pc : NULL,
                 context ? (void *)(ULONG_PTR)context->Sp : NULL );
        return FALSE;
    }

    ctx->ContextFlags = CONTEXT_I386_CONTROL;
    if (pBTCpuGetContext)
        pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, ctx );
    ctx->ContextFlags = CONTEXT_I386_CONTROL;
    ctx->Eip = (ULONG)pc;
    if (pBTCpuSetContext)
        pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, ctx );

    MESSAGE( "macrunner-wow64: native guest32 execute route pc=%08lx esp=%08lx "
             "native_pc=%p native_sp=%p\n",
             ctx->Eip, ctx->Esp, context ? (void *)(ULONG_PTR)context->Pc : NULL,
             context ? (void *)(ULONG_PTR)context->Sp : NULL );
    return TRUE;
}

void WINAPI Wow64PrepareForException( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    EXCEPTION_POINTERS ptrs = { rec, context };
    I386_CONTEXT ctx = { CONTEXT_I386_CONTROL };
    void *old_exception_list = NULL;
    BOOL masked_guest_seh = macrunner_wow64_i386_mask_native_guest_seh( &old_exception_list );

    if (macrunner_wow64_i386_native_exec_fault( rec, context, &ctx ))
        cpu_simulate();

    pBTCpuResetToConsistentState( &ptrs );
    if (masked_guest_seh)
        NtCurrentTeb()->Tib.ExceptionList = old_exception_list;
}
#endif


/**********************************************************************
 *           Wow64PassExceptionToGuest  (wow64.@)
 */
void WINAPI Wow64PassExceptionToGuest( EXCEPTION_POINTERS *ptrs )
{
    EXCEPTION_RECORD32 rec32;

    exception_record_64to32( &rec32, ptrs->ExceptionRecord );
    call_user_exception_dispatcher( &rec32, NULL, ptrs->ContextRecord );
}


/**********************************************************************
 *           Wow64ProcessPendingCrossProcessItems  (wow64.@)
 */
void WINAPI Wow64ProcessPendingCrossProcessItems(void)
{
    CROSS_PROCESS_WORK_LIST *list = (void *)wow64info->CrossProcessWorkList;
    CROSS_PROCESS_WORK_ENTRY *entry;
    BOOLEAN flush = FALSE;
    UINT next;

    if (!list) return;
    entry = RtlWow64PopAllCrossProcessWorkFromWorkList( &list->work_list, &flush );

    if (flush)
    {
        if (pBTCpuFlushInstructionCacheHeavy) pBTCpuFlushInstructionCacheHeavy( NULL, 0 );
        while (entry)
        {
            next = entry->next;
            RtlWow64PushCrossProcessWorkOntoFreeList( &list->free_list, entry );
            entry = next ? CROSS_PROCESS_LIST_ENTRY( &list->work_list, next ) : NULL;
        }
        return;
    }

    while (entry)
    {
        switch (entry->id)
        {
        case CrossProcessPreVirtualAlloc:
        case CrossProcessPostVirtualAlloc:
            if (!pBTCpuNotifyMemoryAlloc) break;
            pBTCpuNotifyMemoryAlloc( (void *)entry->addr, entry->size, entry->args[0], entry->args[1],
                                     entry->id == CrossProcessPostVirtualAlloc, entry->args[2] );
            break;
        case CrossProcessPreVirtualFree:
        case CrossProcessPostVirtualFree:
            if (!pBTCpuNotifyMemoryFree) break;
            pBTCpuNotifyMemoryFree( (void *)entry->addr, entry->size, entry->args[0],
                                     entry->id == CrossProcessPostVirtualFree, entry->args[1] );
            break;
        case CrossProcessPreVirtualProtect:
        case CrossProcessPostVirtualProtect:
            if (!pBTCpuNotifyMemoryProtect) break;
            pBTCpuNotifyMemoryProtect( (void *)entry->addr, entry->size, entry->args[0],
                                       entry->id == CrossProcessPostVirtualProtect, entry->args[1] );
            break;
        case CrossProcessFlushCache:
            if (!pBTCpuFlushInstructionCache2) break;
            pBTCpuFlushInstructionCache2( (void *)entry->addr, entry->size );
            break;
        case CrossProcessFlushCacheHeavy:
            if (!pBTCpuFlushInstructionCacheHeavy) break;
            pBTCpuFlushInstructionCacheHeavy( (void *)entry->addr, entry->size );
            break;
        case CrossProcessMemoryWrite:
            if (!pBTCpuNotifyMemoryDirty) break;
            pBTCpuNotifyMemoryDirty( (void *)entry->addr, entry->size );
            break;
        }
        next = entry->next;
        RtlWow64PushCrossProcessWorkOntoFreeList( &list->free_list, entry );
        entry = next ? CROSS_PROCESS_LIST_ENTRY( &list->work_list, next ) : NULL;
    }
}


/**********************************************************************
 *           Wow64RaiseException  (wow64.@)
 */
NTSTATUS WINAPI Wow64RaiseException( int code, EXCEPTION_RECORD *rec )
{
    EXCEPTION_RECORD32 rec32;
    BOOL first_chance = TRUE;
    union
    {
        I386_CONTEXT i386;
        ARM_CONTEXT arm;
    } ctx32 = { 0 };

    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        EXCEPTION_RECORD int_rec = { 0 };

        ctx32.i386.ContextFlags = CONTEXT_I386_ALL;
        pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx32.i386 );
        if (code == -1) break;
        int_rec.ExceptionAddress = (void *)(ULONG_PTR)ctx32.i386.Eip;
        switch (code)
        {
        case 0x00:  /* division by zero */
            int_rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
            break;
        case 0x01:  /* single-step */
            ctx32.i386.EFlags &= ~0x100;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx32.i386 );
            int_rec.ExceptionCode = EXCEPTION_SINGLE_STEP;
            break;
        case 0x03:  /* breakpoint */
            int_rec.ExceptionCode = EXCEPTION_BREAKPOINT;
            int_rec.ExceptionAddress = (void *)(ULONG_PTR)(ctx32.i386.Eip - 1);
            int_rec.NumberParameters = 1;
            break;
        case 0x04:  /* overflow */
            int_rec.ExceptionCode = EXCEPTION_INT_OVERFLOW;
            break;
        case 0x05:  /* array bounds */
            int_rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
            break;
        case 0x06:  /* invalid opcode */
            int_rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
            break;
        case 0x09:   /* coprocessor segment overrun */
            int_rec.ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
            break;
        case 0x0c:  /* stack fault */
            int_rec.ExceptionCode = EXCEPTION_STACK_OVERFLOW;
            break;
        case 0x0d:  /* general protection fault */
            int_rec.ExceptionCode = EXCEPTION_PRIV_INSTRUCTION;
            break;
        case 0x29:  /* __fastfail */
            int_rec.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
            int_rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
            int_rec.NumberParameters = 1;
            int_rec.ExceptionInformation[0] = ctx32.i386.Ecx;
            first_chance = FALSE;
            break;
        case 0x2d:  /* debug service */
            ctx32.i386.Eip += 3;
            pBTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx32.i386 );
            int_rec.ExceptionCode    = EXCEPTION_BREAKPOINT;
            int_rec.ExceptionAddress = (void *)(ULONG_PTR)ctx32.i386.Eip;
            int_rec.NumberParameters = 1;
            int_rec.ExceptionInformation[0] = ctx32.i386.Eax;
            break;
        default:
            int_rec.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
            int_rec.ExceptionAddress = (void *)(ULONG_PTR)ctx32.i386.Eip;
            int_rec.NumberParameters = 2;
            int_rec.ExceptionInformation[1] = 0xffffffff;
            break;
        }
        *rec = int_rec;
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
        ctx32.arm.ContextFlags = CONTEXT_ARM_ALL;
        pBTCpuGetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &ctx32.arm );
        break;
    }

    exception_record_64to32( &rec32, rec );
    raise_exception( &rec32, &ctx32, first_chance, rec );

    return STATUS_SUCCESS;
}
