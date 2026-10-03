/*
 *    Copyright (c) 2000 Lionel Ulmer
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
#ifndef __WINE_OPENGL32_UNIX_PRIVATE_H
#define __WINE_OPENGL32_UNIX_PRIVATE_H

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wingdi.h"
#include "ntgdi.h"

#include "wine/opengl_driver.h"
#include "unix_thunks.h"

struct registry_entry
{
    const char *name;      /* name of the extension */
    const char *extension; /* name of the GL/WGL extension */
    size_t offset;         /* offset in the opengl_funcs table */
};

extern const struct registry_entry extension_registry[];
extern const int extension_registry_size;

extern struct opengl_funcs null_opengl_funcs;

static inline const struct opengl_funcs *get_dc_funcs( HDC hdc )
{
    DWORD has_opengl;

    if (NtGdiGetDCDword( hdc, NtGdiHasOpenGL, &has_opengl ) && has_opengl)
        return __wine_get_opengl_driver( WINE_OPENGL_DRIVER_VERSION );

    RtlSetLastWin32Error( ERROR_INVALID_HANDLE );
    return &null_opengl_funcs;
}

#ifdef _WIN64

/* MacRunner, лейн ЛЕСТНИЦА, итерация 2610 — ТОТ ЖЕ КЛАСС, ДВА НЕПЕРЕВЕДЁННЫХ МЕСТА.
 * Здесь ГОСТЕВЫЕ и сам массив, и каждый его элемент: `address` приходит прямо из полей
 * wow64-структур (`params->offsets`, `params->sizes`, `params->indices` — 10 точек вызова
 * в сгенерированном unix_thunks.c), а элементы — гостевые 32-битные указатели.
 * Прежний код разыменовывал `address` как хостовый и складывал элементы через `ULongToPtr`.
 * ★ ГРАНИЦА ЗАМЕРА: этот путь на Diablo НЕ наблюдался (её ddraw->wined3d не зовёт
 * multi-draw-indirect). Правка сделана по КЛАССУ, а не по замеру, и это сказано вслух. */
static inline void *macrunner_guest32_host_ptr( ULONG addr );
static inline void *copy_wow64_ptr32s( UINT_PTR address, ULONG count )
{
    ULONG *ptrs = macrunner_guest32_host_ptr( (ULONG)address );
    void **tmp;

    if (!ptrs || !(tmp = calloc( count, sizeof(*tmp) ))) return NULL;
    while (count--) tmp[count] = macrunner_guest32_host_ptr( ptrs[count] );
    return tmp;
}

/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 258 — НЕНУЛЕВАЯ БАЗА 32-БИТНОГО ГОСТЯ.
 * `ULongToPtr` здесь давал адрес в нижних 4 ГБ, где у нас ничего не отображено (macOS не даёт
 * `__PAGEZERO` меньше 4 ГБ), и первое же разыменование `teb32_ptr->WowTebOffset` валило
 * инициализацию: `warn:opengl:DllMain Failed to initialize thread, status 0xc0000005`, следом
 * `Initialization of L"opengl32.dll" failed` → падают `wined3d` и `ddraw` → игра показывает
 * диалог «Direct Draw Error». Тот же класс, что в `wow64win` (95 переводов),
 * `wow64/process.c` и `wow64_wine_dbg_write`.
 * Переводчик берём через `dlsym`: `opengl32.so` не линкуется с нашим `ntdll.so` напрямую. */
static inline void *macrunner_guest32_host_ptr( ULONG addr )
{
    static void *(*resolve)( ULONG_PTR );
    static int tried;

    if (!tried)
    {
        extern void *dlsym( void *, const char * );
        tried = 1;
        resolve = (void *(*)( ULONG_PTR ))dlsym( (void *)-2 /* RTLD_DEFAULT */,
                                                 "macrunner_hb_wow64_guest32_host_ptr" );
    }
    if (resolve)
    {
        void *host = resolve( addr );

        if (host) return host;
    }
    return ULongToPtr( addr );
}

static inline TEB *get_teb64( ULONG teb32 )
{
    TEB32 *teb32_ptr = macrunner_guest32_host_ptr( teb32 );
    /* MacRunner 2026-08-27, Diablo — ПРОВЕРКА ПЕРЕВОДА TEB.
     *
     * Два отказа из четырёх приходят отсюда: sig_symbol=wow64_thread_attach в
     * opengl32.so, а он делает teb->glTable = &null_opengl_funcs по адресу,
     * который вернула эта функция. Адреса отказов 0x57efff238 и 0x57efef238 —
     * уже с базой зеркала, то есть перевод сработал, но результат указывает на
     * невыделенную страницу (DFSC=0x07). Печатаем всё три величины: гостевой
     * TEB32, его хозяйский адрес и WowTebOffset. */
    {
        static int n;
        if (++n <= 4)
        {
            fprintf( stderr, "macrunner-gl-teb64: n=%d teb32=%08x host=%p offset=%d итог=%p\n",
                     n, (unsigned)teb32, (void *)teb32_ptr,
                     teb32_ptr ? (int)teb32_ptr->WowTebOffset : 0,
                     teb32_ptr ? (void *)((char *)teb32_ptr + teb32_ptr->WowTebOffset) : NULL );
            fflush( stderr );
        }
    }
    return (TEB *)((char *)teb32_ptr + teb32_ptr->WowTebOffset);
}

extern struct buffer *invalidate_buffer_name( TEB *teb, GLuint name );
extern struct buffer *invalidate_buffer_target( TEB *teb, GLenum target );
extern void free_buffer( const struct opengl_funcs *funcs, struct buffer *buffer );
extern NTSTATUS return_wow64_string( const void *str, PTR32 *wow64_str );

#endif

extern pthread_mutex_t wgl_lock;

extern NTSTATUS process_attach( void *args );
extern NTSTATUS thread_attach( void *args );
extern NTSTATUS process_detach( void *args );
extern NTSTATUS get_pixel_formats( void *args );
extern void set_context_attribute( TEB *teb, GLenum name, const void *value, size_t size );
extern void set_current_fbo( TEB *teb, GLenum target, GLuint framebuffer );
extern GLuint get_default_fbo( TEB *teb, GLenum target );
extern void push_default_fbo( TEB *teb );
extern void pop_default_fbo( TEB *teb );
extern void resolve_default_fbo( TEB *teb, BOOL read );

#endif /* __WINE_OPENGL32_UNIX_PRIVATE_H */
