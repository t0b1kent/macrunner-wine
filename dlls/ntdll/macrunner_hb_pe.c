/*
 * MacRunner HyperBridge PE-side call helpers.
 *
 * Unix-side HyperBridge enters this PE export before calling complex ARM64
 * Wine exports.  That gives user32/ntdll a normal PE caller frame instead of
 * a Unix ntdll.so frame when it captures or unwinds context.
 */

#include <stdarg.h>
#include <stdint.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#define MACRUNNER_HB_IMPORT_ARG_MAX 20

struct macrunner_hb_pe_callback12_frame
{
    void *target;
    const uint64_t *args;
    uint64_t ret;
};

uint64_t __wine_macrunner_hb_pe_call12( void *target, const uint64_t *args )
{
    typedef uint64_t (*macrunner_hb_pe_fn20)( uint64_t, uint64_t, uint64_t, uint64_t,
                                              uint64_t, uint64_t, uint64_t, uint64_t,
                                              uint64_t, uint64_t, uint64_t, uint64_t,
                                              uint64_t, uint64_t, uint64_t, uint64_t,
                                              uint64_t, uint64_t, uint64_t, uint64_t );

    if (!target || !args) return 0;

    return ((macrunner_hb_pe_fn20)target)( args[0], args[1], args[2], args[3],
                                           args[4], args[5], args[6], args[7],
                                           args[8], args[9], args[10], args[11],
                                           args[12], args[13], args[14], args[15],
                                           args[16], args[17], args[18], args[19] );
}

void __wine_macrunner_hb_pe_callback12( struct macrunner_hb_pe_callback12_frame *frame )
{
    NTSTATUS status;

    if (frame) frame->ret = __wine_macrunner_hb_pe_call12( frame->target, frame->args );
    status = NtCallbackReturn( frame ? &frame->ret : NULL, frame ? sizeof(frame->ret) : 0, STATUS_SUCCESS );

    /*
     * call_user_mode_callback enters this function with a branch, not a call,
     * so returning normally would jump through an undefined LR (observed as
     * PC=0 during Phase F bring-up).  Surface a real callback-contract error
     * instead of hiding it behind a null-return crash.
     */
    RtlRaiseStatus( status ? status : STATUS_NO_CALLBACK_ACTIVE );
}
