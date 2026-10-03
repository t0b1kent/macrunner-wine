#ifndef MACRUNNER_NATIVE_PREFIX_POLICY_H
#define MACRUNNER_NATIVE_PREFIX_POLICY_H
#include <stdint.h>

/* Semantically reconstructed from the recorded signal_arm64.o.
 * The original header bytes are lost. Distribute a binary rebuilt from this
 * source; this header is not a byte-exact source recovery for Wine 1.0.6. */
static int macrunner_native_prefix_range( uintptr_t pc, uintptr_t begin, uintptr_t end )
{
    return begin < end && pc >= begin && pc < end && !(pc & 3);
}

static int macrunner_native_prefix_classify( uintptr_t pc, int fex, int arm64ec,
        uintptr_t syscall_begin, uintptr_t syscall_end, uintptr_t unix_begin, uintptr_t unix_end )
{
    if (!fex || !arm64ec) return FALSE;
    return macrunner_native_prefix_range( pc, syscall_begin, syscall_end ) ||
           macrunner_native_prefix_range( pc, unix_begin, unix_end );
}

static BOOL macrunner_native_prefix_context_unchanged( const CONTEXT *before, const CONTEXT *after )
{
    return before->Pc == after->Pc && before->Sp == after->Sp && before->Cpsr == after->Cpsr &&
           !memcmp( before->X, after->X, sizeof(before->X) ) &&
           !memcmp( before->V, after->V, sizeof(before->V) ) &&
           before->Fpcr == after->Fpcr && before->Fpsr == after->Fpsr;
}
#endif
