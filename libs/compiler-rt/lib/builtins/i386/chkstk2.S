// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.

#include "../assembly.h"

// _chkstk routine
// This routine is windows specific
// http://msdn.microsoft.com/en-us/library/ms648426.aspx

// Notes from r227519
// MSVC produces a _chkstk function and _alloca, where _alloca is a normal
// function call that performs the stack probe and adjusts esp.  _chkstk only
// performs the probe and leaves esp unchanged.  GCC/clang i386 codegen emits
// calls to _alloca for dynamic stack allocations, so it is provided here as an
// alias of __chkstk.

#ifdef __i386__

.text
.balign 4
DEFINE_COMPILERRT_FUNCTION(_alloca) // _alloca is an alias of __chkstk
DEFINE_COMPILERRT_FUNCTION(__chkstk)
        push   %ecx
        cmp    $0x1000,%eax
        lea    8(%esp),%ecx     // esp before calling this routine -> ecx
        jb     1f
2:
        sub    $0x1000,%ecx
        test   %ecx,(%ecx)
        sub    $0x1000,%eax
        cmp    $0x1000,%eax
        ja     2b
1:
        sub    %eax,%ecx
        test   %ecx,(%ecx)

        lea    4(%esp),%eax     // load pointer to the return address into eax
        mov    %ecx,%esp        // install the new top of stack pointer into esp
        mov    -4(%eax),%ecx    // restore ecx
        push   (%eax)           // push return address onto the stack
        sub    %esp,%eax        // restore the original value in eax
        ret
END_COMPILERRT_FUNCTION(__chkstk)
END_COMPILERRT_FUNCTION(_alloca)

#endif // __i386__
