/* MacRunner native kernel page mode. LGPL-2.1-or-later; default off. */
#ifndef MACRUNNER_VM_PAGE4K_H
#define MACRUNNER_VM_PAGE4K_H
#if defined(__APPLE__) && defined(__aarch64__)
extern BOOL macrunner_vm_page4k_enabled(void) __attribute__((visibility("hidden")));
#endif
#endif
