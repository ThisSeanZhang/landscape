#ifndef __LD_MAP_ARENA_H__
#define __LD_MAP_ARENA_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Shared arena plumbing for every BPF_MAP_TYPE_ARENA declaration in this
 * tree (WAN trie, per-chain nat4 arenas, tests, benches). */

/* libbpf 1.7's bpf_helpers.h does not ship the __arena macro yet */
#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

/* The pinned vmlinux.h predates BPF_MAP_TYPE_ARENA, so use its raw value;
 * libbpf-sys 1.7 only needs the number when parsing the ELF .maps section.
 */
#ifndef BPF_MAP_TYPE_ARENA_V
#define BPF_MAP_TYPE_ARENA_V 33
#endif

/* Hand-emitted BPF_ADDR_SPACE_CAST instruction (off=1, imm=1 → the
 * verifier types the register PTR_TO_ARENA). The opaque volatile asm
 * boundary is the kernel selftests' own trick (BPF_ARENA_FORCE_ASM):
 * LLVM cannot fold or copy-propagate through it, which kills the
 * "re-materialize arena addressing without the addr_space_cast"
 * miscompile under register pressure (proven in bench_nat4_lookup.bpf.c
 * and arena_share.bpf.c). Required for every RUNTIME-indexed arena
 * address; fixed globals can be addressed directly. */
#define LD_ARENA_ADDR_SPACE_CAST 1
#define ARENA_CAST_KERN(var)                                                     \
    asm volatile(".byte 0xBF;     "                                              \
                 ".ifc %[reg], r0; .byte 0x00; .endif; "                         \
                 ".ifc %[reg], r1; .byte 0x11; .endif; "                         \
                 ".ifc %[reg], r2; .byte 0x22; .endif; "                         \
                 ".ifc %[reg], r3; .byte 0x33; .endif; "                         \
                 ".ifc %[reg], r4; .byte 0x44; .endif; "                         \
                 ".ifc %[reg], r5; .byte 0x55; .endif; "                         \
                 ".ifc %[reg], r6; .byte 0x66; .endif; "                         \
                 ".ifc %[reg], r7; .byte 0x77; .endif; "                         \
                 ".ifc %[reg], r8; .byte 0x88; .endif; "                         \
                 ".ifc %[reg], r9; .byte 0x99; .endif; "                         \
                 ".short %[off]; "                                               \
                 ".long %[as]"                                                   \
                 : [reg] "+r"(var)                                               \
                 : [off] "i"(LD_ARENA_ADDR_SPACE_CAST), [as] "i"(1))

#endif /* __LD_MAP_ARENA_H__ */
