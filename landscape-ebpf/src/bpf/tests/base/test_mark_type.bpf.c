// Echo-decode skb->mark via the mark.h layout helpers. Rust-side tests
// (src/tests/mark_layout.rs) encode SocketMark values with landscape-common
// and assert the C decode through PROG_TEST_RUN — pinning the cross-language
// mark layout contract (Rust writes / eBPF reads).
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/mark.h"

char LICENSE[] SEC("license") = "GPL";

// Decode results are written into cb:
//   cb[0] = bits 0-15 (chain_id under the HostDirect layout)
//   cb[1] = bits 24-31 (MARK_TYPE_*)
SEC("tc/ingress")
int test_mark_type_decode(struct __sk_buff *skb) {
    u32 mark = skb_mark(skb);
    skb->cb[0] = get_host_direct_chain_id(mark);
    skb->cb[1] = get_mark_type(mark);
    return TC_ACT_OK;
}
