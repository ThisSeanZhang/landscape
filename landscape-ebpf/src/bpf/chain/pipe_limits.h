#ifndef __LD_PIPE_LIMITS_H_
#define __LD_PIPE_LIMITS_H_

// Capacity of the per-link chain root prog arrays (XDP + TC) and of the WAN
// ingress dispatch map. Every pinned instance must agree on these values:
// `reuse_pinned_map_or_recreate` probes compare `max_entries` and would
// otherwise recreate the pin, dropping the entries of live chains.
//
// Keep in sync with the Rust side (`maps::wan::WAN_DISPATCH_MAX_ENTRIES` and
// the prog-array creation in `chain/hub.rs`).

#define XDP_PIPE_MAX_ENTRIES 1024
#define WAN_DISPATCH_MAX_ENTRIES 1024

#endif /* __LD_PIPE_LIMITS_H_ */
