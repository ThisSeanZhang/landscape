#ifndef __LANDSCAPE_LOG_H__
#define __LANDSCAPE_LOG_H__
#include <bpf/bpf_helpers.h>

#ifndef BPF_LOG_TOPIC
#define BPF_LOG_TOPIC "default"
#endif

// Prefix each message with "[ls] <topic> : ". BPF_LOG_TOPIC must be a string
// literal; it is concatenated into the format at compile time rather than
// passed as a %s argument, so it does not consume one of bpf_printk()'s
// argument slots (format-only calls stay on the lightweight
// bpf_trace_printk path).
#define ld_bpf_log(fmt, args...) bpf_printk("[ls] " BPF_LOG_TOPIC " : " fmt, ##args)

#endif  // __LANDSCAPE_LOG_H__
