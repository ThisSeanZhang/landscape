#ifndef __LANDSCAPE_LOG_H__
#define __LANDSCAPE_LOG_H__
#include <bpf/bpf_helpers.h>

#ifndef BPF_LOG_TOPIC
#define BPF_LOG_TOPIC "default"
#endif

#define ld_bpf_log(fmt, args...) bpf_printk("[ls] %s : " fmt, BPF_LOG_TOPIC, ##args)

#endif  // __LANDSCAPE_LOG_H__
