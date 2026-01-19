#ifndef __LANDSCAPE_LOG_H__
#define __LANDSCAPE_LOG_H__
#include <bpf/bpf_helpers.h>

enum bpf_log_level {
    BPF_LOG_LEVEL_NONE = 0,
    BPF_LOG_LEVEL_ERROR,
    BPF_LOG_LEVEL_WARN,
    BPF_LOG_LEVEL_INFO,
    BPF_LOG_LEVEL_DEBUG,
    BPF_LOG_LEVEL_TRACE,
    BPF_LOG_LEVEL_MAX = BPF_LOG_LEVEL_TRACE,
};

static const char *bpf_log_level_str[] = {"NONE ", "ERROR", "WARN ", "INFO ", "DEBUG", "TRACE"};

#ifndef BPF_LOG_LEVEL
#define BPF_LOG_LEVEL BPF_LOG_LEVEL_DEBUG
#endif

#ifndef BPF_LOG_TOPIC
#define BPF_LOG_TOPIC "default"
#endif

// https://docs.kernel.org/core-api/printk-formats.html
#define _bpf_vprintk_exists bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_trace_vprintk)

#define _bpf_log_logv(level, fmt, args...)                                                         \
    ({                                                                                             \
        if (BPF_LOG_LEVEL >= level) {                                                              \
            bpf_printk("[ls][%s] %s : " fmt, bpf_log_level_str[level], BPF_LOG_TOPIC, ##args);     \
        }                                                                                          \
    })

#define bpf_log_error(args...) _bpf_log_logv(BPF_LOG_LEVEL_ERROR, args)
#define bpf_log_warn(args...) _bpf_log_logv(BPF_LOG_LEVEL_WARN, args)
#define bpf_log_info(args...) _bpf_log_logv(BPF_LOG_LEVEL_INFO, args)
#define bpf_log_debug(args...) _bpf_log_logv(BPF_LOG_LEVEL_DEBUG, args)
#define bpf_log_trace(args...) _bpf_log_logv(BPF_LOG_LEVEL_TRACE, args)

#endif  // __LANDSCAPE_LOG_H__
