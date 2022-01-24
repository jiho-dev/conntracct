#ifndef __CT_EVENT_H__
#define __CT_EVENT_H__

// 12 * u64: 96 bytes
struct ct_event_s {
    u64 start;
    u64 stop;
    u64 ts;
    u64 cptr;
    u64 packets_orig;
    u64 bytes_orig;
    u64 packets_ret;
    u64 bytes_ret;
    u32 srcaddr;
    u32 dstaddr;
    u32 nataddr;
    u32 connmark;
    u32 netns;
    u16 srcport;
    u16 dstport;
    u16 natport;
    u16 zone;
    u8 proto;
    u8 event_type;
    u8 tcp_state;
    u8 padding[1];
};

enum ct_event_config {
    ConfigReady,
    ConfigCaptureAll,
    ConfigCoolDown, // 0: off, > 1: on
    ConfigMax,
};

enum ct_event_type {
    EventNone,
    EventAdd,
    EventUpdate,
    EventDelete,
};

enum ct_event_config_ratecurve {
    ConfigCurve0Age,
    ConfigCurve0Interval,
    ConfigCurve1Age,
    ConfigCurve1Interval,
    ConfigCurve2Age,
    ConfigCurve2Interval,
    ConfigCurveMax,
};

# define printk(fmt, ...)                           \
({                                                  \
    char ____fmt[] = fmt;                           \
    bpf_trace_printk(____fmt, sizeof(____fmt),      \
                 ##__VA_ARGS__);                    \
})

#ifdef _LINUX_3_10
// Compatibility: Linux-3.10.0 from CentOS 7.3
struct nf_conn_acct {
    struct nf_conn_counter counter[IP_CT_DIR_MAX];
};
#endif


#define LABEL_FLOWLOG 0x0000000000000001

#endif
