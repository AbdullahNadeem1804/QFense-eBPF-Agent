#include <uapi/linux/ptrace.h>

struct sockaddr_in_min {
    short            sin_family;
    unsigned short   sin_port;
    struct { unsigned int s_addr; } sin_addr;
    char             sin_zero[8];
};

// Strictly aligned 136-byte structure to prevent Python ctypes memory corruption
struct crypto_event_t {
    u64 cgroup_id;             // 8 bytes
    u32 pid;                   // 4 bytes
    u32 bit_length;            // 4 bytes
    u32 daddr;                 // 4 bytes
    u16 dport;                 // 2 bytes
    u8 is_network_event;       // 1 byte
    u8 _pad;                   // 1 byte (Explicit padding)
    char comm[16];             // 16 bytes
    char algo_name[32];        // 32 bytes
    char cipher_suite[64];     // 64 bytes
};

struct algo_t {
    char name[32];
    u32 bits;
};

BPF_PERF_OUTPUT(qfense_events);
BPF_HASH(crypto_tracked_pids, u32, struct algo_t);

// UPROBE 1: Catch algorithm name (e.g., RSA, ML-KEM)
int probe_evp_pkey_new(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct algo_t algo = {};
    const char *name_ptr = (const char *)PT_REGS_PARM2(ctx);
    if (name_ptr) {
        bpf_probe_read_user_str(&algo.name, sizeof(algo.name), name_ptr);
    }
    crypto_tracked_pids.update(&pid, &algo);

    struct crypto_event_t evt = {};
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = pid;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.algo_name, algo.name, sizeof(algo.name));
    evt.is_network_event = 0;
    qfense_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// UPROBE 2: Catch exact key bit-lengths via internal control calls
int probe_evp_pkey_ctx_ctrl(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int cmd = (int)PT_REGS_PARM4(ctx); // 4th argument: cmd
    
    // OpenSSL internal macro definition for EVP_PKEY_CTRL_RSA_KEYGEN_BITS is 4099
    if (cmd == 4099) {
        int bits = (int)PT_REGS_PARM5(ctx); // 5th argument: p1 (bit size)
        struct algo_t *algo_ptr = crypto_tracked_pids.lookup(&pid);
        
        if (algo_ptr != NULL) {
            algo_ptr->bits = bits; // Save to Hash Map for network tracker
            
            struct crypto_event_t evt = {};
            evt.cgroup_id = bpf_get_current_cgroup_id();
            evt.pid = pid;
            evt.bit_length = bits;
            bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
            __builtin_memcpy(evt.algo_name, algo_ptr->name, sizeof(evt.algo_name));
            evt.is_network_event = 0;
            qfense_events.perf_submit(ctx, &evt, sizeof(evt));
        }
    }
    return 0;
}

// UPROBE 3: Catch TLS Cipher Suites requested by libssl.so
int probe_ssl_set_cipher_list(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct crypto_event_t evt = {};
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = pid;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    // The cipher suite string is the 2nd argument
    const char *cipher_ptr = (const char *)PT_REGS_PARM2(ctx);
    if (cipher_ptr) {
        bpf_probe_read_user_str(&evt.cipher_suite, sizeof(evt.cipher_suite), cipher_ptr);
    }
    
    evt.is_network_event = 2; // Flag '2' marks a TLS string event
    qfense_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// KPROBE: Correlate outbound network sockets
int kprobe__tcp_v4_connect(struct pt_regs *ctx, void *sk, void *uaddr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct algo_t *algo_ptr = crypto_tracked_pids.lookup(&pid);
    if (algo_ptr == NULL) return 0;

    struct sockaddr_in_min *usin = (struct sockaddr_in_min *)uaddr;
    struct crypto_event_t evt = {};
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = pid;
    evt.bit_length = algo_ptr->bits; // Carry bit length over to network alert
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.algo_name, algo_ptr->name, sizeof(evt.algo_name));
    
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &usin->sin_addr.s_addr);
    bpf_probe_read_kernel(&evt.dport, sizeof(evt.dport), &usin->sin_port);
    evt.dport = __builtin_bswap16(evt.dport); 
    evt.is_network_event = 1;

    qfense_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}