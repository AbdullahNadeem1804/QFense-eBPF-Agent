#include <uapi/linux/ptrace.h>

// Define distinct event types so the dashboard knows exactly what happened
#define EVENT_CONTEXT_CREATED 0
#define EVENT_KEYGEN_ATTEMPT  1
#define EVENT_KEYGEN_SUCCESS  2
#define EVENT_KEYGEN_FAILURE  3

// 1. The payload sent to Python
struct crypto_event_t {
    u64 cgroup_id;
    u32 pid;
    u8  event_type;      
    char comm[16];
    char algo_name[32];
};

// 2. The FIX: We must use a struct for the Hash Map value, not a raw array
struct algo_t {
    char name[32];
};

BPF_PERF_OUTPUT(qfense_events);
BPF_HASH(tracked_pids, u32, struct algo_t); // Track PID -> Algorithm struct

// 3. Hook Context Creation
int probe_evp_context(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct algo_t algo = {};
    
    // OpenSSL 3.x passes algorithm name string as the 2nd parameter
    const char *name_ptr = (const char *)PT_REGS_PARM2(ctx);
    if (name_ptr) {
        bpf_probe_read_user_str(&algo.name, sizeof(algo.name), name_ptr);
        tracked_pids.update(&pid, &algo);
    }

    struct crypto_event_t evt = {};
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = pid;
    evt.event_type = EVENT_CONTEXT_CREATED;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.algo_name, algo.name, sizeof(evt.algo_name));

    qfense_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// 4. Hook Keygen Attempt (Entry)
int probe_evp_keygen_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct algo_t *algo_ptr = tracked_pids.lookup(&pid);
    if (algo_ptr == NULL) return 0; // Not a crypto process we are tracking

    struct crypto_event_t evt = {};
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = pid;
    evt.event_type = EVENT_KEYGEN_ATTEMPT;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.algo_name, algo_ptr->name, sizeof(evt.algo_name));

    qfense_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// 5. Hook Keygen Result (Return)
int probe_evp_keygen_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct algo_t *algo_ptr = tracked_pids.lookup(&pid);
    if (algo_ptr == NULL) return 0;

    // PT_REGS_RC gets the return value of the function
    long ret = PT_REGS_RC(ctx);

    struct crypto_event_t evt = {};
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = pid;
    // If return value is 1, it was a success. 0 means failure.
    evt.event_type = (ret == 1) ? EVENT_KEYGEN_SUCCESS : EVENT_KEYGEN_FAILURE;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.algo_name, algo_ptr->name, sizeof(evt.algo_name));

    qfense_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
