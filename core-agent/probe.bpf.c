#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "probe.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, char[32]);
    __uint(max_entries, 10240);
} tracked_pids SEC(".maps");

const volatile int target_pid = -1;

SEC("uprobe/context")
int probe_evp_context(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pid != -1 && pid != target_pid) return 0;

    char algo[32] = {};
    const char *name_ptr = (const char *)PT_REGS_PARM2(ctx);
    if (name_ptr) {
        bpf_probe_read_user_str(&algo, sizeof(algo), name_ptr);
        bpf_map_update_elem(&tracked_pids, &pid, &algo, BPF_ANY);
    }

    struct crypto_event_t *evt;
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->cgroup_id = bpf_get_current_cgroup_id();
    evt->pid = pid;
    evt->event_type = EVENT_CONTEXT_CREATED;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->algo_name, algo, sizeof(evt->algo_name));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("uprobe/keygen_entry")
int probe_evp_keygen_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pid != -1 && pid != target_pid) return 0;

    char *algo = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!algo) return 0;

    struct crypto_event_t *evt;
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->cgroup_id = bpf_get_current_cgroup_id();
    evt->pid = pid;
    evt->event_type = EVENT_KEYGEN_ATTEMPT;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->algo_name, algo, sizeof(evt->algo_name));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("uretprobe/keygen_return")
int probe_evp_keygen_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pid != -1 && pid != target_pid) return 0;

    char *algo = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!algo) return 0;

    long ret = PT_REGS_RC(ctx);

    struct crypto_event_t *evt;
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->cgroup_id = bpf_get_current_cgroup_id();
    evt->pid = pid;
    evt->event_type = (ret == 1) ? EVENT_KEYGEN_SUCCESS : EVENT_KEYGEN_FAILURE;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->algo_name, algo, sizeof(evt->algo_name));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
