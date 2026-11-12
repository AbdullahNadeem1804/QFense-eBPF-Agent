#ifndef __PROBE_H
#define __PROBE_H

#define EVENT_CONTEXT_CREATED 0
#define EVENT_KEYGEN_ATTEMPT  1
#define EVENT_KEYGEN_SUCCESS  2
#define EVENT_KEYGEN_FAILURE  3

struct crypto_event_t {
    unsigned long long cgroup_id;
    unsigned int pid;
    unsigned char event_type;
    char comm[16];
    char algo_name[32];
};

#endif /* __PROBE_H */
