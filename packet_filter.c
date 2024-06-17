#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TCP_PORT 4040
#define PROCESS_NAME "myprocess"

struct key_t {
    u32 pid;
};

BPF_HASH(process_map, struct key_t, u32);

int trace_exec(struct pt_regs *ctx) {
    struct task_struct *task;
    struct key_t key = {};
    u32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (strncmp(comm, PROCESS_NAME, sizeof(PROCESS_NAME)) == 0) {
        key.pid = pid;
        process_map.update(&key, &pid);
    }

    return 0;
}

int trace_exit(struct pt_regs *ctx) {
    struct key_t key = {};
    u32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;

    key.pid = pid;
    process_map.delete(&key);

    return 0;
}

int packet_filter(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0, sizeof(*eth));
    if (!eth)
        return 0;

    struct iphdr *ip = bpf_hdr_pointer(skb, sizeof(*eth), sizeof(*ip));
    if (!ip)
        return 0;

    if (ip->protocol != IPPROTO_TCP)
        return 0;

    struct tcphdr *tcp = bpf_hdr_pointer(skb, sizeof(*eth) + sizeof(*ip), sizeof(*tcp));
    if (!tcp)
        return 0;

    struct sock *sk = skb->sk;
    if (!sk)
        return 0;

    u32 pid = sk->sk_socket->file->f_owner.pid;

    struct key_t key = {.pid = pid};
    u32 *value = process_map.lookup(&key);

    if (value && tcp->dest == bpf_htons(TCP_PORT)) {
        return -1;
    }

    return 0;
}
