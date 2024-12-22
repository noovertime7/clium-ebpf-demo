//go:build ignore
#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "xdp_helper.h"

#define ARP_OP_REQUEST 1  // 请求
#define ARP_OP_REPLY   2  // 应答
#define ETH_ALEN 6

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 comm[80];
	unsigned char smac[ETH_ALEN];  // 来源mac
	u32 sip;                     // 来源ip
    u32 dip;                     // 目标地址
    u32 op;                     // ARP类型 譬如 1：请求 2：应答
};



struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("xdp")
int arp(struct xdp_md* ctx) {
	struct ethhdr* eth;  // 链路层
	  if (get_eth(ctx, &eth) < 0) {
        return XDP_PASS;
    };

	if (!is_arp(eth)) {
        return XDP_PASS;
    };

	struct arphdr* arp;

    if (get_arp(ctx, eth, &arp) < 0) {
        return XDP_PASS;
    };

	struct iphdr* iph;
    if (get_iphdr(ctx, eth, &iph) < 0) {
        return XDP_PASS;
    };

	struct event* data = NULL;
    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
        return XDP_PASS;
    }

 // ip层直接获取源ip
    // data->sip = bpf_ntohl(iph->saddr);

    // 解析arp包获取源ip
    data->sip = get_arp_sourceip(ctx, arp);
    data->dip = get_arp_targetip(ctx, arp);
    data->op = bpf_htons(arp->ar_op);

    bpf_probe_read_kernel(data->smac, ETH_ALEN, eth->h_source);
    bpf_ringbuf_submit(data, 0);
    return XDP_PASS;
}
