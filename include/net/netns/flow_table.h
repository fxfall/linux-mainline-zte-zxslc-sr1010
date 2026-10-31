/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_FLOW_TABLE_H
#define __NETNS_FLOW_TABLE_H

#include <linux/mutex.h>

struct nf_flow_table_stat {
	unsigned int count_wq_add;
	unsigned int count_wq_del;
	unsigned int count_wq_stats;
};

struct nf_flow_clients;

struct netns_ft {
	struct nf_flow_table_stat __percpu *stat;
#ifdef CONFIG_NF_FLOW_TABLE_CLIENT_STATS
	struct nf_flow_clients *clients;
	struct mutex clients_sample_lock;
	u64 clients_sampled_ms;
	u64 clients_sequence;
	u64 clients_elapsed_ms;
	u32 clients_errors;
#endif
};
#endif
