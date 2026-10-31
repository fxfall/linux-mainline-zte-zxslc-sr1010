// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/rhashtable.h>
#include <linux/netdevice.h>
#include <linux/tc_act/tc_csum.h>
#include <net/flow_offload.h>
#include <net/ip_tunnels.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#define NF_FLOW_RULE_ACTION_MAX	24
#define NF_FLOW_HW_RETRY_MAX_SHIFT 5

struct nf_flow_hw_result {
	int error;
	char reason[NF_FLOW_HW_REASON_LEN];
};

static struct workqueue_struct *nf_flow_offload_add_wq;
static struct workqueue_struct *nf_flow_offload_del_wq;
static struct workqueue_struct *nf_flow_offload_stats_wq;

struct flow_offload_work {
	struct list_head	list;
	enum flow_cls_command	cmd;
	struct nf_flowtable	*flowtable;
	struct flow_offload	*flow;
	struct work_struct	work;
};

#define NF_FLOW_DISSECTOR(__match, __type, __field)	\
	(__match)->dissector.offset[__type] =		\
		offsetof(struct nf_flow_key, __field)

static void nf_flow_rule_lwt_match(struct nf_flow_match *match,
				   struct ip_tunnel_info *tun_info)
{
	struct nf_flow_key *mask = &match->mask;
	struct nf_flow_key *key = &match->key;
	unsigned long long enc_keys;

	if (!tun_info || !(tun_info->mode & IP_TUNNEL_INFO_TX))
		return;

	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_ENC_CONTROL, enc_control);
	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_ENC_KEYID, enc_key_id);
	key->enc_key_id.keyid = tunnel_id_to_key32(tun_info->key.tun_id);
	mask->enc_key_id.keyid = 0xffffffff;
	enc_keys = BIT_ULL(FLOW_DISSECTOR_KEY_ENC_KEYID) |
		   BIT_ULL(FLOW_DISSECTOR_KEY_ENC_CONTROL);

	if (ip_tunnel_info_af(tun_info) == AF_INET) {
		NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS,
				  enc_ipv4);
		key->enc_ipv4.src = tun_info->key.u.ipv4.dst;
		key->enc_ipv4.dst = tun_info->key.u.ipv4.src;
		if (key->enc_ipv4.src)
			mask->enc_ipv4.src = 0xffffffff;
		if (key->enc_ipv4.dst)
			mask->enc_ipv4.dst = 0xffffffff;
		enc_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS);
		key->enc_control.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
	} else {
		memcpy(&key->enc_ipv6.src, &tun_info->key.u.ipv6.dst,
		       sizeof(struct in6_addr));
		memcpy(&key->enc_ipv6.dst, &tun_info->key.u.ipv6.src,
		       sizeof(struct in6_addr));
		if (memcmp(&key->enc_ipv6.src, &in6addr_any,
			   sizeof(struct in6_addr)))
			memset(&mask->enc_ipv6.src, 0xff,
			       sizeof(struct in6_addr));
		if (memcmp(&key->enc_ipv6.dst, &in6addr_any,
			   sizeof(struct in6_addr)))
			memset(&mask->enc_ipv6.dst, 0xff,
			       sizeof(struct in6_addr));
		enc_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS);
		key->enc_control.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
	}

	match->dissector.used_keys |= enc_keys;
}

static void nf_flow_rule_vlan_match(struct flow_dissector_key_vlan *key,
				    struct flow_dissector_key_vlan *mask,
				    u16 vlan_id, __be16 proto)
{
	key->vlan_id = vlan_id;
	mask->vlan_id = VLAN_VID_MASK;
	key->vlan_tpid = proto;
	mask->vlan_tpid = 0xffff;
}

static int nf_flow_rule_match(struct nf_flow_match *match,
			      const struct flow_offload_tuple *tuple,
			      struct dst_entry *other_dst)
{
	struct nf_flow_key *mask = &match->mask;
	struct nf_flow_key *key = &match->key;
	struct ip_tunnel_info *tun_info;
	bool vlan_encap = false;

	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_META, meta);
	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_CONTROL, control);
	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_BASIC, basic);
	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_IPV4_ADDRS, ipv4);
	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_IPV6_ADDRS, ipv6);
	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_TCP, tcp);
	NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_PORTS, tp);

	if (other_dst && other_dst->lwtstate) {
		tun_info = lwt_tun_info(other_dst->lwtstate);
		nf_flow_rule_lwt_match(match, tun_info);
	}

	if (tuple->xmit_type == FLOW_OFFLOAD_XMIT_TC)
		key->meta.ingress_ifindex = tuple->tc.iifidx;
	else
		key->meta.ingress_ifindex = tuple->iifidx;

	mask->meta.ingress_ifindex = 0xffffffff;

	if (tuple->encap_num > 0 && !(tuple->in_vlan_ingress & BIT(0)) &&
	    tuple->encap[0].proto == htons(ETH_P_8021Q)) {
		NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_VLAN, vlan);
		nf_flow_rule_vlan_match(&key->vlan, &mask->vlan,
					tuple->encap[0].id,
					tuple->encap[0].proto);
		vlan_encap = true;
	}

	if (tuple->encap_num > 1 && !(tuple->in_vlan_ingress & BIT(1)) &&
	    tuple->encap[1].proto == htons(ETH_P_8021Q)) {
		if (vlan_encap) {
			NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_CVLAN,
					  cvlan);
			nf_flow_rule_vlan_match(&key->cvlan, &mask->cvlan,
						tuple->encap[1].id,
						tuple->encap[1].proto);
		} else {
			NF_FLOW_DISSECTOR(match, FLOW_DISSECTOR_KEY_VLAN,
					  vlan);
			nf_flow_rule_vlan_match(&key->vlan, &mask->vlan,
						tuple->encap[1].id,
						tuple->encap[1].proto);
		}
	}

	switch (tuple->l3proto) {
	case AF_INET:
		key->control.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
		key->basic.n_proto = htons(ETH_P_IP);
		key->ipv4.src = tuple->src_v4.s_addr;
		mask->ipv4.src = 0xffffffff;
		key->ipv4.dst = tuple->dst_v4.s_addr;
		mask->ipv4.dst = 0xffffffff;
		break;
       case AF_INET6:
		key->control.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
		key->basic.n_proto = htons(ETH_P_IPV6);
		key->ipv6.src = tuple->src_v6;
		memset(&mask->ipv6.src, 0xff, sizeof(mask->ipv6.src));
		key->ipv6.dst = tuple->dst_v6;
		memset(&mask->ipv6.dst, 0xff, sizeof(mask->ipv6.dst));
		break;
	default:
		return -EOPNOTSUPP;
	}
	mask->control.addr_type = 0xffff;
	match->dissector.used_keys |= BIT_ULL(key->control.addr_type);
	mask->basic.n_proto = 0xffff;

	switch (tuple->l4proto) {
	case IPPROTO_TCP:
		key->tcp.flags = 0;
		mask->tcp.flags = cpu_to_be16(be32_to_cpu(TCP_FLAG_RST | TCP_FLAG_FIN) >> 16);
		match->dissector.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_TCP);
		break;
	case IPPROTO_UDP:
	case IPPROTO_GRE:
		break;
	default:
		return -EOPNOTSUPP;
	}

	key->basic.ip_proto = tuple->l4proto;
	mask->basic.ip_proto = 0xff;

	match->dissector.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_META) |
				      BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
				      BIT_ULL(FLOW_DISSECTOR_KEY_BASIC);

	switch (tuple->l4proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		key->tp.src = tuple->src_port;
		mask->tp.src = 0xffff;
		key->tp.dst = tuple->dst_port;
		mask->tp.dst = 0xffff;

		match->dissector.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_PORTS);
		break;
	}

	return 0;
}

static void flow_offload_mangle(struct flow_action_entry *entry,
				enum flow_action_mangle_base htype, u32 offset,
				const __be32 *value, const __be32 *mask)
{
	entry->id = FLOW_ACTION_MANGLE;
	entry->mangle.htype = htype;
	entry->mangle.offset = offset;
	memcpy(&entry->mangle.mask, mask, sizeof(u32));
	memcpy(&entry->mangle.val, value, sizeof(u32));
}

static inline struct flow_action_entry *
flow_action_entry_next(struct nf_flow_rule *flow_rule)
{
	int i;

	if (unlikely(flow_rule->rule->action.num_entries >= NF_FLOW_RULE_ACTION_MAX))
		return NULL;

	i = flow_rule->rule->action.num_entries++;

	return &flow_rule->rule->action.entries[i];
}

static int flow_offload_eth_src(struct net *net,
				const struct flow_offload *flow,
				enum flow_offload_tuple_dir dir,
				struct nf_flow_rule *flow_rule)
{
	struct flow_action_entry *entry0 = flow_action_entry_next(flow_rule);
	struct flow_action_entry *entry1 = flow_action_entry_next(flow_rule);
	const struct flow_offload_tuple *other_tuple, *this_tuple;
	struct net_device *dev = NULL;
	const unsigned char *addr;
	u32 mask, val;
	u16 val16;

	if (!entry0 || !entry1)
		return -E2BIG;

	this_tuple = &flow->tuplehash[dir].tuple;

	switch (this_tuple->xmit_type) {
	case FLOW_OFFLOAD_XMIT_DIRECT:
		addr = this_tuple->out.h_source;
		break;
	case FLOW_OFFLOAD_XMIT_NEIGH:
		other_tuple = &flow->tuplehash[!dir].tuple;
		dev = dev_get_by_index(net, other_tuple->iifidx);
		if (!dev)
			return -ENOENT;

		addr = dev->dev_addr;
		break;
	default:
		return -EOPNOTSUPP;
	}

	mask = ~0xffff0000;
	memcpy(&val16, addr, 2);
	val = val16 << 16;
	flow_offload_mangle(entry0, FLOW_ACT_MANGLE_HDR_TYPE_ETH, 4,
			    &val, &mask);

	mask = ~0xffffffff;
	memcpy(&val, addr + 2, 4);
	flow_offload_mangle(entry1, FLOW_ACT_MANGLE_HDR_TYPE_ETH, 8,
			    &val, &mask);

	dev_put(dev);

	return 0;
}

static int flow_offload_eth_dst(struct net *net,
				const struct flow_offload *flow,
				enum flow_offload_tuple_dir dir,
				struct nf_flow_rule *flow_rule)
{
	struct flow_action_entry *entry0 = flow_action_entry_next(flow_rule);
	struct flow_action_entry *entry1 = flow_action_entry_next(flow_rule);
	const struct flow_offload_tuple *other_tuple, *this_tuple;
	const struct dst_entry *dst_cache;
	unsigned char ha[ETH_ALEN];
	struct neighbour *n;
	const void *daddr;
	u32 mask, val;
	u8 nud_state;
	u16 val16;

	if (!entry0 || !entry1)
		return -E2BIG;

	this_tuple = &flow->tuplehash[dir].tuple;

	switch (this_tuple->xmit_type) {
	case FLOW_OFFLOAD_XMIT_DIRECT:
		ether_addr_copy(ha, this_tuple->out.h_dest);
		break;
	case FLOW_OFFLOAD_XMIT_NEIGH:
		other_tuple = &flow->tuplehash[!dir].tuple;
		daddr = &other_tuple->src_v4;
		dst_cache = this_tuple->dst_cache;
		n = dst_neigh_lookup(dst_cache, daddr);
		if (!n)
			return -ENOENT;

		read_lock_bh(&n->lock);
		nud_state = n->nud_state;
		ether_addr_copy(ha, n->ha);
		read_unlock_bh(&n->lock);
		neigh_release(n);

		if (!(nud_state & NUD_VALID))
			return -ENOENT;
		break;
	default:
		return -EOPNOTSUPP;
	}

	mask = ~0xffffffff;
	memcpy(&val, ha, 4);
	flow_offload_mangle(entry0, FLOW_ACT_MANGLE_HDR_TYPE_ETH, 0,
			    &val, &mask);

	mask = ~0x0000ffff;
	memcpy(&val16, ha + 4, 2);
	val = val16;
	flow_offload_mangle(entry1, FLOW_ACT_MANGLE_HDR_TYPE_ETH, 4,
			    &val, &mask);

	return 0;
}

static int flow_offload_ipv4_snat(struct net *net,
				  const struct flow_offload *flow,
				  enum flow_offload_tuple_dir dir,
				  struct nf_flow_rule *flow_rule)
{
	struct flow_action_entry *entry = flow_action_entry_next(flow_rule);
	u32 mask = ~htonl(0xffffffff);
	__be32 addr;
	u32 offset;

	if (!entry)
		return -E2BIG;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v4.s_addr;
		offset = offsetof(struct iphdr, saddr);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v4.s_addr;
		offset = offsetof(struct iphdr, daddr);
		break;
	default:
		return -EOPNOTSUPP;
	}

	flow_offload_mangle(entry, FLOW_ACT_MANGLE_HDR_TYPE_IP4, offset,
			    &addr, &mask);
	return 0;
}

static int flow_offload_ipv4_dnat(struct net *net,
				  const struct flow_offload *flow,
				  enum flow_offload_tuple_dir dir,
				  struct nf_flow_rule *flow_rule)
{
	struct flow_action_entry *entry = flow_action_entry_next(flow_rule);
	u32 mask = ~htonl(0xffffffff);
	__be32 addr;
	u32 offset;

	if (!entry)
		return -E2BIG;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr;
		offset = offsetof(struct iphdr, daddr);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v4.s_addr;
		offset = offsetof(struct iphdr, saddr);
		break;
	default:
		return -EOPNOTSUPP;
	}

	flow_offload_mangle(entry, FLOW_ACT_MANGLE_HDR_TYPE_IP4, offset,
			    &addr, &mask);
	return 0;
}

static int flow_offload_ipv6_mangle(struct nf_flow_rule *flow_rule,
				     unsigned int offset,
				     const __be32 *addr, const __be32 *mask)
{
	struct flow_action_entry *entry;
	int i;

	for (i = 0; i < sizeof(struct in6_addr) / sizeof(u32); i++) {
		entry = flow_action_entry_next(flow_rule);
		if (!entry)
			return -E2BIG;

		flow_offload_mangle(entry, FLOW_ACT_MANGLE_HDR_TYPE_IP6,
				    offset + i * sizeof(u32), &addr[i], mask);
	}

	return 0;
}

static int flow_offload_ipv6_snat(struct net *net,
				  const struct flow_offload *flow,
				  enum flow_offload_tuple_dir dir,
				  struct nf_flow_rule *flow_rule)
{
	u32 mask = ~htonl(0xffffffff);
	const __be32 *addr;
	u32 offset;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v6.s6_addr32;
		offset = offsetof(struct ipv6hdr, saddr);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v6.s6_addr32;
		offset = offsetof(struct ipv6hdr, daddr);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return flow_offload_ipv6_mangle(flow_rule, offset, addr, &mask);
}

static int flow_offload_ipv6_dnat(struct net *net,
				  const struct flow_offload *flow,
				  enum flow_offload_tuple_dir dir,
				  struct nf_flow_rule *flow_rule)
{
	u32 mask = ~htonl(0xffffffff);
	const __be32 *addr;
	u32 offset;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6.s6_addr32;
		offset = offsetof(struct ipv6hdr, daddr);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v6.s6_addr32;
		offset = offsetof(struct ipv6hdr, saddr);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return flow_offload_ipv6_mangle(flow_rule, offset, addr, &mask);
}

static int flow_offload_l4proto(const struct flow_offload *flow)
{
	u8 protonum = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.l4proto;
	u8 type = 0;

	switch (protonum) {
	case IPPROTO_TCP:
		type = FLOW_ACT_MANGLE_HDR_TYPE_TCP;
		break;
	case IPPROTO_UDP:
		type = FLOW_ACT_MANGLE_HDR_TYPE_UDP;
		break;
	default:
		break;
	}

	return type;
}

static int flow_offload_port_snat(struct net *net,
				  const struct flow_offload *flow,
				  enum flow_offload_tuple_dir dir,
				  struct nf_flow_rule *flow_rule)
{
	struct flow_action_entry *entry = flow_action_entry_next(flow_rule);
	u32 mask, port;
	u32 offset;

	if (!entry)
		return -E2BIG;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		port = ntohs(flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_port);
		offset = 0; /* offsetof(struct tcphdr, source); */
		port = htonl(port << 16);
		mask = ~htonl(0xffff0000);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		port = ntohs(flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_port);
		offset = 0; /* offsetof(struct tcphdr, dest); */
		port = htonl(port);
		mask = ~htonl(0xffff);
		break;
	default:
		return -EOPNOTSUPP;
	}

	flow_offload_mangle(entry, flow_offload_l4proto(flow), offset,
			    &port, &mask);
	return 0;
}

static int flow_offload_port_dnat(struct net *net,
				  const struct flow_offload *flow,
				  enum flow_offload_tuple_dir dir,
				  struct nf_flow_rule *flow_rule)
{
	struct flow_action_entry *entry = flow_action_entry_next(flow_rule);
	u32 mask, port;
	u32 offset;

	if (!entry)
		return -E2BIG;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		port = ntohs(flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_port);
		offset = 0; /* offsetof(struct tcphdr, dest); */
		port = htonl(port);
		mask = ~htonl(0xffff);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		port = ntohs(flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_port);
		offset = 0; /* offsetof(struct tcphdr, source); */
		port = htonl(port << 16);
		mask = ~htonl(0xffff0000);
		break;
	default:
		return -EOPNOTSUPP;
	}

	flow_offload_mangle(entry, flow_offload_l4proto(flow), offset,
			    &port, &mask);
	return 0;
}

static int flow_offload_ipv4_checksum(struct net *net,
				      const struct flow_offload *flow,
				      struct nf_flow_rule *flow_rule)
{
	u8 protonum = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.l4proto;
	struct flow_action_entry *entry = flow_action_entry_next(flow_rule);

	if (!entry)
		return -E2BIG;

	entry->id = FLOW_ACTION_CSUM;
	entry->csum_flags = TCA_CSUM_UPDATE_FLAG_IPV4HDR;

	switch (protonum) {
	case IPPROTO_TCP:
		entry->csum_flags |= TCA_CSUM_UPDATE_FLAG_TCP;
		break;
	case IPPROTO_UDP:
		entry->csum_flags |= TCA_CSUM_UPDATE_FLAG_UDP;
		break;
	}

	return 0;
}

static int flow_offload_redirect(struct net *net,
				 const struct flow_offload *flow,
				 enum flow_offload_tuple_dir dir,
				 struct nf_flow_rule *flow_rule)
{
	const struct flow_offload_tuple *this_tuple, *other_tuple;
	struct flow_action_entry *entry;
	struct net_device *dev;
	int ifindex;

	this_tuple = &flow->tuplehash[dir].tuple;
	switch (this_tuple->xmit_type) {
	case FLOW_OFFLOAD_XMIT_DIRECT:
		this_tuple = &flow->tuplehash[dir].tuple;
		ifindex = this_tuple->out.ifidx;
		break;
	case FLOW_OFFLOAD_XMIT_NEIGH:
		other_tuple = &flow->tuplehash[!dir].tuple;
		ifindex = other_tuple->iifidx;
		break;
	default:
		return -EOPNOTSUPP;
	}

	dev = dev_get_by_index(net, ifindex);
	if (!dev)
		return -ENODEV;

	entry = flow_action_entry_next(flow_rule);
	if (!entry) {
		dev_put(dev);
		return -E2BIG;
	}

	entry->id = FLOW_ACTION_REDIRECT;
	entry->dev = dev;

	return 0;
}

static int flow_offload_encap_tunnel(const struct flow_offload *flow,
				     enum flow_offload_tuple_dir dir,
				     struct nf_flow_rule *flow_rule)
{
	const struct flow_offload_tuple *this_tuple;
	struct flow_action_entry *entry;
	struct dst_entry *dst;

	this_tuple = &flow->tuplehash[dir].tuple;
	if (this_tuple->xmit_type == FLOW_OFFLOAD_XMIT_DIRECT)
		return 0;

	dst = this_tuple->dst_cache;
	if (dst && dst->lwtstate) {
		struct ip_tunnel_info *tun_info;

		tun_info = lwt_tun_info(dst->lwtstate);
		if (tun_info && (tun_info->mode & IP_TUNNEL_INFO_TX)) {
			entry = flow_action_entry_next(flow_rule);
			if (!entry)
				return -E2BIG;
			entry->id = FLOW_ACTION_TUNNEL_ENCAP;
			entry->tunnel = tun_info;
		}
	}

	return 0;
}

static int flow_offload_decap_tunnel(const struct flow_offload *flow,
				     enum flow_offload_tuple_dir dir,
				     struct nf_flow_rule *flow_rule)
{
	const struct flow_offload_tuple *other_tuple;
	struct flow_action_entry *entry;
	struct dst_entry *dst;

	other_tuple = &flow->tuplehash[!dir].tuple;
	if (other_tuple->xmit_type == FLOW_OFFLOAD_XMIT_DIRECT)
		return 0;

	dst = other_tuple->dst_cache;
	if (dst && dst->lwtstate) {
		struct ip_tunnel_info *tun_info;

		tun_info = lwt_tun_info(dst->lwtstate);
		if (tun_info && (tun_info->mode & IP_TUNNEL_INFO_TX)) {
			entry = flow_action_entry_next(flow_rule);
			if (!entry)
				return -E2BIG;
			entry->id = FLOW_ACTION_TUNNEL_DECAP;
		}
	}

	return 0;
}

static int
nf_flow_rule_route_common(struct net *net, const struct flow_offload *flow,
			  enum flow_offload_tuple_dir dir,
			  struct nf_flow_rule *flow_rule)
{
	const struct flow_offload_tuple *other_tuple;
	const struct flow_offload_tuple *tuple;
	int i;

	if (flow_offload_decap_tunnel(flow, dir, flow_rule) < 0 ||
	    flow_offload_encap_tunnel(flow, dir, flow_rule) < 0)
		return -1;

	if (flow_offload_eth_src(net, flow, dir, flow_rule) < 0 ||
	    flow_offload_eth_dst(net, flow, dir, flow_rule) < 0)
		return -1;

	tuple = &flow->tuplehash[dir].tuple;

	for (i = 0; i < tuple->encap_num; i++) {
		struct flow_action_entry *entry;

		if (tuple->in_vlan_ingress & BIT(i))
			continue;

		if (tuple->encap[i].proto == htons(ETH_P_8021Q)) {
			entry = flow_action_entry_next(flow_rule);
			if (!entry)
				return -1;
			entry->id = FLOW_ACTION_VLAN_POP;
		}
	}

	other_tuple = &flow->tuplehash[!dir].tuple;

	for (i = 0; i < other_tuple->encap_num; i++) {
		struct flow_action_entry *entry;

		if (other_tuple->in_vlan_ingress & BIT(i))
			continue;

		entry = flow_action_entry_next(flow_rule);
		if (!entry)
			return -1;

		switch (other_tuple->encap[i].proto) {
		case htons(ETH_P_PPP_SES):
			entry->id = FLOW_ACTION_PPPOE_PUSH;
			entry->pppoe.sid = other_tuple->encap[i].id;
			break;
		case htons(ETH_P_8021Q):
			entry->id = FLOW_ACTION_VLAN_PUSH;
			entry->vlan.vid = other_tuple->encap[i].id;
			entry->vlan.proto = other_tuple->encap[i].proto;
			break;
		}
	}

	return 0;
}

int nf_flow_rule_route_ipv4(struct net *net, struct flow_offload *flow,
			    enum flow_offload_tuple_dir dir,
			    struct nf_flow_rule *flow_rule)
{
	if (nf_flow_rule_route_common(net, flow, dir, flow_rule) < 0)
		return -1;

	if (test_bit(NF_FLOW_SNAT, &flow->flags)) {
		if (flow_offload_ipv4_snat(net, flow, dir, flow_rule) < 0 ||
		    flow_offload_port_snat(net, flow, dir, flow_rule) < 0)
			return -1;
	}
	if (test_bit(NF_FLOW_DNAT, &flow->flags)) {
		if (flow_offload_ipv4_dnat(net, flow, dir, flow_rule) < 0 ||
		    flow_offload_port_dnat(net, flow, dir, flow_rule) < 0)
			return -1;
	}
	if (test_bit(NF_FLOW_SNAT, &flow->flags) ||
	    test_bit(NF_FLOW_DNAT, &flow->flags))
		if (flow_offload_ipv4_checksum(net, flow, flow_rule) < 0)
			return -1;

	if (flow_offload_redirect(net, flow, dir, flow_rule) < 0)
		return -1;

	return 0;
}
EXPORT_SYMBOL_GPL(nf_flow_rule_route_ipv4);

int nf_flow_rule_route_ipv6(struct net *net, struct flow_offload *flow,
			    enum flow_offload_tuple_dir dir,
			    struct nf_flow_rule *flow_rule)
{
	if (nf_flow_rule_route_common(net, flow, dir, flow_rule) < 0)
		return -1;

	if (test_bit(NF_FLOW_SNAT, &flow->flags)) {
		if (flow_offload_ipv6_snat(net, flow, dir, flow_rule) < 0 ||
		    flow_offload_port_snat(net, flow, dir, flow_rule) < 0)
			return -1;
	}
	if (test_bit(NF_FLOW_DNAT, &flow->flags)) {
		if (flow_offload_ipv6_dnat(net, flow, dir, flow_rule) < 0 ||
		    flow_offload_port_dnat(net, flow, dir, flow_rule) < 0)
			return -1;
	}

	if (flow_offload_redirect(net, flow, dir, flow_rule) < 0)
		return -1;

	return 0;
}
EXPORT_SYMBOL_GPL(nf_flow_rule_route_ipv6);

static struct nf_flow_rule *
nf_flow_offload_rule_alloc(struct net *net,
			   const struct flow_offload_work *offload,
			   enum flow_offload_tuple_dir dir,
			   struct nf_flow_hw_result *result)
{
	const struct nf_flowtable *flowtable = offload->flowtable;
	const struct flow_offload_tuple *tuple, *other_tuple;
	struct flow_offload *flow = offload->flow;
	struct dst_entry *other_dst = NULL;
	struct nf_flow_rule *flow_rule;
	int err = -ENOMEM;

	strscpy(result->reason, "cannot allocate hardware rule", sizeof(result->reason));
	flow_rule = kzalloc_obj(*flow_rule);
	if (!flow_rule)
		goto err_flow;

	flow_rule->rule = flow_rule_alloc(NF_FLOW_RULE_ACTION_MAX);
	if (!flow_rule->rule)
		goto err_flow_rule;

	flow_rule->rule->match.dissector = &flow_rule->match.dissector;
	flow_rule->rule->match.mask = &flow_rule->match.mask;
	flow_rule->rule->match.key = &flow_rule->match.key;

	tuple = &flow->tuplehash[dir].tuple;
	other_tuple = &flow->tuplehash[!dir].tuple;
	if (other_tuple->xmit_type == FLOW_OFFLOAD_XMIT_NEIGH)
		other_dst = other_tuple->dst_cache;

	err = nf_flow_rule_match(&flow_rule->match, tuple, other_dst);
	if (err < 0) {
		strscpy(result->reason, "cannot construct hardware match",
			sizeof(result->reason));
		goto err_flow_match;
	}

	flow_rule->rule->action.num_entries = 0;
	err = flowtable->type->action(net, flow, dir, flow_rule);
	if (err < 0) {
		/* Some route builders return -1 for unresolved neighbour data. */
		if (err == -1)
			err = -EAGAIN;
		strscpy(result->reason, "cannot resolve hardware actions",
			sizeof(result->reason));
		goto err_flow_match;
	}

	return flow_rule;

err_flow_match:
	kfree(flow_rule->rule);
err_flow_rule:
	kfree(flow_rule);
err_flow:
	result->error = err;
	return ERR_PTR(err);
}

static void __nf_flow_offload_destroy(struct nf_flow_rule *flow_rule)
{
	struct flow_action_entry *entry;
	int i;

	for (i = 0; i < flow_rule->rule->action.num_entries; i++) {
		entry = &flow_rule->rule->action.entries[i];
		if (entry->id != FLOW_ACTION_REDIRECT)
			continue;

		dev_put(entry->dev);
	}
	kfree(flow_rule->rule);
	kfree(flow_rule);
}

#ifdef CONFIG_NF_FLOW_TABLE_CLIENT_STATS
static void nf_flow_stats_scope_get(const struct flow_stats_scope *scope)
{
	nf_flow_clients_scope_get(scope->owner);
	__module_get(THIS_MODULE);
}

static void nf_flow_stats_scope_put(const struct flow_stats_scope *scope)
{
	nf_flow_clients_scope_put(scope->owner);
	module_put(THIS_MODULE);
}

static void nf_flow_stats_scope_account(const struct flow_stats_scope *scope,
				      u64 packets, u64 bytes)
{
	struct net *net;
	int d;

	/* Aggregate endpoint bytes never enter an arbitrary Conntrack record. */
	nf_flow_clients_account_scope(scope->src, scope->dst, bytes);
	rcu_read_lock();
	net = nf_flow_clients_scope_net(scope->owner);
	if (!net)
		goto unlock;
	for (d = 0; d < 2; d++) {
		struct pcpu_sw_netstats *tstats;
		struct net_device *dev;
		u32 lower = scope->path[d * 2], upper = scope->path[d * 2 + 1];

		if (!upper || upper == lower)
			continue;
		dev = dev_get_by_index_rcu(net, upper);
		if (!dev || dev->pcpu_stat_type != NETDEV_PCPU_STAT_TSTATS)
			continue;
		local_bh_disable();
		tstats = this_cpu_ptr(dev->tstats);
		u64_stats_update_begin(&tstats->syncp);
		if (!d) {
			u64_stats_add(&tstats->tx_packets, packets);
			u64_stats_add(&tstats->tx_bytes, bytes);
		} else {
			u64_stats_add(&tstats->rx_packets, packets);
			u64_stats_add(&tstats->rx_bytes, bytes);
		}
		u64_stats_update_end(&tstats->syncp);
		local_bh_enable();
	}
unlock:
	rcu_read_unlock();
}
#endif

static void nf_flow_offload_init(struct flow_cls_offload *cls_flow,
				 __be16 proto, int priority,
				 enum flow_cls_command cmd,
				 const struct flow_offload_tuple *tuple,
				 struct netlink_ext_ack *extack)
{
	cls_flow->common.protocol = proto;
	cls_flow->common.prio = priority;
	cls_flow->common.extack = extack;
	cls_flow->command = cmd;
	cls_flow->cookie = (unsigned long)tuple;
}

static bool nf_flow_hw_dir_due(const struct nf_flow_hw_dir *hw)
{
	u8 state = READ_ONCE(hw->state);

	return state == NF_FLOW_HW_UNTRIED ||
	       (state == NF_FLOW_HW_RETRY &&
		nf_flow_timeout_delta(READ_ONCE(hw->retry_at)) <= 0);
}

static bool nf_flow_hw_add_needed(struct flow_offload *flow)
{
	u8 wanted = test_bit(NF_FLOW_HW_BIDIRECTIONAL, &flow->flags) ? 3 : 1;
	bool needed;

	if (READ_ONCE(flow->hw_mask) == wanted)
		return false;
	/* A lockless queue hint; the serialized worker checks it again. */
	needed = nf_flow_hw_dir_due(&flow->hw[FLOW_OFFLOAD_DIR_ORIGINAL]);
	if (test_bit(NF_FLOW_HW_BIDIRECTIONAL, &flow->flags))
		needed |= nf_flow_hw_dir_due(&flow->hw[FLOW_OFFLOAD_DIR_REPLY]);
	return needed;
}

static void nf_flow_hw_record(struct flow_offload *flow, int dir,
			      const struct nf_flow_hw_result *result,
			      bool add_attempt)
{
	struct nf_flow_hw_dir *hw = &flow->hw[dir];
	u32 delay;

	spin_lock_bh(&flow->hw_lock);
	if (add_attempt && hw->attempts != U32_MAX)
		hw->attempts++;
	if (add_attempt)
		hw->stats_error = 0;
	hw->error = result->error;
	strscpy(hw->reason, result->reason, sizeof(hw->reason));
	if (!result->error) {
		WRITE_ONCE(hw->state, NF_FLOW_HW_INSTALLED);
		hw->failures = 0;
		WRITE_ONCE(hw->retry_at, 0);
		hw->stats_error = 0;
	} else {
		hw->failures = min_t(u8, hw->failures + 1, NF_FLOW_HW_RETRY_MAX_SHIFT + 1);
		if (result->error == -EOPNOTSUPP) {
			/* Cached only until this flow is destroyed/re-admitted. */
			WRITE_ONCE(hw->state, NF_FLOW_HW_UNSUPPORTED);
			WRITE_ONCE(hw->retry_at, 0);
		} else {
			WRITE_ONCE(hw->state, NF_FLOW_HW_RETRY);
			delay = HZ << (hw->failures - 1);
			WRITE_ONCE(hw->retry_at, nf_flowtable_time_stamp + delay);
		}
	}
	if (hw->state == NF_FLOW_HW_INSTALLED)
		WRITE_ONCE(flow->hw_mask, flow->hw_mask | BIT(dir));
	else
		WRITE_ONCE(flow->hw_mask, flow->hw_mask & ~BIT(dir));
	spin_unlock_bh(&flow->hw_lock);
}

/* Called from offload workqueue context, never from the packet datapath. */
static void nf_flow_hw_sync(struct flow_offload *flow)
{
	u8 mask = 0;
	int dir;

	spin_lock_bh(&flow->hw_lock);
	for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++)
		if (flow->hw[dir].state == NF_FLOW_HW_INSTALLED)
			mask |= BIT(dir);
	WRITE_ONCE(flow->hw_mask, mask);
	spin_unlock_bh(&flow->hw_lock);
	/* Preserve the existing ABI: HW_OFFLOAD means at least one direction. */
	if (mask)
		set_bit(IPS_HW_OFFLOAD_BIT, &flow->ct->status);
	else
		clear_bit(IPS_HW_OFFLOAD_BIT, &flow->ct->status);
	nf_flow_clients_hw(flow, mask);
}

static const char *nf_flow_hw_error_message(int error)
{
	switch (error) {
	case -EOPNOTSUPP:
		return "hardware does not support this rule";
	case -ENOSPC:
		return "hardware resources exhausted";
	case -ENOMEM:
		return "hardware backend allocation failed";
	case -EAGAIN:
		return "hardware dependency not ready";
	case -EEXIST:
		return "conflicting hardware rule";
	case -ENETDOWN:
		return "hardware datapath not ready";
	case -ENOENT:
		return "hardware rule not found";
	default:
		return "hardware callback failed";
	}
}

static int nf_flow_offload_tuple(struct nf_flowtable *flowtable,
				 struct flow_offload *flow,
				 struct nf_flow_rule *flow_rule,
				 enum flow_offload_tuple_dir dir,
				 int priority, int cmd,
				 struct flow_stats *stats,
				 struct list_head *block_cb_list,
				 struct nf_flow_hw_result *result)
{
	struct flow_cls_offload cls_flow = {};
	struct netlink_ext_ack extack = {};
	struct flow_block_cb *block_cb;
	__be16 proto = ETH_P_ALL;
	struct nf_flow_hw_result failure = {
		.error = -ENODEV,
		.reason = "no hardware offload callback",
	};
	bool had_error = false;
	int err, i = 0;

	nf_flow_offload_init(&cls_flow, proto, priority, cmd,
			     &flow->tuplehash[dir].tuple, &extack);
	if (cmd == FLOW_CLS_REPLACE)
		cls_flow.rule = flow_rule->rule;
#ifdef CONFIG_NF_FLOW_TABLE_CLIENT_STATS
	/* Endpoint records live until netns teardown; drivers only compare tokens.
	 * Do not group different flowtables, endpoint directions or PPP devices.
	 */
	cls_flow.stats_scope.src = flow->client_ip[!dir] ?: flow->client[!dir];
	cls_flow.stats_scope.dst = flow->client_ip[dir] ?: flow->client[dir];
	if (cls_flow.stats_scope.src || cls_flow.stats_scope.dst) {
		int d;

		cls_flow.stats_scope.owner = nf_flow_clients_scope_owner(read_pnet(&flowtable->net));
		cls_flow.stats_scope.domain = flowtable;
		cls_flow.stats_scope.get = nf_flow_stats_scope_get;
		cls_flow.stats_scope.put = nf_flow_stats_scope_put;
		cls_flow.stats_scope.account = nf_flow_stats_scope_account;
		for (d = 0; d < FLOW_OFFLOAD_DIR_MAX; d++) {
			const struct flow_offload_tuple *t = &flow->tuplehash[d ^ dir].tuple;

			if (t->xmit_type == FLOW_OFFLOAD_XMIT_DIRECT) {
				cls_flow.stats_scope.path[d * 2] = t->out.ifidx;
				cls_flow.stats_scope.path[d * 2 + 1] = t->out.encap_ifidx;
			} else if (t->xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
				cls_flow.stats_scope.path[d * 2] = t->dst_cache->dev->ifindex;
			}
		}
	}
#endif

	down_read(&flowtable->flow_block_lock);
	list_for_each_entry(block_cb, block_cb_list, list) {
		/* Extack belongs to this invocation, not the preceding callback. */
		memset(&extack, 0, sizeof(extack));
		err = block_cb->cb(TC_SETUP_CLSFLOWER, &cls_flow,
				   block_cb->cb_priv);
		if (err < 0) {
			/*
			 * One transiently unavailable backend must not be hidden
			 * by another backend's permanent EOPNOTSUPP.
			 */
			if (!had_error ||
			    (failure.error == -EOPNOTSUPP && err != -EOPNOTSUPP)) {
				failure.error = err;
				strscpy(failure.reason,
					extack._msg ?: nf_flow_hw_error_message(err),
					sizeof(failure.reason));
			}
			had_error = true;
			continue;
		}

		i++;
	}
	up_read(&flowtable->flow_block_lock);

	if (stats)
		memcpy(stats, &cls_flow.stats, sizeof(*stats));

	if (result) {
		if (i)
			memset(result, 0, sizeof(*result));
		else
			*result = failure;
	}
	return i ?: failure.error;
}

static int flow_offload_tuple_add(struct flow_offload_work *offload,
				  struct nf_flow_rule *flow_rule,
				  enum flow_offload_tuple_dir dir,
				  struct nf_flow_hw_result *result,
				  struct flow_stats *stats)
{
	return nf_flow_offload_tuple(offload->flowtable, offload->flow,
				     flow_rule, dir,
				     offload->flowtable->priority,
				     FLOW_CLS_REPLACE, stats,
				     &offload->flowtable->flow_block.cb_list, result);
}

static int flow_offload_tuple_del(struct flow_offload_work *offload,
				  enum flow_offload_tuple_dir dir,
				  struct flow_stats *stats,
				  struct nf_flow_hw_result *result)
{
	return nf_flow_offload_tuple(offload->flowtable, offload->flow, NULL, dir,
			      offload->flowtable->priority,
			      FLOW_CLS_DESTROY, stats,
			      &offload->flowtable->flow_block.cb_list, result);
}

static void flow_offload_stats_account(struct flow_offload_work *offload,
				       int dir, const struct flow_stats *stats)
{
	if (!stats->pkts)
		return;
	if (offload->flowtable->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_add(offload->flow->ct, dir, stats->pkts, stats->bytes);
	nf_flow_clients_account(offload->flow, dir, stats->bytes, true);
	nf_flow_encap_tx_acct(offload->flow, dir, stats->pkts, stats->bytes);
	nf_flow_encap_rx_acct(offload->flow, dir, stats->pkts, stats->bytes);
}

static void flow_offload_work_add(struct flow_offload_work *offload)
{
	struct net *net = read_pnet(&offload->flowtable->net);
	struct flow_offload *flow = offload->flow;
	struct nf_flow_hw_result result;
	struct nf_flow_rule *rule;
	struct flow_stats stats;
	int dir, ret;

	if (test_bit(NF_FLOW_TEARDOWN, &flow->flags) ||
	    test_bit(NF_FLOW_CLOSING, &flow->flags) ||
	    test_bit(NF_FLOW_HW_DYING, &flow->flags))
		return;
	/* Existing software flows may retry HW admission; never oversubscribe.
	 * New over-limit candidates are already dropped synchronously by ADD.
	 */
	ret = nf_flow_clients_reserve(flow);
	if (ret == -ENOENT)
		return;
	if (ret) {
		memset(&result, 0, sizeof(result));
		result.error = ret;
		strscpy(result.reason, "client NPU connection limit reached",
			sizeof(result.reason));
		for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++)
			if (flow->hw[dir].state != NF_FLOW_HW_INSTALLED)
				nf_flow_hw_record(flow, dir, &result, true);
		return;
	}
	for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++) {
		if (dir == FLOW_OFFLOAD_DIR_REPLY &&
		    !test_bit(NF_FLOW_HW_BIDIRECTIONAL, &flow->flags))
			break;
		if (!nf_flow_hw_dir_due(&flow->hw[dir]))
			continue;
		memset(&result, 0, sizeof(result));
		rule = nf_flow_offload_rule_alloc(net, offload, dir, &result);
		if (!IS_ERR(rule)) {
			memset(&stats, 0, sizeof(stats));
			flow_offload_tuple_add(offload, rule, dir, &result, &stats);
			flow_offload_stats_account(offload, dir, &stats);
			__nf_flow_offload_destroy(rule);
		}
		nf_flow_hw_record(flow, dir, &result, true);
	}
	nf_flow_hw_sync(flow);
}

static int flow_offload_tuple_stats(struct flow_offload_work *offload,
				     enum flow_offload_tuple_dir dir,
				     struct flow_stats *stats,
				     struct nf_flow_hw_result *result)
{
	return nf_flow_offload_tuple(offload->flowtable, offload->flow, NULL, dir,
				    offload->flowtable->priority,
				    FLOW_CLS_STATS, stats,
				    &offload->flowtable->flow_block.cb_list, result);
}

static void flow_offload_work_stats(struct flow_offload_work *offload)
{
	struct flow_stats stats[FLOW_OFFLOAD_DIR_MAX] = {};
	struct flow_offload *flow = offload->flow;
	struct nf_flow_hw_result result;
	int dir;
	int ret;
	u64 lastused;

	for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++) {
		/* A software-only direction is not a missing hardware counter. */
		if (!(READ_ONCE(flow->hw_mask) & BIT(dir)))
			continue;
		ret = flow_offload_tuple_stats(offload, dir, &stats[dir], &result);
		spin_lock_bh(&flow->hw_lock);
		flow->hw[dir].stats_error = ret < 0 ? ret : 0;
		if (ret < 0)
			strscpy(flow->hw[dir].reason, result.reason,
				sizeof(flow->hw[dir].reason));
		else
			flow->hw[dir].reason[0] = '\0';
		spin_unlock_bh(&flow->hw_lock);
		if (ret >= 0)
			continue;
		/* A disappearing rule is normal; a final valid sample may follow it. */
		if (ret != -ENOENT || !stats[dir].used_hw_stats_valid)
			memset(&stats[dir], 0, sizeof(stats[dir]));
		if (ret != -ENOENT)
			nf_flow_clients_stats_error(flow);
		/* ENOENT confirms absence; I/O errors do not prove rule removal. */
		if (ret == -ENOENT)
			nf_flow_hw_record(flow, dir, &result, false);
	}
	nf_flow_hw_sync(flow);

	lastused = max_t(u64, stats[0].lastused, stats[1].lastused);
	offload->flow->timeout = max_t(u64, offload->flow->timeout,
				       lastused + flow_offload_get_timeout(offload->flow));

	for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++)
		flow_offload_stats_account(offload, dir, &stats[dir]);
}

static void flow_offload_work_del(struct flow_offload_work *offload)
{
	struct flow_offload *flow = offload->flow;
	struct nf_flow_hw_result result;
	struct flow_stats stats;
	int dir, ret;

	/* Ordinary drivers may settle counters only through STATS. */
	flow_offload_work_stats(offload);
	for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++) {
		if (dir == FLOW_OFFLOAD_DIR_REPLY &&
		    !test_bit(NF_FLOW_HW_BIDIRECTIONAL, &flow->flags))
			break;
		memset(&stats, 0, sizeof(stats));
		/* Also discard any backend bookkeeping for refused rules. */
		ret = flow_offload_tuple_del(offload, dir, &stats, &result);
		flow_offload_stats_account(offload, dir, &stats);
		spin_lock_bh(&flow->hw_lock);
		if (ret < 0 && ret != -ENOENT && ret != -ENODEV) {
			/* The backend must quarantine its uncertain allocations. */
			flow->hw[dir].error = ret;
			strscpy(flow->hw[dir].reason, result.reason,
				sizeof(flow->hw[dir].reason));
			WRITE_ONCE(flow->hw[dir].state, NF_FLOW_HW_QUARANTINED);
		} else {
			flow->hw[dir].error = 0;
			flow->hw[dir].reason[0] = '\0';
			WRITE_ONCE(flow->hw[dir].state, NF_FLOW_HW_REMOVED);
		}
		WRITE_ONCE(flow->hw[dir].retry_at, 0);
		spin_unlock_bh(&flow->hw_lock);
	}
	nf_flow_hw_sync(flow);
	/* Software teardown is complete; quarantined resources belong to driver. */
	set_bit(NF_FLOW_HW_DEAD, &flow->flags);
}

static void flow_offload_work_handler(struct work_struct *work)
{
	struct flow_offload_work *offload;
	struct net *net;

	offload = container_of(work, struct flow_offload_work, work);
	net = read_pnet(&offload->flowtable->net);
	switch (offload->cmd) {
		case FLOW_CLS_REPLACE:
			flow_offload_work_add(offload);
			NF_FLOW_TABLE_STAT_DEC_ATOMIC(net, count_wq_add);
			break;
		case FLOW_CLS_DESTROY:
			flow_offload_work_del(offload);
			NF_FLOW_TABLE_STAT_DEC_ATOMIC(net, count_wq_del);
			break;
		case FLOW_CLS_STATS:
			flow_offload_work_stats(offload);
			NF_FLOW_TABLE_STAT_DEC_ATOMIC(net, count_wq_stats);
			break;
		default:
			WARN_ON_ONCE(1);
	}
	smp_mb__before_atomic();
	clear_bit(NF_FLOW_PENDING, &offload->flow->flags);

	kfree(offload);
}

static void flow_offload_queue_work(struct flow_offload_work *offload)
{
	struct net *net = read_pnet(&offload->flowtable->net);

	if (offload->cmd == FLOW_CLS_REPLACE) {
		NF_FLOW_TABLE_STAT_INC_ATOMIC(net, count_wq_add);
		queue_work(nf_flow_offload_add_wq, &offload->work);
	} else if (offload->cmd == FLOW_CLS_DESTROY) {
		NF_FLOW_TABLE_STAT_INC_ATOMIC(net, count_wq_del);
		queue_work(nf_flow_offload_del_wq, &offload->work);
	} else {
		NF_FLOW_TABLE_STAT_INC_ATOMIC(net, count_wq_stats);
		queue_work(nf_flow_offload_stats_wq, &offload->work);
	}
}

static struct flow_offload_work *
nf_flow_offload_work_alloc(struct nf_flowtable *flowtable,
			   struct flow_offload *flow, unsigned int cmd)
{
	struct flow_offload_work *offload;

	if (test_and_set_bit(NF_FLOW_PENDING, &flow->flags))
		return NULL;

	offload = kmalloc_obj(struct flow_offload_work, GFP_ATOMIC);
	if (!offload) {
		clear_bit(NF_FLOW_PENDING, &flow->flags);
		return NULL;
	}

	offload->cmd = cmd;
	offload->flow = flow;
	offload->flowtable = flowtable;
	INIT_WORK(&offload->work, flow_offload_work_handler);

	return offload;
}

static bool nf_flow_offload_unsupported(struct flow_offload *flow)
{
	if (flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.tun_num ||
	    flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.tun_num)
		return true;

	return false;
}

void nf_flow_offload_refresh(struct nf_flowtable *flowtable,
			     struct flow_offload *flow)
{
	struct flow_offload_work *offload;

	if (test_bit(NF_FLOW_TEARDOWN, &flow->flags) ||
	    test_bit(NF_FLOW_CLOSING, &flow->flags) ||
	    test_bit(NF_FLOW_HW_DYING, &flow->flags) ||
	    test_bit(NF_FLOW_HW_DEAD, &flow->flags) ||
	    test_bit(NF_FLOW_PENDING, &flow->flags) ||
	    !nf_flow_hw_add_needed(flow))
		return;

	offload = nf_flow_offload_work_alloc(flowtable, flow, FLOW_CLS_REPLACE);
	if (!offload)
		return;

	flow_offload_queue_work(offload);
}

void nf_flow_offload_add(struct nf_flowtable *flowtable,
			 struct flow_offload *flow)
{
	if (nf_flow_offload_unsupported(flow))
		return;

	set_bit(NF_FLOW_HW, &flow->flags);
	nf_flow_offload_refresh(flowtable, flow);
}

void nf_flow_offload_del(struct nf_flowtable *flowtable,
			 struct flow_offload *flow)
{
	struct flow_offload_work *offload;

	offload = nf_flow_offload_work_alloc(flowtable, flow, FLOW_CLS_DESTROY);
	if (!offload)
		return;

	set_bit(NF_FLOW_HW_DYING, &flow->flags);
	flow_offload_queue_work(offload);
}

void nf_flow_offload_stats(struct nf_flowtable *flowtable,
			   struct flow_offload *flow)
{
	struct flow_offload_work *offload;
#ifdef CONFIG_NF_FLOW_TABLE_CLIENT_STATS
	u64 now = get_jiffies_64(), interval = 0;
#endif
	__s32 delta;

	if (!nf_flow_offload_has_hw(flow))
		return;

#ifdef CONFIG_NF_FLOW_TABLE_CLIENT_STATS
	if (flowtable->clients_aggregate_stats) {
		u64 next = READ_ONCE(flow->hw_stats_next);
		unsigned long timeout = flow_offload_get_timeout(flow);

		/* A busy software fallback refreshes flow->timeout too. Basing
		 * this check on that timeout hides an invalidated HW rule forever.
		 */
		interval = max_t(u64, 1, timeout >= 10 * HZ ?
				 timeout / 2 : timeout / 10);
		if (!next) {
			/* Fresh rules already have an installation timestamp. Avoid
			 * an immediate age transaction for every short-lived BT flow.
			 */
			WRITE_ONCE(flow->hw_stats_next, now + interval);
			return;
		}
		if (time_before64(now, next))
			return;
	} else
#endif
	{
		delta = nf_flow_timeout_delta(flow->timeout);
		if (delta >= (9 * flow_offload_get_timeout(flow)) / 10)
			return;
	}

	offload = nf_flow_offload_work_alloc(flowtable, flow, FLOW_CLS_STATS);
	if (!offload)
		return;
#ifdef CONFIG_NF_FLOW_TABLE_CLIENT_STATS
	if (interval)
		WRITE_ONCE(flow->hw_stats_next, now + interval);
#endif
	flow_offload_queue_work(offload);
}

#ifdef CONFIG_NF_FLOW_TABLE_CLIENT_STATS
bool nf_flow_offload_stats_aggregate(struct nf_flowtable *table)
{
	struct flow_cls_offload cls = { .command = FLOW_CLS_STATS_AGGREGATE };
	struct flow_block_cb *cb;
	bool supported = true, found = false;

	cls.stats_scope.domain = table;
	down_read(&table->flow_block_lock);
	list_for_each_entry(cb, &table->flow_block.cb_list, list) {
		int ret;

		cls.aggregate_stats_supported = false;
		ret = cb->cb(TC_SETUP_CLSFLOWER, &cls, cb->cb_priv);
		found = true;
		supported &= cls.aggregate_stats_supported;
		/* A failed supported batch must not create a per-rule read storm. */
		if (ret < 0 && cls.aggregate_stats_supported)
			nf_flow_clients_batch_error(read_pnet(&table->net));
	}
	up_read(&table->flow_block_lock);
	return found && supported;
}

void nf_flow_offload_stats_force(struct nf_flowtable *table, struct flow_offload *flow)
{
	struct flow_offload_work *offload;

	if (!nf_flow_offload_has_hw(flow))
		return;
	offload = nf_flow_offload_work_alloc(table, flow, FLOW_CLS_STATS);
	if (offload)
		flow_offload_queue_work(offload);
}

void nf_flow_offload_stats_flush(void)
{
	flush_workqueue(nf_flow_offload_stats_wq);
}
#endif

void nf_flow_table_offload_flush_cleanup(struct nf_flowtable *flowtable)
{
	if (nf_flowtable_hw_offload(flowtable)) {
		flush_workqueue(nf_flow_offload_del_wq);
		nf_flow_table_gc_run(flowtable);
	}
}

#ifdef CONFIG_NF_FLOW_TABLE_PROCFS
static const char *nf_flow_hw_state_name(u8 state)
{
	switch (state) {
	case NF_FLOW_HW_INSTALLED:
		return "installed";
	case NF_FLOW_HW_RETRY:
		return "retry";
	case NF_FLOW_HW_UNSUPPORTED:
		return "unsupported";
	case NF_FLOW_HW_REMOVED:
		return "removed";
	case NF_FLOW_HW_QUARANTINED:
		return "quarantined";
	default:
		return "untried";
	}
}

void nf_flow_offload_hw_show(struct seq_file *seq, struct nf_flowtable *table,
			     struct flow_offload *flow)
{
	struct nf_flow_hw_dir hw[FLOW_OFFLOAD_DIR_MAX];
	const struct flow_offload_tuple *tuple;
	bool requested = test_bit(NF_FLOW_HW, &flow->flags);
	u8 mask;
	int dir;

	spin_lock_bh(&flow->hw_lock);
	memcpy(hw, flow->hw, sizeof(hw));
	mask = flow->hw_mask;
	spin_unlock_bh(&flow->hw_lock);
	for (dir = 0; dir < FLOW_OFFLOAD_DIR_MAX; dir++) {
		bool eligible = requested && (!dir ||
			test_bit(NF_FLOW_HW_BIDIRECTIONAL, &flow->flags));
		s32 delta = nf_flow_timeout_delta(hw[dir].retry_at);
		u32 retry_ms = hw[dir].state == NF_FLOW_HW_RETRY && delta > 0 ?
				jiffies_to_msecs(delta) : 0;

		tuple = &flow->tuplehash[dir].tuple;
		seq_printf(seq, "priority=%d dir=%s iif=%d family=%u proto=%u ",
			   table->priority, dir ? "reply" : "original",
			   tuple->iifidx, tuple->l3proto, tuple->l4proto);
		if (tuple->l3proto == NFPROTO_IPV4)
			seq_printf(seq, "src=%pI4 dst=%pI4 ",
				   &tuple->src_v4, &tuple->dst_v4);
		else if (tuple->l3proto == NFPROTO_IPV6)
			seq_printf(seq, "src=%pI6c dst=%pI6c ",
				   &tuple->src_v6, &tuple->dst_v6);
		seq_printf(seq, "sport=%u dport=%u hw_mask=%u state=%s errno=%d stats_errno=%d attempts=%u failures=%u retry_ms=%u pending=%d dying=%d closing=%d teardown=%d reason=\"",
			   ntohs(tuple->src_port), ntohs(tuple->dst_port), mask,
			   eligible ? nf_flow_hw_state_name(hw[dir].state) : "disabled",
			   hw[dir].error, hw[dir].stats_error, hw[dir].attempts,
			   hw[dir].failures, retry_ms,
			   test_bit(NF_FLOW_PENDING, &flow->flags),
			   test_bit(NF_FLOW_HW_DYING, &flow->flags),
			   test_bit(NF_FLOW_CLOSING, &flow->flags),
			   test_bit(NF_FLOW_TEARDOWN, &flow->flags));
		seq_escape(seq, hw[dir].reason, "\\\"\n\r\t");
		seq_puts(seq, "\"\n");
	}
}
#endif

void nf_flow_table_offload_flush(struct nf_flowtable *flowtable)
{
	if (nf_flowtable_hw_offload(flowtable)) {
		flush_workqueue(nf_flow_offload_add_wq);
		flush_workqueue(nf_flow_offload_del_wq);
		flush_workqueue(nf_flow_offload_stats_wq);
	}
}

static int nf_flow_table_block_setup(struct nf_flowtable *flowtable,
				     struct flow_block_offload *bo,
				     enum flow_block_command cmd)
{
	struct flow_block_cb *block_cb, *next;
	int err = 0;

	down_write(&flowtable->flow_block_lock);
	switch (cmd) {
	case FLOW_BLOCK_BIND:
		list_splice(&bo->cb_list, &flowtable->flow_block.cb_list);
		break;
	case FLOW_BLOCK_UNBIND:
		list_for_each_entry_safe(block_cb, next, &bo->cb_list, list) {
			list_del(&block_cb->list);
			flow_block_cb_free(block_cb);
		}
		break;
	default:
		WARN_ON_ONCE(1);
		err = -EOPNOTSUPP;
	}
	up_write(&flowtable->flow_block_lock);

	return err;
}

static void nf_flow_table_block_offload_init(struct flow_block_offload *bo,
					     struct net *net,
					     enum flow_block_command cmd,
					     struct nf_flowtable *flowtable,
					     struct netlink_ext_ack *extack)
{
	memset(bo, 0, sizeof(*bo));
	bo->net		= net;
	bo->block	= &flowtable->flow_block;
	bo->command	= cmd;
	bo->binder_type	= FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS;
	bo->extack	= extack;
	bo->cb_list_head = &flowtable->flow_block.cb_list;
	INIT_LIST_HEAD(&bo->cb_list);
}

static void nf_flow_table_indr_cleanup(struct flow_block_cb *block_cb)
{
	struct nf_flowtable *flowtable = block_cb->indr.data;
	struct net_device *dev = block_cb->indr.dev;

	nf_flow_table_gc_cleanup(flowtable, dev);
	down_write(&flowtable->flow_block_lock);
	list_del(&block_cb->list);
	list_del(&block_cb->driver_list);
	flow_block_cb_free(block_cb);
	up_write(&flowtable->flow_block_lock);
}

static int nf_flow_table_indr_offload_cmd(struct flow_block_offload *bo,
					  struct nf_flowtable *flowtable,
					  struct net_device *dev,
					  enum flow_block_command cmd,
					  struct netlink_ext_ack *extack)
{
	nf_flow_table_block_offload_init(bo, dev_net(dev), cmd, flowtable,
					 extack);

	return flow_indr_dev_setup_offload(dev, NULL, TC_SETUP_FT, flowtable, bo,
					   nf_flow_table_indr_cleanup);
}

static int nf_flow_table_offload_cmd(struct flow_block_offload *bo,
				     struct nf_flowtable *flowtable,
				     struct net_device *dev,
				     enum flow_block_command cmd,
				     struct netlink_ext_ack *extack)
{
	int err;

	nf_flow_table_block_offload_init(bo, dev_net(dev), cmd, flowtable,
					 extack);
	down_write(&flowtable->flow_block_lock);
	err = dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_FT, bo);
	up_write(&flowtable->flow_block_lock);
	if (err < 0)
		return err;

	return 0;
}

int nf_flow_table_offload_setup(struct nf_flowtable *flowtable,
				struct net_device *dev,
				enum flow_block_command cmd)
{
	struct netlink_ext_ack extack = {};
	struct flow_block_offload bo;
	int err;

	if (!nf_flowtable_hw_offload(flowtable))
		return nf_flow_offload_xdp_setup(flowtable, dev, cmd);

	/*
	 * Drain while callbacks still exist: the last UNBIND otherwise makes
	 * final DESTROY/STATS unreachable. Invalidate the table conservatively;
	 * other surviving devices can admit new flows normally.
	 */
	if (cmd == FLOW_BLOCK_UNBIND) {
		nf_flow_table_gc_cleanup(flowtable, NULL);
		nf_flow_table_gc_run(flowtable);
		nf_flow_table_offload_flush(flowtable);
	}
	if (dev->netdev_ops->ndo_setup_tc)
		err = nf_flow_table_offload_cmd(&bo, flowtable, dev, cmd,
						&extack);
	else
		err = nf_flow_table_indr_offload_cmd(&bo, flowtable, dev, cmd,
						     &extack);
	if (err < 0)
		return err;

	return nf_flow_table_block_setup(flowtable, &bo, cmd);
}
EXPORT_SYMBOL_GPL(nf_flow_table_offload_setup);

int nf_flow_table_offload_init(void)
{
	nf_flow_offload_add_wq  = alloc_workqueue("nf_ft_offload_add",
						  WQ_UNBOUND | WQ_SYSFS, 0);
	if (!nf_flow_offload_add_wq)
		return -ENOMEM;

	nf_flow_offload_del_wq  = alloc_workqueue("nf_ft_offload_del",
						  WQ_UNBOUND | WQ_SYSFS, 0);
	if (!nf_flow_offload_del_wq)
		goto err_del_wq;

	nf_flow_offload_stats_wq  = alloc_workqueue("nf_ft_offload_stats",
						    WQ_UNBOUND | WQ_SYSFS, 1);
	if (!nf_flow_offload_stats_wq)
		goto err_stats_wq;

	return 0;

err_stats_wq:
	destroy_workqueue(nf_flow_offload_del_wq);
err_del_wq:
	destroy_workqueue(nf_flow_offload_add_wq);
	return -ENOMEM;
}

void nf_flow_table_offload_exit(void)
{
	destroy_workqueue(nf_flow_offload_add_wq);
	destroy_workqueue(nf_flow_offload_del_wq);
	destroy_workqueue(nf_flow_offload_stats_wq);
}
