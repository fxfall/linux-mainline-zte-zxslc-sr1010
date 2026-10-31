/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_ZTE_NPPT_OFFLOAD_H
#define _LINUX_ZTE_NPPT_OFFLOAD_H

#include <linux/if_ether.h>
#include <linux/netdevice.h>

struct zte_nppt;
struct zte_nppt_host;
struct zte_nppt_vlan;
struct seq_file;

/* Current fast-flow lease. These are configured resources, not silicon limits. */
#define ZTE_NPPT_API_VERSION	3
#define ZTE_NPPT_FAST_IKEY_DEPTH	4096
/* Factory statistics layout. Flowtable endpoint groups share these slots;
 * this is not a directional forwarding-entry or connection-count limit.
 */
#define ZX279133_FAST_STAT_DEPTH	1024
#define ZX279133_FAST_STAT_COUNTERS (2U * ZX279133_FAST_STAT_DEPTH)
#define ZX279133_FAST_AGE_DEPTH	BIT(18)
#define ZX279133_WANID_PPPOE_PUSH	1
#define ZX279133_WANID_PPPOE_POP	2
#define ZTE_NPPT_DDR_BYTES	0x01000000

/* Implemented API primitives, not a claim about all silicon capabilities. */
#define ZTE_NPPT_CAP_ZCAM	BIT_ULL(0)
#define ZTE_NPPT_CAP_DDR		BIT_ULL(1)
#define ZTE_NPPT_CAP_HOST_VID0	BIT_ULL(2)
#define ZTE_NPPT_CAP_WANID	BIT_ULL(3)
#define ZTE_NPPT_CAP_STATS	BIT_ULL(4)
#define ZTE_NPPT_CAP_AGE		BIT_ULL(5)
#define ZTE_NPPT_CAP_PPU_MCODE	BIT_ULL(6)
/* Experimental R16 layout, LAN IPv4 ingress only. */
#define ZTE_NPPT_CAP_LAN_VID_KEY	BIT_ULL(7)

enum zx279133_flow_port {
	ZX279133_FLOW_PORT_NONE,
	ZX279133_FLOW_PORT_LAN,
	ZX279133_FLOW_PORT_WAN,
};

struct zx279133_wanid_profile {
	u8 mac[ETH_ALEN];
	u32 sip;
	u16 sid;
	u8 pppoe;
};

/* Supplier serializes these APIs with begin/end or its client callback lock. */
struct zte_nppt_vlan *zte_nppt_vlan_get(struct zte_nppt *np, u16 vid);
int zte_nppt_vlan_put(struct zte_nppt *np, struct zte_nppt_vlan *vlan);
void zte_nppt_vlan_abandon(struct zte_nppt *np, struct zte_nppt_vlan *vlan);
void zte_nppt_vlan_status(struct zte_nppt *np, u32 *rows, u32 *users,
			  u32 *uncertain);

struct zte_nppt_info {
	u32 api_version;
	u32 ikey_depth;
	u64 capabilities;
	u32 ppu_version_major;
	u32 ppu_version_minor;
	bool ppu_version_valid;
	/* No verified revision register or post-write ACK contract yet. */
	bool hardware_revision_valid;
	bool write_completion_verified;
	u32 stat_depth;
	u32 age_depth;
	u32 ddr_bytes;
	u64 generation;
	bool ready;
};

/*
 * One client leases the SDT14 fast-flow, fast IKEY, age and stat ranges.
 * ZCAM slots, SDT9 Hosts and WANID profiles are owned and shared by npu.
 * A future FDB/ACL consumer must obtain coordinated ranges from npu first.
 * Callbacks run with the supplier datapath mutex held; never call begin()
 * from them. The client must pin its module for every installed flow-block
 * callback, and retain uncertain hardware resources until invalidated.
 */
struct zte_nppt_client_ops {
	void *(*attach)(struct zte_nppt *np, struct device *dev);
	int (*detach)(void *priv);
	int (*setup_tc)(void *priv, struct net_device *dev,
			enum tc_setup_type type, void *data);
	bool (*active)(void *priv);
	int (*reset)(void *priv);
	/* Existing topology worker, after successful invalidation/drain. */
	void (*resync)(void *client);
};

int zte_nppt_register_client(const struct zte_nppt_client_ops *ops);
void zte_nppt_unregister_client(const struct zte_nppt_client_ops *ops);
void zte_nppt_get(struct zte_nppt *np);
void zte_nppt_put(struct zte_nppt *np);

/* begin/end guard access to a live, prepared device and serialize shutdown. */
int zte_nppt_begin(struct zte_nppt *np);
int zte_nppt_try_begin(struct zte_nppt *np);
void zte_nppt_end(struct zte_nppt *np);
/* Remaining instance queries/accessors require begin/end or a client callback. */
void zte_nppt_get_info(struct zte_nppt *np, struct zte_nppt_info *info);
enum zx279133_flow_port zte_nppt_dev_port(struct zte_nppt *np,
					struct net_device *dev, u16 *port);
bool zte_nppt_is_wan(struct zte_nppt *np, struct net_device *dev);
int zte_nppt_flow_ready(struct zte_nppt *np);

/* VID0 LAN Host format only; no VLAN-aware FDB or automatic learning ABI. */
struct zte_nppt_host *zte_nppt_host_get(struct zte_nppt *np, const u8 *mac, u16 port);
int zte_nppt_host_put(struct zte_nppt *np, struct zte_nppt_host *host);
void zte_nppt_hosts_show(struct zte_nppt *np, struct seq_file *s);
int zte_nppt_zcam_alloc(struct zte_nppt *np, const u8 *key, u8 selector,
			u8 *block, u8 *cell, u8 *addr);
void zte_nppt_zcam_release(struct zte_nppt *np, u8 block, u8 cell, u8 addr);

/* Hardware encoding is supplied by fnoffload; addresses are never exported.
 * These preserve the existing writer semantics: zero means submitted, not
 * independently observed hardware hit. DDR validity publication is ordered.
 * Caller holds begin/end or is executing a supplier callback above.
 */
int zte_nppt_zcam_write(struct zte_nppt *np, u8 block, u8 cell, u8 addr,
			const u32 *words, unsigned int count);
int zte_nppt_ddr_write(struct zte_nppt *np, u32 bucket, const u32 *words);
#ifdef CONFIG_DEBUG_FS
/* One 64-byte row in logical writer order; caller holds begin/end. */
int zte_nppt_debug_ddr_read(struct zte_nppt *np, u32 bucket, u32 *table);
#endif
int zte_nppt_ddr_clear(struct zte_nppt *np, u32 bucket);
int zte_nppt_ikey_write(struct zte_nppt *np, u32 index, const u32 *data);
int zte_nppt_stats_read(struct zte_nppt *np, u16 id, u64 *packets, u64 *bytes);
int zte_nppt_age_read_clear(struct zte_nppt *np, u32 id, bool *used);
int zte_nppt_wanid_get(struct zte_nppt *np, bool downstream,
		       const struct zx279133_wanid_profile *profile, u8 *id);
void zte_nppt_wanid_put(struct zte_nppt *np, u8 id, bool snat);

struct zte_nppt_host *zte_nppt_host_lookup_get(struct zte_nppt *np, const u8 *mac);
int zte_nppt_host_limit(struct zte_nppt *np, struct zte_nppt_host *host,
			 u8 slot, bool upload, bool download);
void zte_nppt_host_watch(struct zte_nppt *np, u8 slot, const u8 *mac);
#endif
