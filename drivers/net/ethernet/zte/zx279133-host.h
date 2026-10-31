/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ZX279133_HOST_H
#define _ZX279133_HOST_H

#include <linux/types.h>

struct device;
struct seq_file;
struct zte_nppt;
struct zte_nppt_host;
struct zx279133_host_manager;

struct zx279133_host_manager *
zx279133_hosts_create(struct zte_nppt *np, struct device *dev);
int zx279133_hosts_start(struct zx279133_host_manager *manager);
void zx279133_hosts_quiesce(struct zx279133_host_manager *manager);
void zx279133_hosts_destroy(struct zx279133_host_manager *manager);
bool zx279133_hosts_active(struct zx279133_host_manager *manager);
int zx279133_hosts_reap(struct zx279133_host_manager *manager, bool ready);
void zx279133_hosts_reset_result(struct zx279133_host_manager *manager, int ret);
int zx279133_hosts_ready(struct zx279133_host_manager *manager);
int zx279133_hosts_zcam_alloc(struct zx279133_host_manager *manager,
			      const u8 *key, u8 selector,
			      u8 *block, u8 *cell, u8 *addr);
void zx279133_hosts_zcam_release(struct zx279133_host_manager *manager,
				 u8 block, u8 cell, u8 addr);
struct zte_nppt_host *zx279133_host_get(struct zx279133_host_manager *manager,
					const u8 *mac, u16 port);
int zx279133_host_put(struct zx279133_host_manager *manager,
		      struct zte_nppt_host *host);
void zx279133_hosts_show(struct zx279133_host_manager *manager, struct seq_file *s);
int zx279133_nppt_topology_reset(struct zte_nppt *np);

struct zte_nppt_host *
zx279133_host_lookup_get(struct zx279133_host_manager *manager, const u8 *mac);
int zx279133_host_limit(struct zx279133_host_manager *manager,
			struct zte_nppt_host *host, u8 slot,
			bool upload, bool download);
void zx279133_host_watch(struct zx279133_host_manager *manager,
			 u8 slot, const u8 *mac);
#endif
