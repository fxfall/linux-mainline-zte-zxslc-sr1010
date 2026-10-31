/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ZX279133_METER_H
#define _ZX279133_METER_H
#include <linux/zte_nppt_native.h>
struct zx279133_eth;
struct zx279133_meter_pool;
int zx279133_meter_get(struct zx279133_meter_pool **pool,
		       struct zx279133_eth *eth,
		       const struct zte_nppt_plcr_profile *profile,
		       const void *scope, u32 action_index,
		       struct zte_nppt_meter **out);
int zx279133_meter_put(struct zx279133_meter_pool *pool,
		       struct zx279133_eth *eth, struct zte_nppt_meter *meter);
void zx279133_meter_abandon(struct zx279133_meter_pool *pool,
			    struct zte_nppt_meter *meter);
int zx279133_meter_drain(struct zx279133_meter_pool *pool,
			 struct zx279133_eth *eth);
bool zx279133_meter_active(struct zx279133_meter_pool *pool);
void zx279133_meter_destroy(struct zx279133_meter_pool *pool);
bool zx279133_meter_profile_busy(struct zx279133_meter_pool *pool, u8 id);
bool zx279133_meter_binding_busy(struct zx279133_meter_pool *pool, u16 id);
void zx279133_meter_inventory_changed(struct zx279133_meter_pool *pool);
int zx279133_meter_mac_get(struct zx279133_meter_pool **pool,
			   struct zx279133_eth *eth,
			   const struct zte_nppt_plcr_profile *profile,
			   u8 slot, bool download, struct zte_nppt_meter **out);
#endif
