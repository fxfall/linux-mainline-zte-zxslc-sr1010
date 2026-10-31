// SPDX-License-Identifier: GPL-2.0-only
/* Managed PLCR leases. No workqueues, packet hooks or probe-time table scan. */
#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/export.h>
#include "zx279133-native.h"
#include "zx279133-meter.h"

#define METER_FAST_BUCKETS 32
#define METER_MAC_CLIENTS 32
#define METER_BUCKETS (METER_FAST_BUCKETS + 2 * METER_MAC_CLIENTS)
#define METER_FLOW_BASE 192

struct meter_profile {
	struct zte_nppt_plcr_profile config;
	u32 saved[3];
	unsigned int refs;
	bool dirty;
};

struct zte_nppt_meter {
	u32 saved[4];
	const void *scope;
	u32 action_index;
	unsigned int refs;
	u8 bucket;
	u8 profile;
	bool used;
	bool orphan;
	bool binding_restored;
	bool uncertain;
};

struct zx279133_meter_pool {
	struct meter_profile profiles[ZTE_NPPT_PLCR_PROFILES];
	struct zte_nppt_meter buckets[METER_BUCKETS];
	DECLARE_BITMAP(external_profiles, ZTE_NPPT_PLCR_PROFILES);
	bool inventoried;
};

static u16 meter_flow_id(unsigned int bucket)
{
	if (bucket < METER_FAST_BUCKETS)
		return METER_FLOW_BASE + bucket;
	bucket -= METER_FAST_BUCKETS;
	return (bucket & 1 ? 0x814 : 0x414) + bucket / 2;
}

static bool meter_profile_equal(const struct zte_nppt_plcr_profile *a,
				const struct zte_nppt_plcr_profile *b)
{
	return a->cir == b->cir && a->eir == b->eir && a->cbs == b->cbs &&
	a->ebs == b->ebs && a->cd_mode == b->cd_mode &&
	a->cf_flag == b->cf_flag && a->cm_flag == b->cm_flag &&
	a->pkt_sign == b->pkt_sign;
}

static int meter_profile_restore(struct zx279133_eth *eth, u8 id, u32 *saved)
{
	u32 actual[3];
	int ret = zx279133_native_profile_words(eth, id, saved, true);

	if (!ret)
		ret = zx279133_native_profile_words(eth, id, actual, false);
	if (!ret && memcmp(saved, actual, sizeof(actual)))
		ret = -EIO;
	return ret;
}

static int meter_binding_restore(struct zx279133_eth *eth, u16 id, u32 *saved)
{
	u32 actual[4];
	int ret = zx279133_native_binding_words(eth, id, saved, true);

	if (!ret)
		ret = zx279133_native_binding_words(eth, id, actual, false);
	if (!ret && memcmp(saved, actual, sizeof(actual)))
		ret = -EIO;
	return ret;
}

int zx279133_meter_put(struct zx279133_meter_pool *p,
		       struct zx279133_eth *eth, struct zte_nppt_meter *m)
{
	struct meter_profile *profile;
	int ret;

	if (!p || !m || m->bucket >= METER_BUCKETS ||
	    m != &p->buckets[m->bucket] || !m->used)
		return -EINVAL;
	if (m->refs > 1) {
		m->refs--;
		return 0;
	}
	profile = &p->profiles[m->profile];
	m->uncertain = true;
	if (!m->binding_restored) {
		ret = meter_binding_restore(eth, meter_flow_id(m->bucket), m->saved);
		if (ret)
			return ret;
		m->binding_restored = true;
	}
	if (profile->refs == 1) {
		profile->dirty = true;
		ret = meter_profile_restore(eth, m->profile, profile->saved);
		if (ret)
			return ret;
		profile->dirty = false;
	}
	profile->refs--;
	m->used = false;
	return 0;
}

void zx279133_meter_abandon(struct zx279133_meter_pool *p,
			    struct zte_nppt_meter *m)
{
	if (p && m && m->bucket < METER_BUCKETS && m == &p->buckets[m->bucket] &&
	    m->used)
		m->orphan = true;
}

static int meter_reap(struct zx279133_meter_pool *p, struct zx279133_eth *eth)
{
	unsigned int i;
	int ret;

	for (i = 0; i < METER_BUCKETS; i++)
		if (p->buckets[i].used && p->buckets[i].orphan) {
			ret = zx279133_meter_put(p, eth, &p->buckets[i]);
			if (ret)
				return ret;
		}
	return 0;
}

int zx279133_meter_drain(struct zx279133_meter_pool *p, struct zx279133_eth *eth)
{
	unsigned int i;
	int ret;

	if (!p)
		return 0;
	ret = meter_reap(p, eth);
	if (ret)
		return ret;
	for (i = 0; i < METER_BUCKETS; i++)
		if (p->buckets[i].used)
			return -EBUSY;
	p->inventoried = false;
	return 0;
}

/* Scan only on first use or after an unmanaged binding edit. Never per packet
 * or from a timer. Do not overwrite a profile referenced by an external meter.
 */
static int meter_inventory(struct zx279133_meter_pool *p, struct zx279133_eth *eth)
{
	struct zte_nppt_plcr_binding binding;
	unsigned int id;
	int ret;

	bitmap_zero(p->external_profiles, ZTE_NPPT_PLCR_PROFILES);
	for (id = 0; id < ZTE_NPPT_PLCR_FLOWS; id++) {
		unsigned int slot;
		bool owned = false;

		for (slot = 0; slot < METER_BUCKETS; slot++)
			if (meter_flow_id(slot) == id && p->buckets[slot].used) {
				owned = true;
				break;
			}
		if (owned)
			continue;
		ret = zx279133_native_plcr_binding_get(eth, id, &binding);
		if (ret)
			return ret;
		if (binding.enabled)
			__set_bit(binding.profile, p->external_profiles);
	}
	p->inventoried = true;
	return 0;
}

static int meter_get(struct zx279133_meter_pool **pool,
		     struct zx279133_eth *eth,
		     const struct zte_nppt_plcr_profile *wanted,
		     const void *scope, u32 action_index,
		     unsigned int first, unsigned int end,
		     struct zte_nppt_meter **out)
{
	struct zte_nppt_plcr_profile actual;
	struct zte_nppt_plcr_binding binding;
	struct zx279133_meter_pool *p;
	struct meter_profile *profile;
	struct zte_nppt_meter *m = NULL;
	unsigned int i, id = ZTE_NPPT_PLCR_PROFILES;
	int ret;

	*out = NULL;
	if (!wanted || wanted->cir > 0x3ffff || wanted->eir > 0x3ffff ||
	    wanted->cbs > 0x7ffffff || wanted->ebs > 0x7ffffff ||
	    wanted->cd_mode != 2 || wanted->cf_flag > 1 || wanted->cm_flag > 1 ||
	    wanted->pkt_sign > 1)
		return -EINVAL;
	if (!*pool) {
		*pool = kzalloc(sizeof(**pool), GFP_KERNEL);
		if (!*pool)
			return -ENOMEM;
	}
	p = *pool;
	ret = meter_reap(p, eth);
	if (ret)
		return ret;
	if (!p->inventoried) {
		ret = meter_inventory(p, eth);
		if (ret)
			return ret;
	}
	/* One indexed TC action is one shared token bucket, not a rate per flow.
	 * Do not update a meter in place while unrelated flows still reference it.
	 */
	if (scope && action_index)
		for (i = first; i < end; i++) {
			struct zte_nppt_meter *shared = &p->buckets[i];

			if (!shared->used || shared->orphan || shared->scope != scope ||
			    shared->action_index != action_index)
				continue;
			profile = &p->profiles[shared->profile];
			if (profile->dirty || shared->binding_restored || shared->uncertain ||
			    !meter_profile_equal(&profile->config, wanted))
				return -EBUSY;
			shared->refs++;
			*out = shared;
			return 0;
		}
	for (i = first; i < end; i++) {
		if (p->buckets[i].used)
			continue;
		ret = zx279133_native_plcr_binding_get(eth, meter_flow_id(i), &binding);
		if (ret)
			return ret;
		if (!binding.enabled) {
			m = &p->buckets[i];
			m->bucket = i;
			break;
		}
	}
	if (!m)
		return -ENOSPC;
	for (i = 0; i < ZTE_NPPT_PLCR_PROFILES; i++)
		if (p->profiles[i].refs && !p->profiles[i].dirty &&
		    meter_profile_equal(&p->profiles[i].config, wanted)) {
			id = i;
			break;
		}
	if (id == ZTE_NPPT_PLCR_PROFILES)
		for (i = 0; i < ZTE_NPPT_PLCR_PROFILES; i++)
			if (!p->profiles[i].refs && !test_bit(i, p->external_profiles)) {
				id = i;
				break;
			}
	if (id == ZTE_NPPT_PLCR_PROFILES)
		return -ENOSPC;
	profile = &p->profiles[id];
	ret = zx279133_native_binding_words(eth, meter_flow_id(m->bucket),
					    m->saved, false);
	if (ret)
		return ret;
	if (!profile->refs) {
		ret = zx279133_native_profile_words(eth, id, profile->saved, false);
		if (ret)
			return ret;
		profile->config = *wanted;
	}
	m->scope = scope;
	m->action_index = action_index;
	m->refs = 1;
	m->profile = id;
	m->used = true;
	m->orphan = false;
	m->binding_restored = false;
	m->uncertain = false;
	profile->refs++;
	if (profile->refs == 1) {
		profile->dirty = true;
		ret = zx279133_native_plcr_profile_set(eth, id, wanted);
		if (ret)
			goto rollback;
		ret = zx279133_native_plcr_profile_get(eth, id, &actual);
		if (ret)
			goto rollback;
		if (!meter_profile_equal(&actual, wanted)) {
			ret = -EIO;
			goto rollback;
		}
		profile->dirty = false;
	}
	binding.profile = id;
	binding.enabled = true;
	ret = zx279133_native_plcr_binding_set(eth, meter_flow_id(m->bucket), &binding);
	if (ret)
		goto rollback;
	ret = zx279133_native_plcr_binding_get(eth, meter_flow_id(m->bucket), &binding);
	if (ret)
		goto rollback;
	if (!binding.enabled || binding.profile != id) {
		ret = -EIO;
		goto rollback;
	}
	*out = m;
	return 0;
rollback:
	m->orphan = true;
	/* Retain failed rollback inside NPU; it is retried before reuse/detach. */
	zx279133_meter_put(p, eth, m);
	return ret;
}

int zx279133_meter_get(struct zx279133_meter_pool **pool,
		       struct zx279133_eth *eth,
		       const struct zte_nppt_plcr_profile *wanted,
		       const void *scope, u32 action_index,
		       struct zte_nppt_meter **out)
{
	return meter_get(pool, eth, wanted, scope, action_index,
			 0, METER_FAST_BUCKETS, out);
}

int zx279133_meter_mac_get(struct zx279133_meter_pool **pool,
			   struct zx279133_eth *eth,
			   const struct zte_nppt_plcr_profile *wanted,
			   u8 slot, bool download, struct zte_nppt_meter **out)
{
	unsigned int bucket = METER_FAST_BUCKETS + slot * 2 + download;

	if (slot >= METER_MAC_CLIENTS)
		return -EINVAL;
	return meter_get(pool, eth, wanted, NULL, 0, bucket, bucket + 1, out);
}

bool zx279133_meter_profile_busy(struct zx279133_meter_pool *p, u8 id)
{
	return p && id < ZTE_NPPT_PLCR_PROFILES && p->profiles[id].refs;
}

bool zx279133_meter_binding_busy(struct zx279133_meter_pool *p, u16 id)
{
	unsigned int i;

	if (p)
		for (i = 0; i < METER_BUCKETS; i++)
			if (p->buckets[i].used && meter_flow_id(i) == id)
				return true;
	return false;
}

void zx279133_meter_inventory_changed(struct zx279133_meter_pool *p)
{
	if (p)
		p->inventoried = false;
}

u8 zte_nppt_meter_bucket(const struct zte_nppt_meter *m)
{
	return m->bucket;
}
EXPORT_SYMBOL_GPL(zte_nppt_meter_bucket);

void zx279133_meter_destroy(struct zx279133_meter_pool *p)
{
	kfree(p);
}

bool zx279133_meter_active(struct zx279133_meter_pool *p)
{
	unsigned int i;

	if (p)
		for (i = 0; i < METER_BUCKETS; i++)
			if (p->buckets[i].used)
				return true;
	return false;
}
