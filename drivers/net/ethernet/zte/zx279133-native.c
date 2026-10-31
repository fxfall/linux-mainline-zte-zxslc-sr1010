// SPDX-License-Identifier: GPL-2.0-only
/* CPU133 NP primitives reconstructed from OEM np.ko. No init-time caller.
 * Source locations and limitations: docs/NP-NATIVE-API-R1.md in the project.
 */
#include <linux/bitfield.h>
#include <linux/io.h>
#include <linux/iopoll.h>

#include "zx279133.h"
#include "zx279133-native.h"

#define PLCR_PROFILE_BASE	0x40000
#define PLCR_MODE		0x280016
#define PLCR_BASE		0x280017
#define PLCR_CONFIGURED_BASE	40960
#define SSCH_GATE		0x00b8
#define SSCH_GATE_BIT		BIT(6)
#define SSCH_COMMAND		0x2c014
#define SSCH_DONE		0x2c018
#define SSCH_DATA		0x2c01c
#define SSCH_COMMAND_MASK	0xffc0007f
#define SSCH_MODE0		0x2c02c
#define SSCH_MODE1		0x2c030
#define SSCH_QUEUE_ENABLE0	0x2c060
#define SSCH_QUEUE_ENABLE1	0x2c064

static int zx279133_plcr_pack(const struct zte_nppt_plcr_profile *p, u32 *w)
{
	if (!p || p->cir > GENMASK(17, 0) || p->eir > GENMASK(17, 0) ||
	    p->cbs > GENMASK(26, 0) || p->ebs > GENMASK(26, 0) ||
	    p->cd_mode != 2 || p->cf_flag > 1 || p->cm_flag > 1 ||
	    p->pkt_sign > 1)
		return -EINVAL;
	w[0] = p->cir | p->cbs << 18;
	w[1] = (p->cbs >> 14) | p->eir << 13 | p->ebs << 31;
	w[2] = (p->ebs >> 1) | (u32)p->cd_mode << 26 |
		(u32)p->cf_flag << 28 | (u32)p->cm_flag << 29 |
		(u32)p->pkt_sign << 30;
	return 0;
}

static void zx279133_plcr_unpack(const u32 *w, struct zte_nppt_plcr_profile *p)
{
	*p = (struct zte_nppt_plcr_profile) {
		.cir = w[0] & GENMASK(17, 0),
		.cbs = (w[0] >> 18) | (w[1] & GENMASK(12, 0)) << 14,
		.eir = (w[1] >> 13) & GENMASK(17, 0),
		.ebs = (w[1] >> 31) | (w[2] & GENMASK(25, 0)) << 1,
		.cd_mode = (w[2] >> 26) & 3,
		.cf_flag = (w[2] >> 28) & 1,
		.cm_flag = (w[2] >> 29) & 1,
		.pkt_sign = (w[2] >> 30) & 1,
	};
}

int zx279133_native_plcr_profile_get(struct zx279133_eth *eth, u8 id,
				     struct zte_nppt_plcr_profile *profile)
{
	u32 words[3];
	unsigned int i;
	int ret;

	if (!profile || id >= ZTE_NPPT_PLCR_PROFILES)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(words); i++) {
		ret = zx279133_native_plcr_io(eth, PLCR_PROFILE_BASE + id * 4 + i,
					      &words[i], false);
		if (ret)
			return ret;
	}
	zx279133_plcr_unpack(words, profile);
	return 0;
}

int zx279133_native_plcr_profile_set(struct zx279133_eth *eth, u8 id,
				     const struct zte_nppt_plcr_profile *profile)
{
	u32 words[3];
	unsigned int i;
	int ret;

	if (id >= ZTE_NPPT_PLCR_PROFILES)
		return -EINVAL;
	ret = zx279133_plcr_pack(profile, words);
	if (ret)
		return ret;
	for (i = 0; i < ARRAY_SIZE(words); i++) {
		ret = zx279133_native_plcr_io(eth, PLCR_PROFILE_BASE + id * 4 + i,
					      &words[i], true);
		if (ret)
			return ret;
	}
	return 0;
}

static int zx279133_plcr_binding_io(struct zx279133_eth *eth, u16 id,
				    u32 *words, bool write)
{
	u32 base, mode;
	int ret;

	if (id >= ZTE_NPPT_PLCR_FLOWS)
		return -EINVAL;
	if (id < 128)
		return zx279133_native_plcr_io(eth, id * 4 + 3, &words[3], write);
	/* OEM se_plcr_init builds a mode-3 128-bit descriptor at this pool end.
	 * Read the live configuration before using the driver's reserved region.
	 */
	ret = zx279133_native_plcr_io(eth, PLCR_MODE, &mode, false);
	if (ret)
		return ret;
	ret = zx279133_native_plcr_io(eth, PLCR_BASE, &base, false);
	if (ret)
		return ret;
	if (mode != 3 || base != PLCR_CONFIGURED_BASE)
		return -ESTALE;
	return zx279133_native_eram_io(eth, base + id, words, write);
}

int zx279133_native_plcr_binding_get(struct zx279133_eth *eth, u16 id,
				     struct zte_nppt_plcr_binding *binding)
{
	u32 words[4] = {};
	int ret;

	if (!binding)
		return -EINVAL;
	ret = zx279133_plcr_binding_io(eth, id, words, false);
	if (ret)
		return ret;
	*binding = (struct zte_nppt_plcr_binding) {
		.profile = (words[3] >> 15) & 0x7f,
		.enabled = !!(words[3] & BIT(22)),
	};
	return 0;
}

int zx279133_native_plcr_binding_set(struct zx279133_eth *eth, u16 id,
				     const struct zte_nppt_plcr_binding *binding)
{
	u32 words[4] = {};

	if (!binding || binding->profile >= ZTE_NPPT_PLCR_PROFILES)
		return -EINVAL;
	words[3] = (u32)binding->profile << 15 | (u32)binding->enabled << 22;
	return zx279133_plcr_binding_io(eth, id, words, true);
}

int zx279133_native_plcr_timing_get(struct zx279133_eth *eth,
				    struct zte_nppt_plcr_timing *timing)
{
	static const u32 addresses[] = { 0x280018, 0x300010, 0x30000e, 0x28001f };
	u32 value[ARRAY_SIZE(addresses)];
	unsigned int i;
	int ret;

	if (!timing)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(addresses); i++) {
		ret = zx279133_native_plcr_io(eth, addresses[i], &value[i], false);
		if (ret)
			return ret;
	}
	*timing = (struct zte_nppt_plcr_timing) {
		.time_count = value[0], .packet_length = value[1],
		.packet_offset = value[2], .loose_length = value[3],
	};
	return 0;
}

/* np.ko ssch_ind_{read,write}: command -> wait -> data, also for writes.
 * Do not substitute the data-before-command protocol used by other windows.
 * np_ind_lock protects the shared scheduler gate and the entire transaction.
 */
static int zx279133_ssch_ind(struct zx279133_eth *eth, u8 ram, u8 index,
			     u32 *value, bool write)
{
	u32 gate = readl(eth->base + SSCH_GATE);
	u32 command, status;
	int ret;

	if (gate & SSCH_GATE_BIT)
		writel(gate & ~SSCH_GATE_BIT, eth->base + SSCH_GATE);
	ret = readl_poll_timeout_atomic(eth->base + SSCH_DONE, status,
					status & BIT(0), 1, 1000);
	if (ret)
		goto restore;
	command = (u32)ram << 22 | index | (write ? 0 : BIT(27));
	command |= readl(eth->base + SSCH_COMMAND) & ~SSCH_COMMAND_MASK;
	writel(command, eth->base + SSCH_COMMAND);
	ret = readl_poll_timeout_atomic(eth->base + SSCH_DONE, status,
					status & BIT(0), 1, 1000);
	if (ret)
		goto restore;
	if (write)
		writel(*value, eth->base + SSCH_DATA);
	else
		*value = readl(eth->base + SSCH_DATA);
restore:
	gate = (readl(eth->base + SSCH_GATE) & ~SSCH_GATE_BIT) |
		(gate & SSCH_GATE_BIT);
	writel(gate, eth->base + SSCH_GATE);
	return ret;
}

int zx279133_native_ssch_global_get(struct zx279133_eth *eth,
				    struct zte_nppt_ssch_global *config)
{
	u32 value;

	if (!config)
		return -EINVAL;
	mutex_lock(&eth->np_ind_lock);
	value = readl(eth->base + ZX279133_SSCH_CFG);
	*config = (struct zte_nppt_ssch_global) {
		.shaping = !!(value & BIT(0)), .dwrr = !!(value & BIT(1)),
		.fill_time = readl(eth->base + ZX279133_SSCH_FILL_TIME) &
			     ZX279133_SSCH_FILL_TIME_MASK,
	};
	mutex_unlock(&eth->np_ind_lock);
	return 0;
}

int zx279133_native_ssch_global_set(struct zx279133_eth *eth,
				    const struct zte_nppt_ssch_global *config)
{
	u32 value;

	if (!config || config->fill_time > ZX279133_SSCH_FILL_TIME_MASK)
		return -EINVAL;
	mutex_lock(&eth->np_ind_lock);
	value = readl(eth->base + ZX279133_SSCH_FILL_TIME);
	writel((value & ~ZX279133_SSCH_FILL_TIME_MASK) | config->fill_time,
	       eth->base + ZX279133_SSCH_FILL_TIME);
	value = readl(eth->base + ZX279133_SSCH_CFG);
	writel((value & ~GENMASK(1, 0)) | (u32)config->shaping |
	       (u32)config->dwrr << 1, eth->base + ZX279133_SSCH_CFG);
	mutex_unlock(&eth->np_ind_lock);
	return 0;
}

static int zx279133_ssch_mode_io(struct zx279133_eth *eth, u8 port, u8 queue,
				 u8 *mode_bit, bool write)
{
	u32 reg, value, bit;

	if (!mode_bit || port > 7 || queue > 7 || (write && *mode_bit > 1))
		return -EINVAL;
	reg = port < 4 ? SSCH_MODE0 : SSCH_MODE1;
	bit = BIT((port % 4) * 8 + queue);
	/* ssch_regtable_init expands descriptor 18 to all 32 bits on CPU133. */
	mutex_lock(&eth->np_ind_lock);
	value = readl(eth->base + reg);
	if (write)
		writel((value & ~bit) | (*mode_bit ? bit : 0), eth->base + reg);
	else
		*mode_bit = !!(value & bit);
	mutex_unlock(&eth->np_ind_lock);
	return 0;
}

int zx279133_native_ssch_mode_get(struct zx279133_eth *eth, u8 port, u8 queue,
				  u8 *mode_bit)
{
	return zx279133_ssch_mode_io(eth, port, queue, mode_bit, false);
}

int zx279133_native_ssch_mode_set(struct zx279133_eth *eth, u8 port, u8 queue,
				  u8 mode_bit)
{
	return zx279133_ssch_mode_io(eth, port, queue, &mode_bit, true);
}

static int zx279133_ssch_weight_io(struct zx279133_eth *eth, u8 port, u8 queue,
				   u32 *weight, bool write)
{
	int ret;

	if (!weight || port > 7 || queue > 7 ||
	    (write && *weight > GENMASK(17, 0)))
		return -EINVAL;
	mutex_lock(&eth->np_ind_lock);
	ret = zx279133_ssch_ind(eth, 0, port * 8 + queue, weight, write);
	mutex_unlock(&eth->np_ind_lock);
	return ret;
}

int zx279133_native_ssch_weight_get(struct zx279133_eth *eth, u8 port, u8 queue,
				    u32 *weight)
{
	return zx279133_ssch_weight_io(eth, port, queue, weight, false);
}

int zx279133_native_ssch_weight_set(struct zx279133_eth *eth, u8 port, u8 queue,
				    u32 weight)
{
	return zx279133_ssch_weight_io(eth, port, queue, &weight, true);
}

static int zx279133_ssch_shaper_io(struct zx279133_eth *eth, u8 port, u8 queue,
				   struct zte_nppt_ssch_shaper *shaper,
				   bool per_queue, bool write)
{
	struct zte_nppt_ssch_shaper result;
	u8 index = per_queue ? port * 8 + queue : port;
	u8 fill_ram = per_queue ? 3 : 1;
	u32 reg, bit, value, fill, cap;
	int ret;

	if (!shaper || port > 7 || queue > 7 ||
	    (write && (shaper->fill > GENMASK(28, 0) ||
		       shaper->cap > GENMASK(20, 0))))
		return -EINVAL;
	reg = per_queue ? (index < 32 ? SSCH_QUEUE_ENABLE0 : SSCH_QUEUE_ENABLE1) :
			 ZX279133_SSCH_CFG;
	bit = per_queue ? BIT(index % 32) : BIT(port + 2);
	mutex_lock(&eth->np_ind_lock);
	value = readl(eth->base + reg);
	if (write) {
		/* OEM queue/port setters quiesce this shaper before replacement. */
		writel(value & ~bit, eth->base + reg);
		fill = shaper->fill;
		cap = shaper->cap;
	} else {
		result.enabled = !!(value & bit);
	}
	ret = zx279133_ssch_ind(eth, fill_ram, index, &fill, write);
	if (ret)
		goto out;
	ret = zx279133_ssch_ind(eth, fill_ram + 1, index, &cap, write);
	if (ret)
		goto out;
	if (write) {
		value = readl(eth->base + reg) & ~bit;
		writel(value | (shaper->enabled ? bit : 0), eth->base + reg);
	} else {
		result.fill = fill;
		result.cap = cap;
		*shaper = result;
	}
out:
	mutex_unlock(&eth->np_ind_lock);
	return ret;
}

int zx279133_native_ssch_queue_get(struct zx279133_eth *eth, u8 port, u8 queue,
				   struct zte_nppt_ssch_shaper *shaper)
{
	return zx279133_ssch_shaper_io(eth, port, queue, shaper, true, false);
}

int zx279133_native_ssch_queue_set(struct zx279133_eth *eth, u8 port, u8 queue,
				   const struct zte_nppt_ssch_shaper *shaper)
{
	struct zte_nppt_ssch_shaper config;

	if (!shaper)
		return -EINVAL;
	config = *shaper;
	return zx279133_ssch_shaper_io(eth, port, queue, &config, true, true);
}

int zx279133_native_ssch_port_get(struct zx279133_eth *eth, u8 port,
				  struct zte_nppt_ssch_shaper *shaper)
{
	return zx279133_ssch_shaper_io(eth, port, 0, shaper, false, false);
}

int zx279133_native_ssch_port_set(struct zx279133_eth *eth, u8 port,
				  const struct zte_nppt_ssch_shaper *shaper)
{
	struct zte_nppt_ssch_shaper config;

	if (!shaper)
		return -EINVAL;
	config = *shaper;
	return zx279133_ssch_shaper_io(eth, port, 0, &config, false, true);
}

int zx279133_native_vlan_get(struct zx279133_eth *eth, u16 vid,
			     struct zte_nppt_vlan_row *row)
{
	if (!row || vid > 4095)
		return -EINVAL;
	return zx279133_native_sdt128_io(eth, 0, vid, row->words, false);
}

int zx279133_native_vlan_set(struct zx279133_eth *eth, u16 vid,
			     const struct zte_nppt_vlan_row *row)
{
	struct zte_nppt_vlan_row data;

	if (!row || vid > 4095)
		return -EINVAL;
	data = *row;
	return zx279133_native_sdt128_io(eth, 0, vid, data.words, true);
}

static bool zx279133_vlan_port_valid(u8 port)
{
	return port <= 7 || (port >= 16 && port <= 39) ||
		(port >= 58 && port <= 63);
}

int zx279133_native_vlan_mode_get(struct zx279133_eth *eth, u16 vid, u8 port,
				  u8 *mode)
{
	struct zte_nppt_vlan_row row;
	int ret;

	if (!mode || !zx279133_vlan_port_valid(port))
		return -EINVAL;
	ret = zx279133_native_vlan_get(eth, vid, &row);
	if (!ret)
		*mode = (row.words[3 - port / 16] >> ((port % 16) * 2)) & 3;
	return ret;
}

int zx279133_native_vlan_mode_set(struct zx279133_eth *eth, u16 vid, u8 port,
				  u8 mode)
{
	struct zte_nppt_vlan_row row;
	u32 shift;
	int ret;

	if (mode > 3 || !zx279133_vlan_port_valid(port))
		return -EINVAL;
	ret = zx279133_native_vlan_get(eth, vid, &row);
	if (ret)
		return ret;
	shift = (port % 16) * 2;
	row.words[3 - port / 16] &= ~(3U << shift);
	row.words[3 - port / 16] |= (u32)mode << shift;
	return zx279133_native_vlan_set(eth, vid, &row);
}

int zx279133_native_pvid_get(struct zx279133_eth *eth, u8 mem, u16 *vid, u8 *prio)
{
	u32 words[2];
	int ret;

	if (!vid || !prio)
		return -EINVAL;
	ret = zx279133_native_spa_io(eth, mem, 1, &words[0], false);
	if (ret)
		return ret;
	ret = zx279133_native_spa_io(eth, mem, 2, &words[1], false);
	if (!ret) {
		*prio = FIELD_GET(GENMASK(27, 25), words[0]);
		*vid = FIELD_GET(GENMASK(29, 18), words[1]);
	}
	return ret;
}

int zx279133_native_pvid_set(struct zx279133_eth *eth, u8 mem, u16 vid, u8 prio)
{
	u32 words[2];
	int ret;

	if (vid > 4095 || prio > 7)
		return -EINVAL;
	ret = zx279133_native_spa_io(eth, mem, 1, &words[0], false);
	if (ret)
		return ret;
	ret = zx279133_native_spa_io(eth, mem, 2, &words[1], false);
	if (ret)
		return ret;
	words[0] = (words[0] & ~GENMASK(27, 25)) | FIELD_PREP(GENMASK(27, 25), prio);
	words[1] = (words[1] & ~GENMASK(29, 18)) | FIELD_PREP(GENMASK(29, 18), vid);
	ret = zx279133_native_spa_io(eth, mem, 1, &words[0], true);
	if (ret)
		return ret;
	return zx279133_native_spa_io(eth, mem, 2, &words[1], true);
}

static bool zx279133_native_port_valid(u8 port)
{
	/* port_mem_id_get is identity for these CPU133 NP indices. */
	return port <= 8 || port == 10 || port == 14 || port == 15 ||
		(port >= 16 && port <= 48) || (port >= 57 && port <= 63);
}

int zx279133_native_invlan_get(struct zx279133_eth *eth, u8 mem, bool *enabled)
{
	u32 word;
	int ret;

	if (!enabled || !zx279133_native_port_valid(mem))
		return -EINVAL;
	ret = zx279133_native_spa_io(eth, mem, 19, &word, false);
	if (!ret)
		*enabled = !!(word & BIT(27));
	return ret;
}

int zx279133_native_invlan_set(struct zx279133_eth *eth, u8 mem, bool enabled)
{
	u32 row[4], word;
	int ret;

	if (!zx279133_native_port_valid(mem))
		return -EINVAL;
	ret = zx279133_native_spa_io(eth, mem, 19, &word, false);
	if (ret)
		return ret;
	ret = zx279133_native_sdt128_io(eth, 0x32, mem, row, false);
	if (ret)
		return ret;
	/* OEM modifies bit 3 of byte 3 of the selector-0x47 word: bit 27. */
	word = (word & ~BIT(27)) | (enabled ? BIT(27) : 0);
	ret = zx279133_native_spa_io(eth, mem, 19, &word, true);
	if (ret)
		return ret;
	if (mem == 0 || mem == 5) {
		ret = zx279133_native_spa_io(eth, mem ? 10 : 14, 19, &word, true);
		if (ret)
			return ret;
	}
	/* OEM mf_port_invlancheck_set also mirrors the whole SPA word to SDT50. */
	row[3] = word;
	return zx279133_native_sdt128_io(eth, 0x32, mem, row, true);
}

/* Restore captured state, including disabled cd_mode=0 and reserved bits.
 * This is intentionally not exposed as a raw-write debug command.
 */
int zx279133_native_profile_words(struct zx279133_eth *eth, u8 id,
				  u32 words[3], bool restore)
{
	unsigned int i;
	int ret;

	if (id >= ZTE_NPPT_PLCR_PROFILES || !words)
		return -EINVAL;
	for (i = 0; i < 3; i++) {
		ret = zx279133_native_plcr_io(eth, PLCR_PROFILE_BASE + id * 4 + i,
					      &words[i], restore);
		if (ret)
			return ret;
	}
	return 0;
}

int zx279133_native_binding_words(struct zx279133_eth *eth, u16 id,
				  u32 words[4], bool restore)
{
	return zx279133_plcr_binding_io(eth, id, words, restore);
}
