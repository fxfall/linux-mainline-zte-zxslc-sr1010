/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ZX279133_NATIVE_H
#define _ZX279133_NATIVE_H

#include <linux/zte_nppt_native.h>

struct zx279133_eth;

int zx279133_ppu_capture(struct zx279133_eth *eth, u16 pc, u8 *me,
			 struct zte_nppt_ppu_context *context);
int zx279133_ppu_vid_probe(struct zx279133_eth *eth, u8 *me,
			   struct zte_nppt_ppu_context *context);

/* Internal backend bridges, not exported as a raw register ABI. */
int zx279133_native_plcr_io(struct zx279133_eth *eth, u32 addr, u32 *value,
			    bool write);
int zx279133_native_eram_io(struct zx279133_eth *eth, u32 block, u32 *data,
			    bool write);
int zx279133_native_sdt128_io(struct zx279133_eth *eth, u32 sdt, u32 index,
			      u32 *data, bool write);
int zx279133_native_spa_io(struct zx279133_eth *eth, u8 mem, u32 word,
			   u32 *data, bool write);

int zx279133_native_plcr_profile_get(struct zx279133_eth *eth,
				     u8 id, struct zte_nppt_plcr_profile *profile);

int zx279133_native_plcr_profile_set(struct zx279133_eth *eth,
				     u8 id, const struct zte_nppt_plcr_profile *profile);

int zx279133_native_plcr_binding_get(struct zx279133_eth *eth,
				     u16 id, struct zte_nppt_plcr_binding *binding);

int zx279133_native_plcr_binding_set(struct zx279133_eth *eth,
				     u16 id, const struct zte_nppt_plcr_binding *binding);

int zx279133_native_plcr_timing_get(struct zx279133_eth *eth,
				    struct zte_nppt_plcr_timing *timing);

int zx279133_native_ssch_global_get(struct zx279133_eth *eth,
				    struct zte_nppt_ssch_global *config);

int zx279133_native_ssch_global_set(struct zx279133_eth *eth,
				    const struct zte_nppt_ssch_global *config);

int zx279133_native_ssch_mode_get(struct zx279133_eth *eth,
				  u8 port, u8 queue, u8 *mode_bit);

int zx279133_native_ssch_mode_set(struct zx279133_eth *eth,
				  u8 port, u8 queue, u8 mode_bit);

int zx279133_native_ssch_weight_get(struct zx279133_eth *eth,
				    u8 port, u8 queue, u32 *weight);

int zx279133_native_ssch_weight_set(struct zx279133_eth *eth,
				    u8 port, u8 queue, u32 weight);

int zx279133_native_ssch_queue_get(struct zx279133_eth *eth,
				   u8 port, u8 queue, struct zte_nppt_ssch_shaper *shaper);

int zx279133_native_ssch_queue_set(struct zx279133_eth *eth,
				   u8 port, u8 queue, const struct zte_nppt_ssch_shaper *shaper);

int zx279133_native_ssch_port_get(struct zx279133_eth *eth,
				  u8 port, struct zte_nppt_ssch_shaper *shaper);

int zx279133_native_ssch_port_set(struct zx279133_eth *eth,
				  u8 port, const struct zte_nppt_ssch_shaper *shaper);

int zx279133_native_vlan_get(struct zx279133_eth *eth,
			     u16 vid, struct zte_nppt_vlan_row *row);

int zx279133_native_vlan_set(struct zx279133_eth *eth,
			     u16 vid, const struct zte_nppt_vlan_row *row);

int zx279133_native_vlan_mode_get(struct zx279133_eth *eth,
				  u16 vid, u8 port, u8 *mode);

int zx279133_native_vlan_mode_set(struct zx279133_eth *eth,
				  u16 vid, u8 port, u8 mode);

int zx279133_native_pvid_get(struct zx279133_eth *eth,
			     u8 mem, u16 *vid, u8 *prio);

int zx279133_native_pvid_set(struct zx279133_eth *eth,
			     u8 mem, u16 vid, u8 prio);

int zx279133_native_invlan_get(struct zx279133_eth *eth,
			       u8 mem, bool *enabled);

int zx279133_native_invlan_set(struct zx279133_eth *eth,
			       u8 mem, bool enabled);

/* Internal exact snapshots: only the meter owner restores its saved words. */
int zx279133_native_profile_words(struct zx279133_eth *eth, u8 id,
				  u32 words[3], bool restore);
int zx279133_native_binding_words(struct zx279133_eth *eth, u16 id,
				  u32 words[4], bool restore);
#endif
