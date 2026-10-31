/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_ZTE_NPPT_NATIVE_H
#define _LINUX_ZTE_NPPT_NATIVE_H

#include <linux/types.h>

struct zte_nppt;

/* Experimental CPU133 hardware primitives, separate from flow capabilities.
 * All instance calls require zte_nppt_begin()/end() or a supplier callback.
 * The exclusive flow client coordinates these shared policy resources. These
 * calls do not allocate profiles, install flows, or translate Linux units.
 * No call is made by probe/open merely because these symbols are present.
 */
#define ZTE_NPPT_NATIVE_API_VERSION 1
#define ZTE_NPPT_PLCR_PROFILES 128
#define ZTE_NPPT_PLCR_FLOWS 4096

/* Passive running-context observation, not an atomic packet snapshot.
 * No instruction/gate/ME control register is written by this API.
 */
#define ZTE_NPPT_PPU_CONTEXT_WORDS 129
struct zte_nppt_ppu_context {
	u32 firmware_crc;
	u32 stage;
	u32 interrupt_mask;
	u32 stopped_final;
	u32 key_bank;
	u32 key[17];
	int key_rc;
	bool captured;
	bool restore_verified;
	bool resume_verified;
	bool mask_restored;
	u32 pc_before;
	u32 pc_after;
	u32 stopped_before;
	u32 stopped_after;
	u32 words[ZTE_NPPT_PPU_CONTEXT_WORDS];
};

int zte_nppt_ppu_context_get(struct zte_nppt *np, u8 me,
			    struct zte_nppt_ppu_context *context);

/* Explicit debug operation: briefly traps a fixed entry/query site, restores
 * the instruction and resumes all contexts trapped by this request.
 */
int zte_nppt_ppu_capture(struct zte_nppt *np, u16 pc, u8 *me,
			 struct zte_nppt_ppu_context *context);
/* Bounded PC139 VID extraction experiment; restores both SRAM blocks. */
int zte_nppt_ppu_vid_probe(struct zte_nppt *np, u8 *me,
			   struct zte_nppt_ppu_context *context);

struct zte_nppt_plcr_profile {
	u32 cir;
	u32 eir;
	u32 cbs;
	u32 ebs;
	u8 cd_mode;
	u8 cf_flag;
	u8 cm_flag;
	u8 pkt_sign;
};

struct zte_nppt_plcr_binding {
	u8 profile;
	bool enabled;
};

struct zte_nppt_plcr_timing {
	u32 time_count;
	u32 packet_length;
	u32 packet_offset;
	u32 loose_length;
};

struct zte_nppt_ssch_global {
	u32 fill_time;
	bool shaping;
	bool dwrr;
};

/* Native token fields; neither fill nor cap is specified in bytes/second. */
struct zte_nppt_ssch_shaper {
	u32 fill;
	u32 cap;
	bool enabled;
};

struct zte_nppt_vlan_row {
	u32 words[4];
};

/* Raw token fields, after the OEM rate conversion, without its silent clamps.
 * The captured OEM setter accepts cd_mode == 2 only; other modes are rejected.
 * Profile writes affect all flows bound to that profile. On a failed multiword
 * write, callers must read back; failure does not imply an unchanged profile.
 */
int zte_nppt_native_plcr_profile_get(struct zte_nppt *np, u8 id,
				     struct zte_nppt_plcr_profile *profile);
int zte_nppt_native_plcr_profile_set(struct zte_nppt *np, u8 id,
				     const struct zte_nppt_plcr_profile *profile);
int zte_nppt_native_plcr_binding_get(struct zte_nppt *np, u16 id,
				     struct zte_nppt_plcr_binding *binding);
/* Like the OEM setter, ERAM-backed writes reset the row's token state. */
int zte_nppt_native_plcr_binding_set(struct zte_nppt *np, u16 id,
				     const struct zte_nppt_plcr_binding *binding);
int zte_nppt_native_plcr_timing_get(struct zte_nppt *np,
				    struct zte_nppt_plcr_timing *timing);

/* Ports/queues are NP SSCH indices, not Linux ifindices or DSA port numbers.
 * mode_bit is the unmodified OEM field (0/1); weight is the native 18-bit word.
 * Shaper replacement disables the target before programming fill/cap. An error
 * can leave it disabled/partly updated; use getters before deciding recovery.
 */
int zte_nppt_native_ssch_global_get(struct zte_nppt *np,
				    struct zte_nppt_ssch_global *config);
int zte_nppt_native_ssch_global_set(struct zte_nppt *np,
				    const struct zte_nppt_ssch_global *config);
int zte_nppt_native_ssch_mode_get(struct zte_nppt *np, u8 port, u8 queue,
				  u8 *mode_bit);
int zte_nppt_native_ssch_mode_set(struct zte_nppt *np, u8 port, u8 queue,
				  u8 mode_bit);
int zte_nppt_native_ssch_weight_get(struct zte_nppt *np, u8 port, u8 queue,
				    u32 *weight);
int zte_nppt_native_ssch_weight_set(struct zte_nppt *np, u8 port, u8 queue,
				    u32 weight);
int zte_nppt_native_ssch_queue_get(struct zte_nppt *np, u8 port, u8 queue,
				   struct zte_nppt_ssch_shaper *shaper);
int zte_nppt_native_ssch_queue_set(struct zte_nppt *np, u8 port, u8 queue,
				   const struct zte_nppt_ssch_shaper *shaper);
int zte_nppt_native_ssch_port_get(struct zte_nppt *np, u8 port,
				  struct zte_nppt_ssch_shaper *shaper);
int zte_nppt_native_ssch_port_set(struct zte_nppt *np, u8 port,
				  const struct zte_nppt_ssch_shaper *shaper);

/* SDT0 control only: this does not add VID to the fast-flow match key. */
int zte_nppt_native_vlan_get(struct zte_nppt *np, u16 vid,
			     struct zte_nppt_vlan_row *row);
int zte_nppt_native_vlan_set(struct zte_nppt *np, u16 vid,
			     const struct zte_nppt_vlan_row *row);
int zte_nppt_native_vlan_mode_get(struct zte_nppt *np, u16 vid, u8 port,
				  u8 *mode);
int zte_nppt_native_vlan_mode_set(struct zte_nppt *np, u16 vid, u8 port,
				  u8 mode);
/* SPA memory indices are deliberately not guessed from Linux port numbers. */
int zte_nppt_native_pvid_get(struct zte_nppt *np, u8 mem, u16 *vid, u8 *prio);
int zte_nppt_native_pvid_set(struct zte_nppt *np, u8 mem, u16 vid, u8 prio);
/* NP port index; includes OEM companion-row updates for ports 0 and 5. */
int zte_nppt_native_invlan_get(struct zte_nppt *np, u8 port, bool *enabled);
int zte_nppt_native_invlan_set(struct zte_nppt *np, u8 port, bool enabled);

/* Managed experimental fast-flow policers. NPU owns global resources;
 * fnoffload owns each lease until the referencing rule is invalidated.
 * All calls require begin/end. A failed put retains the lease for retry.
 * Profile contents are native tokens; this API claims no Linux rate units.
 */
struct zte_nppt_meter;
int zte_nppt_meter_get(struct zte_nppt *np,
		       const struct zte_nppt_plcr_profile *profile,
		       const void *scope, u32 action_index,
		       struct zte_nppt_meter **meter);
int zte_nppt_meter_put(struct zte_nppt *np, struct zte_nppt_meter *meter);
/* Failed installation with no live HW rule: transfer cleanup back to NPU. */
void zte_nppt_meter_abandon(struct zte_nppt *np, struct zte_nppt_meter *meter);
u8 zte_nppt_meter_bucket(const struct zte_nppt_meter *meter);
int zte_nppt_meter_mac_get(struct zte_nppt *np,
			   const struct zte_nppt_plcr_profile *profile,
			   u8 slot, bool download, struct zte_nppt_meter **out);
int zte_nppt_mac_global_get(struct zte_nppt *np, bool *enabled);
int zte_nppt_mac_global_set(struct zte_nppt *np, bool enabled);
#endif
