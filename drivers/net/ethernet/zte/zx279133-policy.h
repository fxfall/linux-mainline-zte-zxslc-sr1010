/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ZX279133_POLICY_H
#define _ZX279133_POLICY_H
#include <linux/errno.h>
#include <linux/math64.h>
#include <linux/zte_nppt_native.h>
/* Policy normalization independent of MMIO and Linux object lifetimes. */
enum zx279133_vlan_edit { ZX_VLAN_KEEP, ZX_VLAN_PUSH, ZX_VLAN_POP, ZX_VLAN_REPLACE };

struct zx279133_vlan_plan {
	u16 vid;
	u16 tci;
	u8 edit;
	bool tagged;
};

static inline int zx279133_vlan_match(struct zx279133_vlan_plan *p,
				      bool tagged, u16 vid, u16 mask)
{
	*p = (struct zx279133_vlan_plan) { .tagged = tagged, .vid = vid };
	if (tagged && (mask != 0xfff || vid >= 4095))
		return -EOPNOTSUPP;
	return 0;
}

/* Untagged is assigned the ingress PVID, not a universal VLAN1.
 * Keep the wire tagged flag for ingress strip/egress formatting decisions.
 */
static inline int zx279133_vlan_domain(const struct zx279133_vlan_plan *p,
				       u16 pvid, u16 *domain)
{
	if (p->tagged && p->vid) {
		*domain = p->vid;
		return 0;
	}
	/* VID0 is a priority tag: like untagged, it uses the ingress PVID. */
	if (!pvid || pvid >= 4095)
		return -EINVAL;
	*domain = pvid;
	return 0;
}

static inline int zx279133_vlan_edit(struct zx279133_vlan_plan *p,
				     u8 edit, u16 tci, u16 tpid)
{
	if (p->edit || edit < ZX_VLAN_PUSH || edit > ZX_VLAN_REPLACE ||
	    (edit == ZX_VLAN_PUSH && p->tagged) ||
	    (edit != ZX_VLAN_PUSH && !p->tagged) ||
	    (edit != ZX_VLAN_POP && (tpid != 0x8100 || (tci & 0xfff) >= 4095)))
		return -EOPNOTSUPP;
	p->edit = edit;
	p->tci = tci;
	return 0;
}

/* OEM fast response edit bits. Classification must be checked independently. */
static inline void zx279133_vlan_response(u8 *fast, const struct zx279133_vlan_plan *p)
{
	if (!p->edit)
		return;
	fast[30] = (fast[30] & 0x3f) | p->edit << 6;
	fast[24] = p->tci;
	fast[25] = p->tci >> 8;
	/* Native response abs(delta)/2; POP sign is carried by the edit opcode. */
	fast[16] = p->edit == ZX_VLAN_REPLACE ? 0 : 2;
	fast[17] = 0;
	fast[18] = 0;
	fast[19] = 0;
}

static inline void zx279133_meter_response(u8 *fast, u8 bucket)
{
	fast[19] = (fast[19] & ~0x7c) | (bucket & 31) << 2;
	fast[29] |= 0x20;
}

/* Explicit experimental conversion, not an asserted hardware clock contract.
 * Round the programmed rate down, never silently exceed a Linux request.
 */
static inline int zx279133_police_tokens(u64 bytes_ps, u32 burst,
					 u32 unit_bps, u32 burst_unit,
					 struct zte_nppt_plcr_profile *p)
{
	u64 tokens;

	if (!unit_bps || !burst_unit || !bytes_ps || !burst || bytes_ps > (~0ULL >> 3))
		return -EINVAL;
	tokens = div_u64(bytes_ps * 8, unit_bps);
	if (!tokens || tokens > 0x3ffff || burst % burst_unit ||
	    burst / burst_unit > 0x7ffffff)
		return -ERANGE;
	*p = (struct zte_nppt_plcr_profile) {
		.cir = tokens, .cbs = burst / burst_unit, .cd_mode = 2,
	};
	return 0;
}

#define ZX279133_MAC_CBS_PER_CIR (64U * 26U)
#define ZX279133_MAC_CBS_MAX_RAW 0x7ffffffU

static inline int zx279133_mac_police_tokens(u64 bytes_ps, u32 burst_override,
					     u32 unit_bps, u32 burst_unit,
					     struct zte_nppt_plcr_profile *p)
{
	u64 cbs;
	int ret;

	/* Keep the calibrated CIR and explicit burst conversion unchanged. The
	 * placeholder burst is replaced below when zero selects automatic CBS.
	 */
	ret = zx279133_police_tokens(bytes_ps,
				     burst_override ? burst_override : burst_unit,
				     unit_bps, burst_unit, p);
	if (ret || burst_override)
		return ret;
	/* OEM CPU133, byte mode, time_cnt1=0: CIR=floor(R/64), CBS=26*R.
	 * Reconstruct the lowest R for this raw CIR instead of treating the
	 * Linux bytes/s request as the OEM API unit. Saturate as its setter does.
	 * These are raw CBS tokens, independent of the explicit byte override.
	 */
	cbs = (u64)p->cir * ZX279133_MAC_CBS_PER_CIR;
	p->cbs = cbs > ZX279133_MAC_CBS_MAX_RAW ?
		ZX279133_MAC_CBS_MAX_RAW : (u32)cbs;
	return 0;
}
#endif
