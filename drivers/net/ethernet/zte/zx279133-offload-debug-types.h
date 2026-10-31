/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ZX279133_OFFLOAD_DEBUG_TYPES_H
#define _ZX279133_OFFLOAD_DEBUG_TYPES_H

#ifdef CONFIG_DEBUG_FS
#define ZX279133_DIAG_EVENTS 16
struct zx279133_diag_event {
	u64 sequence;
	unsigned long stamp;
	unsigned long cookie;
	int command;
	int result;
	bool input_truncated;
	char reason[128];
	char input[512];
};

struct zx279133_diag {
	struct dentry *dir;
	unsigned long cookie;
	unsigned long expires;
	u32 remaining;
	u32 next;
	u32 count;
	u64 sequence;
	bool all;
	struct zx279133_diag_event *events;
};
#endif
#endif
