/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ZX279133_NATIVE_DEBUG_H
#define _ZX279133_NATIVE_DEBUG_H

struct dentry;
struct zte_nppt;

#if IS_ENABLED(CONFIG_ZTE_ZX279133_NATIVE_DEBUG)
struct dentry *zx279133_native_debug_create(struct zte_nppt *np, const char *name);
#else
static inline struct dentry *
zx279133_native_debug_create(struct zte_nppt *np, const char *name)
{
	return NULL;
}
#endif

#endif
