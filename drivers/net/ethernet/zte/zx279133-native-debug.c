// SPDX-License-Identifier: GPL-2.0-only
/* On-demand native NP experiments. No raw register ABI or background work. */
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/zte_nppt_offload.h>
#include <linux/zte_nppt_native.h>

#include "zx279133-native-debug.h"

enum native_target {
	NATIVE_PROFILE, NATIVE_BINDING, NATIVE_TIMING, NATIVE_GLOBAL,
	NATIVE_MODE, NATIVE_WEIGHT, NATIVE_QUEUE, NATIVE_PORT,
	NATIVE_VLAN, NATIVE_VLAN_MODE, NATIVE_PVID, NATIVE_INVLAN,
	NATIVE_PPU_CONTEXT, NATIVE_PPU_CAPTURE, NATIVE_PPU_VID_PROBE,
};

struct native_command {
	const char *name;
	u8 keys;
	u8 values;
	u32 max[9];
};

/* Limits are checked as u32, before narrowing arguments to native API types. */
static const struct native_command native_commands[] = {
	[NATIVE_PROFILE] = { "profile", 1, 8,
		{ 127, 0x3ffff, 0x3ffff, 0x7ffffff, 0x7ffffff, 2, 1, 1, 1 } },
	[NATIVE_BINDING] = { "binding", 1, 2, { 4095, 127, 1 } },
	[NATIVE_TIMING] = { "timing", 0, 4 },
	[NATIVE_GLOBAL] = { "global", 0, 3, { 0x3ffff, 1, 1 } },
	[NATIVE_MODE] = { "mode", 2, 1, { 7, 7, 1 } },
	[NATIVE_WEIGHT] = { "weight", 2, 1, { 7, 7, 0x3ffff } },
	[NATIVE_QUEUE] = { "queue", 2, 3, { 7, 7, 0x1fffffff, 0x1fffff, 1 } },
	[NATIVE_PORT] = { "port", 1, 3, { 7, 0x1fffffff, 0x1fffff, 1 } },
	[NATIVE_VLAN] = { "vlan", 1, 4, { 4095, U32_MAX, U32_MAX, U32_MAX, U32_MAX } },
	[NATIVE_VLAN_MODE] = { "vlan-mode", 2, 1, { 4095, 63, 3 } },
	[NATIVE_PVID] = { "pvid", 1, 2, { 64, 4095, 7 } },
	[NATIVE_INVLAN] = { "invlan", 1, 1, { 63, 1 } },
	[NATIVE_PPU_CONTEXT] = { "ppu-context", 1, 0, { 7 } },
	[NATIVE_PPU_CAPTURE] = { "ppu-capture", 1, 0, { 3406 } },
	[NATIVE_PPU_VID_PROBE] = { "ppu-vid-probe", 0, 0 },
};

static int native_parse(char *text, unsigned int *target, bool *write, u32 *v)
{
	const struct native_command *cmd;
	char *argv[12], *token;
	unsigned int argc = 0, i, count;
	int ret;

	while ((token = strsep(&text, " \t\r\n"))) {
		if (!*token)
			continue;
		if (argc == ARRAY_SIZE(argv))
			return -E2BIG;
		argv[argc++] = token;
	}
	if (argc < 2)
		return -EINVAL;
	if (!strcmp(argv[0], "get"))
		*write = false;
	else if (!strcmp(argv[0], "set"))
		*write = true;
	else
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(native_commands); i++)
		if (!strcmp(argv[1], native_commands[i].name))
			break;
	if (i == ARRAY_SIZE(native_commands))
		return -EOPNOTSUPP;
	*target = i;
	cmd = &native_commands[i];
	if ((i == NATIVE_PPU_CAPTURE || i == NATIVE_PPU_VID_PROBE) && !*write)
		return -EOPNOTSUPP;
	if (*write && (i == NATIVE_TIMING || i == NATIVE_PPU_CONTEXT))
		return -EOPNOTSUPP;
	count = cmd->keys + (*write ? cmd->values : 0);
	if (argc != count + 2)
		return -EINVAL;
	for (i = 0; i < count; i++) {
		ret = kstrtou32(argv[i + 2], 0, &v[i]);
		if (ret)
			return ret;
		if (v[i] > cmd->max[i])
			return -ERANGE;
	}
	return 0;
}

/* The same dispatcher is used for a requested write and its separate readback. */
static int native_run(struct zte_nppt *np, unsigned int target, bool write, u32 *v)
{
	int ret;

	switch (target) {
	case NATIVE_PROFILE: {
		struct zte_nppt_plcr_profile p = {
			.cir = v[1], .eir = v[2], .cbs = v[3], .ebs = v[4],
			.cd_mode = v[5], .cf_flag = v[6], .cm_flag = v[7], .pkt_sign = v[8],
		};

		if (write)
			return zte_nppt_native_plcr_profile_set(np, v[0], &p);
		ret = zte_nppt_native_plcr_profile_get(np, v[0], &p);
		v[1] = p.cir;
		v[2] = p.eir;
		v[3] = p.cbs;
		v[4] = p.ebs;
		v[5] = p.cd_mode;
		v[6] = p.cf_flag;
		v[7] = p.cm_flag;
		v[8] = p.pkt_sign;
		return ret;
	}
	case NATIVE_BINDING: {
		struct zte_nppt_plcr_binding b = { .profile = v[1], .enabled = v[2] };

		if (write)
			return zte_nppt_native_plcr_binding_set(np, v[0], &b);
		ret = zte_nppt_native_plcr_binding_get(np, v[0], &b);
		v[1] = b.profile;
		v[2] = b.enabled;
		return ret;
	}
	case NATIVE_TIMING: {
		struct zte_nppt_plcr_timing t = {};

		ret = zte_nppt_native_plcr_timing_get(np, &t);
		v[0] = t.time_count;
		v[1] = t.packet_length;
		v[2] = t.packet_offset;
		v[3] = t.loose_length;
		return ret;
	}
	case NATIVE_GLOBAL: {
		struct zte_nppt_ssch_global g = {
			.fill_time = v[0], .shaping = v[1], .dwrr = v[2],
		};

		if (write)
			return zte_nppt_native_ssch_global_set(np, &g);
		ret = zte_nppt_native_ssch_global_get(np, &g);
		v[0] = g.fill_time;
		v[1] = g.shaping;
		v[2] = g.dwrr;
		return ret;
	}
	case NATIVE_MODE: {
		u8 mode = v[2];

		if (write)
			return zte_nppt_native_ssch_mode_set(np, v[0], v[1], mode);
		ret = zte_nppt_native_ssch_mode_get(np, v[0], v[1], &mode);
		v[2] = mode;
		return ret;
	}
	case NATIVE_WEIGHT:
		if (write)
			return zte_nppt_native_ssch_weight_set(np, v[0], v[1], v[2]);
		return zte_nppt_native_ssch_weight_get(np, v[0], v[1], &v[2]);
	case NATIVE_QUEUE:
	case NATIVE_PORT: {
		unsigned int k = native_commands[target].keys;
		struct zte_nppt_ssch_shaper s = {
			.fill = v[k], .cap = v[k + 1], .enabled = v[k + 2],
		};

		if (target == NATIVE_QUEUE) {
			if (write)
				return zte_nppt_native_ssch_queue_set(np, v[0], v[1], &s);
			ret = zte_nppt_native_ssch_queue_get(np, v[0], v[1], &s);
		} else {
			if (write)
				return zte_nppt_native_ssch_port_set(np, v[0], &s);
			ret = zte_nppt_native_ssch_port_get(np, v[0], &s);
		}
		v[k] = s.fill;
		v[k + 1] = s.cap;
		v[k + 2] = s.enabled;
		return ret;
	}
	case NATIVE_VLAN: {
		struct zte_nppt_vlan_row row = { .words = { v[1], v[2], v[3], v[4] } };

		if (write)
			return zte_nppt_native_vlan_set(np, v[0], &row);
		ret = zte_nppt_native_vlan_get(np, v[0], &row);
		memcpy(v + 1, row.words, sizeof(row.words));
		return ret;
	}
	case NATIVE_VLAN_MODE: {
		u8 mode = v[2];

		if (write)
			return zte_nppt_native_vlan_mode_set(np, v[0], v[1], mode);
		ret = zte_nppt_native_vlan_mode_get(np, v[0], v[1], &mode);
		v[2] = mode;
		return ret;
	}
	case NATIVE_PVID: {
		u16 vid = v[1];
		u8 prio = v[2];

		if (write)
			return zte_nppt_native_pvid_set(np, v[0], vid, prio);
		ret = zte_nppt_native_pvid_get(np, v[0], &vid, &prio);
		v[1] = vid;
		v[2] = prio;
		return ret;
	}
	case NATIVE_INVLAN: {
		bool enabled = v[1];

		if (write)
			return zte_nppt_native_invlan_set(np, v[0], enabled);
		ret = zte_nppt_native_invlan_get(np, v[0], &enabled);
		v[1] = enabled;
		return ret;
	}
	default:
		return -EOPNOTSUPP;
	}
}

static bool native_can_restore(unsigned int target, const u32 *v)
{
	const struct native_command *cmd = &native_commands[target];
	unsigned int i;

	if (target == NATIVE_TIMING || (target == NATIVE_PROFILE && v[5] != 2))
		return false;
	for (i = 0; i < cmd->keys + cmd->values; i++)
		if (v[i] > cmd->max[i])
			return false;
	return true;
}

struct native_debug_file {
	struct zte_nppt *np;
	/* Serializes this fd's command, response and response length. */
	struct mutex lock;
	char result[4096];
	size_t length;
};

static int native_debug_open(struct inode *inode, struct file *file)
{
	struct native_debug_file *state;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	state->np = inode->i_private;
	zte_nppt_get(state->np);
	mutex_init(&state->lock);
	state->length = scnprintf(state->result, sizeof(state->result),
				  "rc=0 native_api=%u request_required=1\n",
				  ZTE_NPPT_NATIVE_API_VERSION);
	file->private_data = state;
	return nonseekable_open(inode, file);
}

static int native_debug_release(struct inode *inode, struct file *file)
{
	struct native_debug_file *state = file->private_data;

	zte_nppt_put(state->np);
	kfree(state);
	return 0;
}

static ssize_t native_debug_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct native_debug_file *state = file->private_data;
	ssize_t ret;

	mutex_lock(&state->lock);
	ret = simple_read_from_buffer(buf, count, ppos, state->result, state->length);
	mutex_unlock(&state->lock);
	return ret;
}

static ssize_t native_debug_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct native_debug_file *state = file->private_data;
	const struct native_command *cmd;
	u32 v[9] = {};
	unsigned int target = 0, i;
	bool write = false, attempted = false;
	char text[256];
	int ret, write_ret = -ECANCELED;
	size_t len;

	if (!count || count >= sizeof(text))
		return -E2BIG;
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (copy_from_user(text, buf, count))
		return -EFAULT;
	/* Embedded NULs must not conceal trailing commands/arguments. */
	if (memchr(text, '\0', count))
		return -EINVAL;
	text[count] = '\0';
	mutex_lock(&state->lock);
	if (!strcmp(strim(text), "info")) {
		struct zte_nppt_info info;

		ret = zte_nppt_try_begin(state->np);
		if (ret)
			goto error;
		zte_nppt_get_info(state->np, &info);
		zte_nppt_vlan_status(state->np, &v[0], &v[1], &v[2]);
		zte_nppt_end(state->np);
		len = scnprintf(state->result, sizeof(state->result),
				"rc=0 native_api=%u ready=%u generation=%llu flow_api=%u capabilities=%#llx ppu_version_valid=%u ppu_major=%#x ppu_minor=%#x write_completion_verified=%u semantics=native readback_proves_effect=0 ppu_context_read=1 ppu_query_capture=1 capture_wait_ms=100 ppu_query_key_read=1 capture_mask_restore=1 ppu_vid_key_probe=1 vid_key_active=%u vlan_rows=%u vlan_users=%u vlan_uncertain=%u\n",
				ZTE_NPPT_NATIVE_API_VERSION, info.ready, info.generation,
				info.api_version, info.capabilities, info.ppu_version_valid,
				info.ppu_version_major, info.ppu_version_minor,
				info.write_completion_verified,
				!!(info.capabilities & ZTE_NPPT_CAP_LAN_VID_KEY),
				v[0], v[1], v[2]);
		goto done;
	}
	ret = native_parse(text, &target, &write, v);
	if (ret)
		goto error;
	if (write && !capable(CAP_SYS_RAWIO)) {
		ret = -EPERM;
		goto error;
	}
	/* Nonblocking acquisition avoids teardown/debugfs-removal lock cycles. */
	ret = zte_nppt_try_begin(state->np);
	if (ret)
		goto error;
	if (target == NATIVE_PPU_CONTEXT || target == NATIVE_PPU_CAPTURE ||
	    target == NATIVE_PPU_VID_PROBE) {
		struct zte_nppt_ppu_context *context;
		u8 me = target == NATIVE_PPU_VID_PROBE ? 0xff : v[0];
		bool valid_stopped = false;

		context = kzalloc(sizeof(*context), GFP_KERNEL);
		if (!context) {
			zte_nppt_end(state->np);
			ret = -ENOMEM;
			goto error;
		}
		attempted = write;
		if (target == NATIVE_PPU_VID_PROBE)
			ret = zte_nppt_ppu_vid_probe(state->np, &me, context);
		else if (target == NATIVE_PPU_CAPTURE)
			ret = zte_nppt_ppu_capture(state->np, v[0], &me, context);
		else
			ret = zte_nppt_ppu_context_get(state->np, me, context);
		if (write)
			write_ret = ret;
		zte_nppt_end(state->np);
		if (me < 8)
			valid_stopped = (context->stopped_before & context->stopped_after &
					 BIT(me)) && context->pc_before == context->pc_after &&
					 context->pc_before < 12288;
		len = scnprintf(state->result, sizeof(state->result),
				"rc=%d target=%s me=%u firmware_crc=%#x pc_before=%u pc_after=%u stopped_before=%#x stopped_after=%#x trapped=%u restore_verified=%u resume_verified=%u stage=%u int_mask=%#x stopped_final=%#x key_rc=%d key_bank=%u mask_restored=%u pc_valid_stopped=%u atomic=0 restore_supported=0\n",
				ret, native_commands[target].name, me, context->firmware_crc,
				context->pc_before, context->pc_after,
				context->stopped_before, context->stopped_after,
				context->captured, context->restore_verified,
				context->resume_verified, context->stage,
				context->interrupt_mask, context->stopped_final,
				context->key_rc, context->key_bank,
				context->mask_restored, valid_stopped);
		if (ret)
			goto context_done;
		for (i = 0; i < ARRAY_SIZE(context->words); i++)
			len += scnprintf(state->result + len, sizeof(state->result) - len,
					 "w%u=%08x%s", i, context->words[i],
					 (i + 1) % 8 ? " " : "\n");
		len += scnprintf(state->result + len, sizeof(state->result) - len, "\n");
		if (!context->key_rc)
			for (i = 0; i < ARRAY_SIZE(context->key); i++)
				len += scnprintf(state->result + len, sizeof(state->result) - len,
						 "k%u=%08x%s", i, context->key[i],
						 (i + 1) % 8 ? " " : "\n");
context_done:
		kfree(context);
		goto done;
	}
	attempted = write;
	ret = native_run(state->np, target, write, v);
	if (write) {
		write_ret = ret;
		if (!ret)
			ret = native_run(state->np, target, false, v);
	}
	zte_nppt_end(state->np);
	if (ret)
		goto error;
	cmd = &native_commands[target];
	len = scnprintf(state->result, sizeof(state->result),
			"rc=0 op=%s target=%s keys=", write ? "set" : "get", cmd->name);
	for (i = 0; i < cmd->keys; i++)
		len += scnprintf(state->result + len, sizeof(state->result) - len,
				 "%s%u", i ? "," : "", v[i]);
	len += scnprintf(state->result + len, sizeof(state->result) - len, " values=");
	for (i = 0; i < cmd->values; i++)
		len += scnprintf(state->result + len, sizeof(state->result) - len,
				 "%s%u", i ? "," : "", v[cmd->keys + i]);
	len += scnprintf(state->result + len, sizeof(state->result) - len,
			 " restore_supported=%u\n", native_can_restore(target, v));
	goto done;
error:
	len = scnprintf(state->result, sizeof(state->result),
			"rc=%d write_requested=%u write_rc=%d state_may_have_changed=%u\n",
			ret, write, write_ret, attempted);
done:
	state->length = len;
	*ppos = 0;
	mutex_unlock(&state->lock);
	/* Errors are returned in the per-open response, read using the same fd. */
	return count;
}

static const struct file_operations native_debug_fops = {
	.owner = THIS_MODULE,
	.open = native_debug_open,
	.release = native_debug_release,
	.read = native_debug_read,
	.write = native_debug_write,
};

struct dentry *zx279133_native_debug_create(struct zte_nppt *np, const char *name)
{
	struct dentry *dir;
	char dirname[96];

	snprintf(dirname, sizeof(dirname), "zte-npu-%s", name);
	dir = debugfs_create_dir(dirname, NULL);
	if (!IS_ERR(dir))
		debugfs_create_file("native", 0600, dir, np, &native_debug_fops);
	return dir;
}
