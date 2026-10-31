/* SPDX-License-Identifier: GPL-2.0-only */
/* Translator-owned counter leases, not connection state. offload->lock held.
 * Group deltas are exported separately from per-connection flow_stats bytes.
 */
struct zx279133_stat_key {
	const void *owner;
	const void *domain;
	const void *src;
	const void *dst;
	u32 path[4];
	u32 frame_bytes;
};

struct zx279133_stat_group {
	struct hlist_node node;
	struct zx279133_stat_key key;
	struct flow_stats_scope scope;
	u64 packets;
	u64 bytes;
	u64 attempted_epoch;
	u32 refs;
	u16 id;
	int read_error;
	bool attempted;
};

static void zx279133_stat_merge(struct flow_stats *to, const struct flow_stats *from)
{
	flow_stats_update(to, from->bytes, from->pkts, from->drops,
			  from->lastused, FLOW_ACTION_HW_STATS_DELAYED);
}

static int zx279133_stat_group_get(struct zx279133_flow_offload *o,
				  struct zx279133_flow_entry *entry,
				  const struct flow_stats_scope *scope)
{
	struct zx279133_stat_key key = {};
	struct zx279133_stat_group *g;
	u32 hash;
	int ret;

	key.owner = scope->owner;
	key.domain = scope->domain;
	key.src = scope->src;
	key.dst = scope->dst;
	memcpy(key.path, scope->path, sizeof(key.path));
	key.frame_bytes = ETH_HLEN + ETH_FCS_LEN +
		(entry->pppoe ? PPPOE_SES_HLEN : 0) +
		(entry->wan_vlan ? VLAN_HLEN : 0);
	hash = jhash(&key, sizeof(key), 0);
	hash_for_each_possible(o->stat_groups, g, node, hash) {
		if (memcmp(&g->key, &key, sizeof(key)))
			continue;
		if (g->refs == U32_MAX)
			return -EOVERFLOW;
		g->refs++;
		entry->stat_group = g;
		entry->stat = g->id;
		entry->has_stat = true;
		return 0;
	}
	g = kzalloc(sizeof(*g), GFP_KERNEL);
	if (!g)
		return -ENOMEM;
	ret = zx279133_fast_index_alloc(o->stat_used, ZX279133_FAST_STAT_DEPTH, &g->id);
	if (ret)
		goto free;
	ret = zte_nppt_stats_read(o->np, g->id, &g->packets, &g->bytes);
	if (ret) {
		__clear_bit(g->id, o->stat_used);
		goto free;
	}
	memcpy(&g->key, &key, sizeof(key));
	g->refs = 1;
	g->scope = *scope;
	g->scope.get(&g->scope);
	hash_add(o->stat_groups, &g->node, hash);
	o->stat_group_count++;
	entry->stat_group = g;
	entry->stat = g->id;
	entry->has_stat = true;
	return 0;
free:
	kfree(g);
	return ret;
}

/* Caller holds the NPU transaction and offload->lock. One read per group,
 * independent of the number of rules pointing at it. */
static int zx279133_stat_group_read(struct zx279133_flow_offload *o,
				    struct zx279133_stat_group *g, bool final)
{
	u64 epoch = div_u64(get_jiffies_64(), 3 * HZ);
	u64 packets, bytes, delta_packets, delta_bytes, frame_bytes;
	int ret;

	if (!final && g->attempted && g->attempted_epoch == epoch)
		return g->read_error;
	ret = zte_nppt_stats_read(o->np, g->id, &packets, &bytes);
	if (!ret && (packets < g->packets || bytes < g->bytes))
		ret = -EIO;
	g->attempted = true;
	g->attempted_epoch = epoch;
	g->read_error = ret;
	if (ret)
		return ret;
	delta_packets = packets - g->packets;
	delta_bytes = bytes - g->bytes;
	frame_bytes = delta_packets * g->key.frame_bytes;
	delta_bytes = delta_bytes > frame_bytes ? delta_bytes - frame_bytes : 0;
	g->scope.account(&g->scope, delta_packets, delta_bytes);
	g->packets = packets;
	g->bytes = bytes;
	return 0;
}

static int zx279133_stat_group_collect(struct zx279133_flow_offload *o,
				      struct zx279133_flow_entry *entry,
				      struct flow_stats *stats, bool final)
{
	struct zx279133_stat_group *g = entry->stat_group;

	flow_stats_update(stats, 0, 0, 0, entry->lastused, FLOW_ACTION_HW_STATS_DELAYED);
	/* Group counters are polled by the flowtable batch, not age callbacks.
	 * The last owner settles the final bytes before releasing the counter. */
	if (!final || g->refs > 1)
		return 0;
	return zx279133_stat_group_read(o, g, true);
}

static int zx279133_stat_groups_collect(struct zx279133_flow_offload *o,
				       const void *domain)
{
	struct zx279133_stat_group *g;
	unsigned int bucket;
	int ret, error = 0;

	mutex_lock(&o->lock);
	hash_for_each(o->stat_groups, bucket, g, node) {
		if (g->key.domain != domain)
			continue;
		ret = zx279133_stat_group_read(o, g, false);
		if (ret)
			error = ret;
	}
	mutex_unlock(&o->lock);
	return error;
}

static void zx279133_stat_put(struct zx279133_flow_offload *o,
			      struct zx279133_flow_entry *entry)
{
	struct zx279133_stat_group *g = entry->stat_group;

	if (g) {
		if (!--g->refs) {
			hash_del(&g->node);
			__clear_bit(g->id, o->stat_used);
			o->stat_group_count--;
			g->scope.put(&g->scope);
			kfree(g);
		}
		entry->stat_group = NULL;
	} else if (entry->has_stat) {
		__clear_bit(entry->stat, o->stat_used);
	}
	entry->has_stat = false;
}
