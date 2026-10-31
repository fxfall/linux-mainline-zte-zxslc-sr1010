/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after the translator helpers; owns no independent flow state. */
#ifdef CONFIG_DEBUG_FS
enum zx279133_diag_op { DIAG_SUMMARY, DIAG_LIST, DIAG_FLOW, DIAG_EXPLAIN,
	DIAG_EVENTS, DIAG_WATCH, DIAG_OFF, DIAG_CLIENTS, DIAG_CLIENT_SET };
struct zx279133_diag_request {
	enum zx279133_diag_op op;
	unsigned long cookie;
	u32 seconds;
	u32 budget;
	bool all;
	bool live;
	u8 mac[ETH_ALEN];
	u64 upload;
	u64 download;
	u32 burst_bytes;
};

static int zx279133_diag_parse(char *text, struct zx279133_diag_request *r)
{
	char *argv[5], *token;
	unsigned int argc = 0;

	*r = (struct zx279133_diag_request) { .seconds = 30, .budget = 16 };
	while ((token = strsep(&text, " \t\n\r"))) {
		if (!*token)
			continue;
		if (argc == ARRAY_SIZE(argv))
			return -E2BIG;
		argv[argc++] = token;
	}
	if (!argc)
		return -EINVAL;
	if (!strcmp(argv[0], "client-limits") && argc == 1) {
		r->op = DIAG_CLIENTS;
	} else if (!strcmp(argv[0], "client-set") &&
		   (argc == 4 || argc == 5)) {
		r->op = DIAG_CLIENT_SET;
		r->live = true;
		r->burst_bytes = ZX279133_CLIENT_CBS_DEFAULT;
		if (!mac_pton(argv[1], r->mac) || !is_valid_ether_addr(r->mac) ||
		    kstrtou64(argv[2], 10, &r->upload) ||
		    kstrtou64(argv[3], 10, &r->download) ||
		    (argc == 5 && kstrtou32(argv[4], 10, &r->burst_bytes)))
			return -EINVAL;
	} else if (!strcmp(argv[0], "summary") && argc == 1) {
		r->op = DIAG_SUMMARY;
	} else if (!strcmp(argv[0], "events") && argc == 1) {
		r->op = DIAG_EVENTS;
	} else if (!strcmp(argv[0], "trace-off") && argc == 1) {
		r->op = DIAG_OFF;
	} else if (!strcmp(argv[0], "flows") && argc == 3) {
		r->op = DIAG_LIST;
		if (kstrtoul(argv[1], 0, &r->cookie) ||
		    kstrtou32(argv[2], 0, &r->budget) || !r->budget || r->budget > 64)
			return -EINVAL;
	} else if ((!strcmp(argv[0], "flow") || !strcmp(argv[0], "explain")) &&
		   (argc == 2 || argc == 3)) {
		r->op = !strcmp(argv[0], "flow") ? DIAG_FLOW : DIAG_EXPLAIN;
		if (kstrtoul(argv[1], 0, &r->cookie))
			return -EINVAL;
		if (argc == 3) {
			if (r->op != DIAG_FLOW || strcmp(argv[2], "live"))
				return -EINVAL;
			r->live = true;
		}
	} else if (!strcmp(argv[0], "watch") && argc >= 2 && argc <= 4) {
		r->op = DIAG_WATCH;
		r->all = !strcmp(argv[1], "all");
		if (!r->all && kstrtoul(argv[1], 0, &r->cookie))
			return -EINVAL;
		if (argc >= 3 && kstrtou32(argv[2], 0, &r->seconds))
			return -EINVAL;
		if (argc == 4 && kstrtou32(argv[3], 0, &r->budget))
			return -EINVAL;
		if (!r->seconds || r->seconds > 60 || !r->budget ||
		    r->budget > ZX279133_DIAG_EVENTS)
			return -ERANGE;
	} else {
		return -EINVAL;
	}
	return 0;
}

static bool zx279133_diag_matches(struct zx279133_diag *d,
				  unsigned long cookie, unsigned long now)
{
	if (!d->remaining)
		return false;
	if (time_after_eq(now, d->expires)) {
		WRITE_ONCE(d->remaining, 0);
		return false;
	}
	return d->all || d->cookie == cookie;
}

static void zx279133_diag_input(struct zx279133_diag_event *event,
				struct flow_cls_offload *f)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_action_entry *act;
	size_t n;
	int i;

	n = scnprintf(event->input, sizeof(event->input),
		      "keys=%#llx chain=%u actions=%u",
		      (unsigned long long)rule->match.dissector->used_keys,
		      f->common.chain_index, rule->action.num_entries);
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs a;

		flow_rule_match_ipv4_addrs(rule, &a);
		n += scnprintf(event->input + n, sizeof(event->input) - n,
			       " ipv4=%pI4->%pI4 masks=%pI4/%pI4",
			       &a.key->src, &a.key->dst, &a.mask->src, &a.mask->dst);
	} else if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs a;

		flow_rule_match_ipv6_addrs(rule, &a);
		n += scnprintf(event->input + n, sizeof(event->input) - n,
			       " ipv6=%pI6c->%pI6c masks=%pI6c/%pI6c",
			       &a.key->src, &a.key->dst, &a.mask->src, &a.mask->dst);
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports p;

		flow_rule_match_ports(rule, &p);
		n += scnprintf(event->input + n, sizeof(event->input) - n,
			       " ports=%u->%u masks=%#x/%#x", be16_to_cpu(p.key->src),
			       be16_to_cpu(p.key->dst), be16_to_cpu(p.mask->src),
			       be16_to_cpu(p.mask->dst));
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan vlan;

		flow_rule_match_vlan(rule, &vlan);
		n += scnprintf(event->input + n, sizeof(event->input) - n,
			       " ingress_vid=%u vid_mask=%u", vlan.key->vlan_id,
			       vlan.mask->vlan_id);
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan vlan;

		flow_rule_match_cvlan(rule, &vlan);
		n += scnprintf(event->input + n, sizeof(event->input) - n,
			       " ingress_cvid=%u cvid_mask=%u", vlan.key->vlan_id,
			       vlan.mask->vlan_id);
	}
	flow_action_for_each(i, act, &rule->action) {
		if (i >= 12 || n >= sizeof(event->input) - 100) {
			event->input_truncated = true;
			scnprintf(event->input + n, sizeof(event->input) - n, " truncated=1");
			break;
		}
		n += scnprintf(event->input + n, sizeof(event->input) - n,
			       " a%d=%u", i, act->id);
		if (act->id == FLOW_ACTION_MANGLE)
			n += scnprintf(event->input + n, sizeof(event->input) - n,
				       ":mangle(%u,%u,%#x,%#x)", act->mangle.htype,
				       act->mangle.offset, act->mangle.mask, act->mangle.val);
		else if (act->id == FLOW_ACTION_REDIRECT && act->dev)
			n += scnprintf(event->input + n, sizeof(event->input) - n,
				       ":redirect(%s,%d)", act->dev->name, act->dev->ifindex);
		else if (act->id == FLOW_ACTION_VLAN_PUSH || act->id == FLOW_ACTION_VLAN_MANGLE)
			n += scnprintf(event->input + n, sizeof(event->input) - n,
				       ":vlan(%u,%u,%#x)", act->vlan.vid, act->vlan.prio,
				       be16_to_cpu(act->vlan.proto));
		else if (act->id == FLOW_ACTION_POLICE)
			n += scnprintf(event->input + n, sizeof(event->input) - n,
				       ":police(rate_Bps=%llu,burst=%u,exceed=%u,conform=%u)",
				       act->police.rate_bytes_ps, act->police.burst,
				       act->police.exceed.act_id, act->police.notexceed.act_id);
		else if (act->id == FLOW_ACTION_PPPOE_PUSH)
			n += scnprintf(event->input + n, sizeof(event->input) - n,
				       ":pppoe(%u)", act->pppoe.sid);
		else if (act->id == FLOW_ACTION_PRIORITY)
			n += scnprintf(event->input + n, sizeof(event->input) - n,
				       ":priority(%u)", act->priority);
	}
}

static void zx279133_diag_record(struct zx279133_flow_offload *offload,
				 struct flow_cls_offload *f, int ret)
{
	struct zx279133_diag *d = &offload->diag;
	struct zx279133_diag_event *event;

	/* Control callbacks only, never packets; disabled by default. */
	if (!READ_ONCE(d->remaining) || (f->command == FLOW_CLS_STATS && !ret))
		return;
	mutex_lock(&offload->lock);
	if (!zx279133_diag_matches(d, f->cookie, jiffies))
		goto out;
	event = &d->events[d->next];
	memset(event, 0, sizeof(*event));
	event->sequence = ++d->sequence;
	event->stamp = jiffies;
	event->cookie = f->cookie;
	event->command = f->command;
	event->result = ret;
	strscpy(event->reason, ret && f->common.extack && f->common.extack->_msg ?
		f->common.extack->_msg : ret ? "no_extack_reason" : "ok",
		sizeof(event->reason));
	if (f->command == FLOW_CLS_REPLACE)
		zx279133_diag_input(event, f);
	d->next = (d->next + 1) % ZX279133_DIAG_EVENTS;
	d->count = min_t(u32, d->count + 1, ZX279133_DIAG_EVENTS);
	WRITE_ONCE(d->remaining, d->remaining - 1);
out:
	mutex_unlock(&offload->lock);
}

struct zx279133_diag_file {
	struct zx279133_flow_offload *offload;
	/* Protects per-open command response and length. */
	struct mutex lock;
	size_t used;
	char output[16384];
};

static __printf(2, 3) void zx279133_diag_print(struct zx279133_diag_file *s,
					       const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	s->used += vscnprintf(s->output + s->used, sizeof(s->output) - s->used, fmt, args);
	va_end(args);
}

static void zx279133_diag_entry(struct zx279133_diag_file *s,
				struct zx279133_flow_entry *e, bool live)
{
	struct zx279133_flow_offload *o = s->offload;
	struct zx279133_flow_entry *peer;
	const struct zx279133_flow_spec *p = &e->spec;
	u8 fast[ZX279133_FAST_DATA_SIZE];
	u32 table[ZX279133_ZCAM_ENTRY_SIZE / sizeof(u32)] = {};
	u64 packets = 0, bytes = 0;
	int ret;

	peer = e->upstream ? rhashtable_lookup_fast(&o->key_flows, e->reply_key,
						   zx279133_flow_key_ht_params) :
		rhashtable_lookup_fast(&o->reply_flows, e->key, zx279133_flow_reply_ht_params);
	if (peer == e)
		peer = NULL;
	zx279133_diag_print(s, "cookie=%#lx generation=%llu state=%s peer_present=%u",
			    e->debug_cookie, e->debug_generation,
			    e->retired ? "retired" : e->refused ? "refused" :
			    e->stale ? "uncertain" : "submitted", !!peer);
	if (peer)
		zx279133_diag_print(s, " peer_cookie=%#lx peer_retired=%u peer_stale=%u peer_refused=%u",
				    peer->debug_cookie, peer->retired, peer->stale, peer->refused);
	zx279133_diag_print(s, "\nipv6=%u proto=%u ingress=%u egress=%u gemport=%u pppoe=%u snat=%u vlan_push=%u tci=%#x class_set=%u class=%#x\n",
			    p->ipv6, p->ip_proto, p->ingress, p->egress, p->gemport, p->pppoe_sid,
			    e->snat, p->data.vlan_push, p->data.vlan_tci,
			    p->data.traffic_class_set, p->data.traffic_class);
	if (p->data.police_set)
		zx279133_diag_print(s, "police=1 bucket=%u cir=%u cbs=%u experimental_units=1\n",
				    p->data.meter_bucket, p->data.police.cir, p->data.police.cbs);
	if (p->ipv6)
		zx279133_diag_print(s, "tuple=%pI6c:%u->%pI6c:%u\n",
				    &p->data.src_v6, be16_to_cpu(p->data.tuple.src_port),
				    &p->data.dst_v6, be16_to_cpu(p->data.tuple.dst_port));
	else
		zx279133_diag_print(s, "tuple=%pI4:%u->%pI4:%u translated=%pI4:%u->%pI4:%u\n",
				    &p->data.tuple.src_addr, be16_to_cpu(p->data.tuple.src_port),
				    &p->data.tuple.dst_addr, be16_to_cpu(p->data.tuple.dst_port),
				    &p->xlate.src_addr, be16_to_cpu(p->xlate.src_port),
				    &p->xlate.dst_addr, be16_to_cpu(p->xlate.dst_port));
	zx279133_diag_print(s, "src_mac=%pM dst_mac=%pM key=%16phN reply_key=%16phN\n",
			    p->data.eth.h_source, p->data.eth.h_dest, e->key, e->reply_key);
	if (e->stat_group)
		zx279133_diag_print(s, "counter_scope=endpoint-group group_refs=%u per_flow_bytes=unavailable\n",
				    e->stat_group->refs);
	if (e->retired || e->refused)
		return;
	zx279133_diag_print(s, "storage=%s full=%u zcam=%u/%u/%u ddr=%u ikey=%u wanid=%u stat_valid=%u stat=%u age=%u cached_packets=%llu cached_raw_bytes=%llu\n",
			    e->in_ddr ? "ddr" : "zcam", e->full, e->zblock, e->zcell, e->zaddr,
			    e->ddr_bucket, e->ikey, e->wanid, e->has_stat, e->stat, e->age,
			    e->packets, e->bytes);
	zx279133_fast_response_build(fast, &p->data, &p->xlate, p->ingress, p->egress,
				     p->gemport, e->ikey, e->stat, e->has_stat, e->pppoe, e->wanid);
	if (e->full)
		zx279133_fast_full_table_build(table, fast, e->key, e->age);
	else
		zx279133_fast_multi_table_build(table, fast, e->key, e->age);
	zx279133_diag_print(s, "expected_response=%*phN expected_table=%*phN\n",
			    (int)sizeof(fast), fast, e->full ? (int)sizeof(table) :
			    ZX279133_FAST_IKEY_SIZE * 2, table);
	if (live && e->in_ddr) {
		u32 actual[ZX279133_ZCAM_ENTRY_SIZE / sizeof(u32)];

		ret = zte_nppt_debug_ddr_read(o->np, e->ddr_bucket, actual);
		zx279133_diag_print(s, "table_readback=ddr table_rc=%d", ret);
		if (!ret)
			zx279133_diag_print(s, " actual_table=%*phN exact_match=%u",
					    (int)sizeof(actual), actual,
					    !memcmp(actual, table, sizeof(actual)));
		zx279133_diag_print(s, "\n");
	} else {
		zx279133_diag_print(s, "table_readback=%s\n",
				    e->in_ddr ? "not_requested" : "zcam_unsupported");
	}
	if (live && e->has_stat) {
		ret = zte_nppt_stats_read(o->np, e->stat, &packets, &bytes);
		zx279133_diag_print(s, "counter_rc=%d raw_packets=%llu raw_bytes=%llu counter_sample_jiffies=%lu\n",
				    ret, packets, bytes, jiffies);
	}
}

static void zx279133_diag_events(struct zx279133_diag_file *s,
				 bool filter, unsigned long cookie)
{
	struct zx279133_diag *d = &s->offload->diag;
	unsigned int i, start = (d->next + ZX279133_DIAG_EVENTS - d->count) % ZX279133_DIAG_EVENTS;

	zx279133_diag_print(s, "trace_active=%u remaining=%u expires_jiffies=%lu now_jiffies=%lu all=%u watched_cookie=%#lx\n",
			    d->remaining && time_before(jiffies, d->expires), d->remaining,
			    d->expires, jiffies, d->all, d->cookie);
	for (i = 0; i < d->count; i++) {
		struct zx279133_diag_event *e = &d->events[(start + i) % ZX279133_DIAG_EVENTS];

		if (filter && e->cookie != cookie)
			continue;
		zx279133_diag_print(s, "seq=%llu jiffies=%lu cookie=%#lx command=%u rc=%d input_truncated=%u reason=%s\ninput: %s\n",
				    e->sequence, e->stamp, e->cookie, e->command, e->result,
				    e->input_truncated, e->reason, e->input);
	}
}

static int zx279133_diag_open(struct inode *inode, struct file *file)
{
	struct zx279133_diag_file *s;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->offload = inode->i_private;
	kref_get(&s->offload->ref);
	mutex_init(&s->lock);
	file->private_data = s;
	return nonseekable_open(inode, file);
}

static int zx279133_diag_release(struct inode *inode, struct file *file)
{
	struct zx279133_diag_file *s = file->private_data;

	kref_put(&s->offload->ref, zx279133_offload_release);
	kfree(s);
	return 0;
}

static ssize_t zx279133_diag_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct zx279133_diag_file *s = file->private_data;
	ssize_t ret;

	mutex_lock(&s->lock);
	ret = simple_read_from_buffer(buf, count, ppos, s->output, s->used);
	mutex_unlock(&s->lock);
	return ret;
}

static ssize_t zx279133_diag_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct zx279133_diag_file *s = file->private_data;
	struct zx279133_flow_offload *o = s->offload;
	struct zx279133_diag_request r;
	struct zx279133_flow_entry *entry;
	char text[128];
	unsigned long index;
	unsigned int n = 0, active = 0, retired = 0, stale = 0, refused = 0;
	int ret;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (!count || count >= sizeof(text))
		return -E2BIG;
	if (copy_from_user(text, buf, count))
		return -EFAULT;
	if (memchr(text, '\0', count))
		return -EINVAL;
	text[count] = '\0';
	mutex_lock(&s->lock);
	s->used = 0;
	ret = zx279133_diag_parse(text, &r);
	if (ret)
		goto error;
	if (r.live) {
		ret = zte_nppt_try_begin(o->np);
		if (ret)
			goto error;
	}
	if (!mutex_trylock(&o->lock)) {
		ret = -EAGAIN;
		goto end_live;
	}
	if (READ_ONCE(o->detached)) {
		ret = -ENODEV;
		goto unlock;
	}
	zx279133_diag_print(s, "rc=0 debug_api=1 live=%u\n", r.live);
	switch (r.op) {
	case DIAG_CLIENT_SET:
		ret = zx279133_client_set(o, r.mac, r.upload, r.download,
					  r.burst_bytes);
		if (ret)
			break;
		fallthrough;
	case DIAG_CLIENTS:
		zx279133_diag_print(s, "mac_limit_api=1 experimental=%u rate_unit=bytes_per_second accounting=wire direction=source-upload,destination-download capacity=%u connections_supported=0 cbs_default_bytes=%u cbs_min_bytes=%u cbs_max_bytes=%u cbs_default_mode=oem_rate cbs_raw_per_cir=%u cbs_raw_max=%u effect_verified=0\n",
				    READ_ONCE(experimental_mac_limits), ZX279133_CLIENT_LIMITS,
				    ZX279133_CLIENT_CBS_DEFAULT,
				    ZX279133_CLIENT_CBS_MIN,
				    ZX279133_CLIENT_CBS_MAX,
				    ZX279133_MAC_CBS_PER_CIR,
				    ZX279133_MAC_CBS_MAX_RAW);
		for (n = 0; n < ZX279133_CLIENT_LIMITS; n++) {
			struct zx279133_client_limit *c = &o->clients[n];

			if (!c->used)
				continue;
			zx279133_diag_print(s, "mac=%pM upload=%llu download=%llu burst_bytes=%u slot=%u source_binding=%u destination_binding=%u programmed=%u error=%d retained=%u cbs_mode=%s upload_cbs_raw=%u download_cbs_raw=%u\n",
					    c->mac, c->upload, c->download,
					    c->burst_bytes, n,
					    0x414 + n, 0x814 + n, c->programmed,
					    c->error, c->pinned,
					    c->burst_bytes ? "explicit" : "oem_rate",
					    c->cbs_raw[0], c->cbs_raw[1]);
		}
		break;
	case DIAG_SUMMARY:
		xa_for_each(&o->flows, index, entry) {
			retired += entry->retired;
			refused += entry->refused;
			stale += entry->stale;
			active += !entry->retired && !entry->refused;
		}
		zx279133_diag_print(s, "submitted=%u retired=%u refused=%u uncertain=%u ikey=%u/%u stat=%u/%u age=%u/%u ddr=%u/%u full_zcam=%u hardware_reads=0\n",
				    active, retired, refused, stale,
				    bitmap_weight(o->ikey_used, ZX279133_FAST_IKEY_DEPTH),
				    ZX279133_FAST_IKEY_DEPTH,
				    bitmap_weight(o->stat_used, ZX279133_FAST_STAT_DEPTH),
				    ZX279133_FAST_STAT_DEPTH,
				    bitmap_weight(o->age_used, ZX279133_FAST_AGE_DEPTH),
				    (unsigned int)ZX279133_FAST_AGE_DEPTH,
				    o->ddr_entries, (unsigned int)ZX279133_DDR_BUCKETS,
				    o->fast_full_zcam_used);
		zx279133_diag_print(s, "stat_groups=%u stats_mode=endpoint-shared group_sample_ms=3000 per_connection_bytes=not_attributed\n", o->stat_group_count);
		break;
	case DIAG_LIST:
		index = r.cookie;
		while ((entry = xa_find(&o->flows, &index, ULONG_MAX, XA_PRESENT)) &&
		       n < r.budget) {
			zx279133_diag_print(s, "cookie=%#lx state=%s ipv6=%u proto=%u upstream=%u\n",
					    index, entry->retired ? "retired" :
					    entry->refused ? "refused" :
					    entry->stale ? "uncertain" : "submitted",
					    entry->spec.ipv6,
					    entry->spec.ip_proto, entry->upstream);
			n++;
			if (index == ULONG_MAX)
				break;
			index++;
		}
		zx279133_diag_print(s, "rows=%u next_start=%#lx\n", n, index);
		break;
	case DIAG_FLOW:
	case DIAG_EXPLAIN:
		entry = xa_load(&o->flows, r.cookie);
		if (entry)
			zx279133_diag_entry(s, entry, r.live);
		else
			zx279133_diag_print(s, "entry_present=0 cookie=%#lx\n", r.cookie);
		if (r.op == DIAG_EXPLAIN)
			zx279133_diag_events(s, true, r.cookie);
		break;
	case DIAG_EVENTS:
		zx279133_diag_events(s, false, 0);
		break;
	case DIAG_WATCH:
		if (!o->diag.events) {
			o->diag.events = kcalloc(ZX279133_DIAG_EVENTS, sizeof(*o->diag.events),
						 GFP_KERNEL);
			if (!o->diag.events) {
				ret = -ENOMEM;
				break;
			}
		}
		o->diag.all = r.all;
		o->diag.cookie = r.cookie;
		o->diag.expires = jiffies + r.seconds * HZ;
		o->diag.count = 0;
		o->diag.next = 0;
		WRITE_ONCE(o->diag.remaining, r.budget);
		zx279133_diag_print(s, "armed=1 seconds=%u budget=%u all=%u cookie=%#lx\n",
				    r.seconds, r.budget, r.all, r.cookie);
		break;
	case DIAG_OFF:
		WRITE_ONCE(o->diag.remaining, 0);
		zx279133_diag_print(s, "armed=0\n");
		break;
	}
unlock:
	mutex_unlock(&o->lock);
end_live:
	if (r.live)
		zte_nppt_end(o->np);
	if (!ret)
		goto done;
error:
	s->used = 0;
	zx279133_diag_print(s, "rc=%d\n", ret);
done:
	*ppos = 0;
	mutex_unlock(&s->lock);
	return count;
}

static const struct file_operations zx279133_diag_fops = {
	.owner = THIS_MODULE,
	.open = zx279133_diag_open,
	.release = zx279133_diag_release,
	.read = zx279133_diag_read,
	.write = zx279133_diag_write,
};

static void zx279133_diag_init(struct zx279133_flow_offload *o)
{
	char name[96];

	snprintf(name, sizeof(name), "zte-fnoffload-%s", dev_name(o->dev));
	o->diag.dir = debugfs_create_dir(name, NULL);
	if (!IS_ERR(o->diag.dir))
		debugfs_create_file("control", 0600, o->diag.dir, o, &zx279133_diag_fops);
}

static void zx279133_diag_remove(struct zx279133_flow_offload *o)
{
	debugfs_remove_recursive(o->diag.dir);
}
#else
static void zx279133_diag_record(struct zx279133_flow_offload *o,
				 struct flow_cls_offload *f, int ret)
{
}

static void zx279133_diag_init(struct zx279133_flow_offload *o)
{
}

static void zx279133_diag_remove(struct zx279133_flow_offload *o)
{
}
#endif
