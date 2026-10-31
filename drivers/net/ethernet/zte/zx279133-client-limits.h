/* SPDX-License-Identifier: GPL-2.0-only */
/* Explicit per-MAC policy, not a connection table. Called with supplier
 * begin/end and translator lock held; no packet hook, worker or timer.
 */
struct zx279133_client_config {
	u8 mac[ETH_ALEN];
	u64 upload;
	u64 download;
	u32 burst_bytes;
	bool used;
};

static bool zx279133_clients_active(struct zx279133_flow_offload *o)
{
	unsigned int i;

	if (o->mac_global_owned)
		return true;
	for (i = 0; i < ZX279133_CLIENT_LIMITS; i++)
		if (o->clients[i].pinned)
			return true;
	return false;
}

static int zx279133_client_release(struct zx279133_flow_offload *o,
				   struct zx279133_client_limit *c, u8 slot)
{
	int ret, dir;

	/* Disable both MAC selectors before releasing a shared binding. On any
	 * failure retain Host + meters and module pin for a later explicit retry.
	 */
	if (c->host) {
		ret = zte_nppt_host_limit(o->np, c->host, slot, false, false);
		if (ret)
			return ret;
		c->programmed = false;
	}
	for (dir = 0; dir < 2; dir++) {
		if (!c->meters[dir])
			continue;
		ret = zte_nppt_meter_put(o->np, c->meters[dir]);
		if (ret)
			return ret;
		c->meters[dir] = NULL;
		c->cbs_raw[dir] = 0;
	}
	if (c->host) {
		ret = zte_nppt_host_put(o->np, c->host);
		/* host_put consumes the reference even if its final row delete
		 * fails; the NPU Host manager quarantines that zero-user row.
		 */
		c->host = NULL;
		if (ret)
			return ret;
	}
	if (c->pinned) {
		c->pinned = false;
		module_put(THIS_MODULE);
	}
	return 0;
}

static int zx279133_clients_global_restore(struct zx279133_flow_offload *o)
{
	unsigned int i;
	int ret;

	if (!o->mac_global_owned)
		return 0;
	for (i = 0; i < ZX279133_CLIENT_LIMITS; i++)
		if (o->clients[i].pinned)
			return 0;
	ret = zte_nppt_mac_global_set(o->np, o->mac_global_saved);
	if (!ret) {
		o->mac_global_owned = false;
		module_put(THIS_MODULE);
	}
	return ret;
}

static int zx279133_client_apply(struct zx279133_flow_offload *o,
				 struct zx279133_client_limit *c, u8 slot)
{
	struct zte_nppt_plcr_timing timing;
	struct zte_nppt_plcr_profile profile;
	u64 rate[2] = { c->upload, c->download };
	int ret, dir;

	if (c->programmed)
		return 0;
	if (c->pinned)
		return -EIO; /* failed cleanup must be retried before reprogramming */
	if (!READ_ONCE(experimental_mac_limits))
		return -EOPNOTSUPP;
	ret = zte_nppt_native_plcr_timing_get(o->np, &timing);
	if (ret)
		return ret;
	if (timing.time_count != 62500 || timing.packet_length != 8000 ||
	    timing.packet_offset != 24 || timing.loose_length != 16000)
		return -ESTALE;
	c->host = zte_nppt_host_lookup_get(o->np, c->mac);
	if (IS_ERR(c->host)) {
		ret = PTR_ERR(c->host);
		c->host = NULL;
		return ret;
	}
	__module_get(THIS_MODULE);
	c->pinned = true;
	for (dir = 0; dir < 2; dir++) {
		if (!rate[dir])
			continue;
		ret = zx279133_mac_police_tokens(rate[dir], c->burst_bytes,
						 police_unit_bps,
						 police_burst_unit, &profile);
		if (ret)
			goto rollback;
		ret = zte_nppt_meter_mac_get(o->np, &profile, slot, dir, &c->meters[dir]);
		if (ret)
			goto rollback;
		c->cbs_raw[dir] = profile.cbs;
	}
	if (!o->mac_global_owned) {
		ret = zte_nppt_mac_global_get(o->np, &o->mac_global_saved);
		if (ret)
			goto rollback;
		__module_get(THIS_MODULE);
		o->mac_global_owned = true;
		ret = zte_nppt_mac_global_set(o->np, true);
		if (ret)
			goto rollback;
	}
	ret = zte_nppt_host_limit(o->np, c->host, slot, !!rate[0], !!rate[1]);
	if (ret)
		goto rollback;
	c->programmed = true;
	return 0;
rollback:
	zx279133_client_release(o, c, slot);
	zx279133_clients_global_restore(o);
	return ret;
}

static void zx279133_clients_sync(struct zx279133_flow_offload *o)
{
	unsigned int i;

	for (i = 0; i < ZX279133_CLIENT_LIMITS; i++)
		if (o->clients[i].used && !o->clients[i].programmed)
			o->clients[i].error = zx279133_client_apply(o, &o->clients[i], i);
}

static int zx279133_clients_clear(struct zx279133_flow_offload *o, bool hardware)
{
	unsigned int i;
	int ret, error = 0;

	if (!hardware && zx279133_clients_active(o))
		return -EBUSY;
	for (i = 0; i < ZX279133_CLIENT_LIMITS; i++) {
		ret = zx279133_client_release(o, &o->clients[i], i);
		if (ret)
			error = ret;
		if (o->clients[i].used)
			o->clients[i].error = ret ? ret : -ENETDOWN;
	}
	ret = zx279133_clients_global_restore(o);
	return error ? error : ret;
}

static int zx279133_client_set(struct zx279133_flow_offload *o,
			       const u8 *mac, u64 upload, u64 download,
			       u32 burst_bytes)
{
	struct zx279133_client_limit *c = NULL;
	struct zx279133_client_config previous = {};
	struct zte_nppt_plcr_profile profile;
	unsigned int i, slot = ZX279133_CLIENT_LIMITS;
	int ret, apply_ret, cleanup_ret;

	if (!is_valid_ether_addr(mac))
		return -EINVAL;
	/* Zero remains the automatic policy, including across retries/rollback. */
	if (burst_bytes && (burst_bytes < ZX279133_CLIENT_CBS_MIN ||
			    burst_bytes > ZX279133_CLIENT_CBS_MAX))
		return -ERANGE;
	/* Validate before removing an existing policy. 0 disables that direction. */
	if (upload && zx279133_mac_police_tokens(upload, burst_bytes,
						 police_unit_bps, police_burst_unit,
						 &profile))
		return -ERANGE;
	if (download && zx279133_mac_police_tokens(download, burst_bytes,
						   police_unit_bps, police_burst_unit,
						   &profile))
		return -ERANGE;
	/* Do not tear down a working limit before discovering that the explicit
	 * experimental gate has been closed. Disabling a policy remains allowed.
	 */
	if ((upload || download) && !READ_ONCE(experimental_mac_limits))
		return -EOPNOTSUPP;
	for (i = 0; i < ZX279133_CLIENT_LIMITS; i++) {
		if (!o->clients[i].used) {
			if (slot == ZX279133_CLIENT_LIMITS)
				slot = i;
			continue;
		}
		if (ether_addr_equal(o->clients[i].mac, mac)) {
			c = &o->clients[i];
			slot = i;
			break;
		}
	}
	if (!c && !upload && !download)
		return zx279133_clients_global_restore(o);
	if (slot == ZX279133_CLIENT_LIMITS)
		return -ENOSPC;
	c = &o->clients[slot];
	previous.used = c->used;
	if (previous.used) {
		ether_addr_copy(previous.mac, c->mac);
		previous.upload = c->upload;
		previous.download = c->download;
		previous.burst_bytes = c->burst_bytes;
	}
	ret = zx279133_client_release(o, c, slot);
	if (ret) {
		c->error = ret;
		return ret;
	}
	if (!upload && !download) {
		zte_nppt_host_watch(o->np, slot, NULL);
		memset(c, 0, sizeof(*c));
		return zx279133_clients_global_restore(o);
	}
	ether_addr_copy(c->mac, mac);
	c->used = true;
	zte_nppt_host_watch(o->np, slot, mac);
	c->upload = upload;
	c->download = download;
	c->burst_bytes = burst_bytes;
	c->error = zx279133_client_apply(o, c, slot);
	/* Desired policy survives startup without an active Host. A subsequent
	 * flow installation retries once, without polling or a userspace sampler.
	 */
	if (c->error == -ENOENT || c->error == -EAGAIN) {
		c->error = 0;
		return 0;
	}
	if (!c->error)
		return 0;

	/* OEM-style MAC limiting changes the PLCR bindings and table9 action in
	 * separate hardware operations. Try to restore the prior policy if a new
	 * request fails. If cleanup fails, retain ownership of every uncertain
	 * resource instead of replacing pointers that may still be live in NP.
	 */
	apply_ret = c->error;
	if (c->pinned)
		return apply_ret;
	cleanup_ret = zx279133_client_release(o, c, slot);
	if (cleanup_ret) {
		c->error = cleanup_ret;
		return cleanup_ret;
	}
	if (previous.used) {
		ether_addr_copy(c->mac, previous.mac);
		c->used = true;
		c->upload = previous.upload;
		c->download = previous.download;
		c->burst_bytes = previous.burst_bytes;
		zte_nppt_host_watch(o->np, slot, previous.mac);
		c->error = zx279133_client_apply(o, c, slot);
		if (c->error == -ENOENT || c->error == -EAGAIN)
			c->error = 0;
		if (c->error)
			return c->error;
	} else {
		zte_nppt_host_watch(o->np, slot, NULL);
		memset(c, 0, sizeof(*c));
		cleanup_ret = zx279133_clients_global_restore(o);
		if (cleanup_ret)
			return cleanup_ret;
	}
	return apply_ret;
}
