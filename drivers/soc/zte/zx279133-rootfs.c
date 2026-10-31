// SPDX-License-Identifier: GPL-2.0-only
/*
 * Read-only view of the root filesystem stored in the SR1010 firmware slot
 * that the vendor bootloader selected.
 *
 * The vendor flasher and U-Boot place the rootfs payload in good erase blocks
 * only, skipping bad ones. Expose those blocks as a contiguous MTD device named
 * "rootfs" so that a block filesystem such as squashfs can be mounted from it.
 *
 * The device is registered after the fixed partitions, so it takes the next
 * free MTD index (7 on this board). MTD calls its notifiers with mtd_table_mutex
 * held, and registering a device takes that mutex again, so nothing is ever
 * registered from a notifier: the notifier only schedules work.
 */
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/math.h>
#include <linux/mtd/mtd.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/soc/zte/zx279133-bootinfo.h>
#include <linux/workqueue.h>

#define ZX279133_MAX_MTD	64

struct zx279133_rootfs {
	struct mtd_info mtd;
	struct mtd_info *slot;
	unsigned int nr_blocks;
	u64 *block_ofs;		/* good-block offsets inside the slot partition */
};

static struct zx279133_bootinfo bootinfo;
static struct zx279133_rootfs *rootfs;
static DEFINE_MUTEX(rootfs_lock);
static bool rootfs_ready;	/* set once the fixed partitions are registered */

static int zx279133_rootfs_read(struct mtd_info *mtd, loff_t from, size_t len,
				size_t *retlen, u_char *buf)
{
	struct zx279133_rootfs *rfs = mtd->priv;
	u32 erasesize = mtd->erasesize;
	int ret = 0;

	while (len) {
		unsigned int blk = div_u64(from, erasesize);
		u32 ofs = from - (u64)blk * erasesize;
		size_t chunk = min_t(size_t, len, erasesize - ofs);
		size_t done = 0;
		int err;

		err = mtd_read(rfs->slot, rfs->block_ofs[blk] + ofs, chunk,
			       &done, buf);
		*retlen += done;
		if (err == -EUCLEAN)
			err = 0;
		if (err)
			ret = err;
		if (err && !mtd_is_eccerr(err))
			return err;
		if (done != chunk)
			return -EIO;

		from += chunk;
		buf += chunk;
		len -= chunk;
	}

	return ret;
}

static int zx279133_rootfs_block_isbad(struct mtd_info *mtd, loff_t ofs)
{
	return 0;
}

static bool zx279133_is_selected_slot(struct mtd_info *mtd)
{
	u64 start = mtd_get_master_ofs(mtd, 0);

	return mtd_is_partition(mtd) && start == bootinfo.slot_offset &&
	       bootinfo.header_offset <= start + mtd->size;
}

static struct zx279133_rootfs *zx279133_rootfs_create(struct mtd_info *slot)
{
	u32 erasesize = slot->erasesize;
	u64 ofs = bootinfo.rootfs_offset - bootinfo.slot_offset;
	u64 end = bootinfo.header_offset - bootinfo.slot_offset;
	struct zx279133_rootfs *rfs;
	unsigned int i;

	if (!erasesize || ofs % erasesize)
		return ERR_PTR(-EINVAL);

	rfs = kzalloc(sizeof(*rfs), GFP_KERNEL);
	if (!rfs)
		return ERR_PTR(-ENOMEM);

	rfs->nr_blocks = DIV_ROUND_UP(bootinfo.rootfs_size, erasesize);
	rfs->block_ofs = kcalloc(rfs->nr_blocks, sizeof(*rfs->block_ofs),
				 GFP_KERNEL);
	if (!rfs->block_ofs) {
		kfree(rfs);
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < rfs->nr_blocks; ofs += erasesize) {
		int bad;

		if (ofs + erasesize > end)
			goto err_range;

		bad = mtd_block_isbad(slot, ofs);
		if (bad < 0)
			goto err_range;
		if (bad) {
			pr_info("zx279133-rootfs: skipping bad block at %#llx\n",
				mtd_get_master_ofs(slot, ofs));
			continue;
		}
		rfs->block_ofs[i++] = ofs;
	}

	rfs->slot = slot;
	rfs->mtd.name = "rootfs";
	rfs->mtd.type = MTD_ROM;
	/* Read-only and nothing to erase: without this MTD refuses the device. */
	rfs->mtd.flags = MTD_NO_ERASE;
	rfs->mtd.size = (u64)rfs->nr_blocks * erasesize;
	rfs->mtd.erasesize = erasesize;
	rfs->mtd.writesize = slot->writesize;
	rfs->mtd.writebufsize = slot->writesize;
	rfs->mtd.priv = rfs;
	rfs->mtd._read = zx279133_rootfs_read;
	rfs->mtd._block_isbad = zx279133_rootfs_block_isbad;
	return rfs;

err_range:
	pr_err("zx279133-rootfs: rootfs does not fit before the header at %#x\n",
	       bootinfo.header_offset);
	kfree(rfs->block_ofs);
	kfree(rfs);
	return ERR_PTR(-ENOSPC);
}

/* Find the selected slot and register the rootfs device. Not called from MTD. */
static void zx279133_rootfs_setup(void)
{
	struct zx279133_rootfs *rfs;
	struct mtd_info *slot = NULL;
	int i, ret;

	mutex_lock(&rootfs_lock);
	if (rootfs)
		goto out;

	for (i = 0; i < ZX279133_MAX_MTD && !slot; i++) {
		struct mtd_info *mtd = get_mtd_device(NULL, i);

		if (IS_ERR(mtd))
			continue;
		if (zx279133_is_selected_slot(mtd))
			slot = mtd;
		else
			put_mtd_device(mtd);
	}
	if (!slot)
		goto out;

	rfs = zx279133_rootfs_create(slot);
	if (IS_ERR(rfs)) {
		put_mtd_device(slot);
		goto out;
	}

	ret = mtd_device_register(&rfs->mtd, NULL, 0);
	if (ret) {
		pr_err("zx279133-rootfs: registration failed: %d\n", ret);
		put_mtd_device(slot);
		kfree(rfs->block_ofs);
		kfree(rfs);
		goto out;
	}

	rootfs = rfs;
	pr_info("zx279133-rootfs: mtd%d: slot %u rootfs at %#x, %u blocks\n",
		rfs->mtd.index, bootinfo.slot, bootinfo.rootfs_offset,
		rfs->nr_blocks);
out:
	mutex_unlock(&rootfs_lock);
}

static void zx279133_rootfs_work(struct work_struct *work)
{
	zx279133_rootfs_setup();
}

static DECLARE_WORK(zx279133_rootfs_work_item, zx279133_rootfs_work);

/*
 * Runs with mtd_table_mutex held. Only a slot that shows up after the fixed
 * partitions were registered (a late SPI-NAND probe) needs this path.
 */
static void zx279133_rootfs_notify_add(struct mtd_info *mtd)
{
	if (READ_ONCE(rootfs_ready) && !READ_ONCE(rootfs) &&
	    zx279133_is_selected_slot(mtd))
		schedule_work(&zx279133_rootfs_work_item);
}

static void zx279133_rootfs_notify_remove(struct mtd_info *mtd)
{
}

static struct mtd_notifier zx279133_rootfs_notifier = {
	.add = zx279133_rootfs_notify_add,
	.remove = zx279133_rootfs_notify_remove,
};

static int __init zx279133_rootfs_init(void)
{
	if (zx279133_get_bootinfo(&bootinfo) || !bootinfo.rootfs_size)
		return 0;

	register_mtd_user(&zx279133_rootfs_notifier);
	return 0;
}
device_initcall(zx279133_rootfs_init);

/* By now the SPI-NAND driver has registered its fixed partitions. */
static int __init zx279133_rootfs_late(void)
{
	if (!bootinfo.rootfs_size)
		return 0;

	WRITE_ONCE(rootfs_ready, true);
	zx279133_rootfs_setup();
	return 0;
}
late_initcall(zx279133_rootfs_late);
