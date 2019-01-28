/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>	/* struct ethhdr */
#include <linux/if_vlan.h>
#include <linux/ip.h>		/* struct iphdr */
#include <linux/udp.h>		/* struct udphdr */
#include <linux/tcp.h>		/* struct tcphdr */
#include <linux/mutex.h>

#include <asm/uaccess.h>	/* copy_from/to_user */

#include "imc_ipc_wwan.h"
#include "imc_ipc_imem.h" /* for IPC_MEM_MAX_CHANNELS */
#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_trace.h"
#include "imc_ipc_mux.h" /* for IPC_IMEM_MUX_SESSION_ENTRIES */
#include "imc_ipc_export.h"
#include "imc_ipc_chnl_cfg.h"


/* minimum number of transmit queues per WWAN root device */
#define WWAN_MIN_TXQ		(1)
/* maximum number of transmit queues per WWAN root device */
#define WWAN_MAX_TXQ		(IPC_IMEM_MUX_SESSION_ENTRIES + WWAN_MIN_TXQ)
/* minimum number of receive queues per WWAN root device */
#define WWAN_MAX_RXQ		(1)
/* default transmit queue for WWAN root device */
#define WWAN_DEFAULT_TXQ	(0)
/* VLAN tag for WWAN root device */
#define WWAN_ROOT_VLAN_TAG	(0)

#define IPC_MEM_MIN_MTU_SIZE    (68)
#define IPC_MEM_MAX_MTU_SIZE    (1024 * 1024)

#define IPC_MEM_VLAN_TO_SESSION	(1)

#define IPC_WWAN_MAX_VLAN_ENTRIES \
	(IPC_MEM_MAX_CHANNELS + IPC_IMEM_MUX_SESSION_ENTRIES)

/* Required alignment for TX in bytes (32 bit/4 bytes)*/
#define IPC_WWAN_ALIGN (4)

/**
 * struct ipc_vlan_info -  This structure includes information about
 * VLAN device.
 * @vlan_id:	VLAN tag of the VLAN device.
 * @ch_id:	IPC channel number for which VLAN device is created.
 * @stats:	Contains statistics of VLAN devices.
 */
struct ipc_vlan_info {
	int vlan_id;
	int ch_id;
	struct net_device_stats stats;
};

/**
 * struct ipc_wwan - This structure contains information about
 * WWAN root device and interface to the IPC layer.
 * @lock:		Spinlock to be used for atomic operations of the
			root device.
 * @stats:		Contains statistics of WWAN root device
 * @napi:		NAPI structure.
 * @vlan_devs:		Contains information about VLAN devices created under
			WWAN root device.
 * @netdev:		Pointer to network interface device structure.
 * @ops:		Callback Interfaces
 * @ops_instance:	Instance pointer for Callbacks
 */
struct ipc_wwan {
	spinlock_t              lock;
	struct net_device_stats stats;
	struct napi_struct      napi;
	struct ipc_vlan_info    vlan_devs[IPC_WWAN_MAX_VLAN_ENTRIES];
	int                     vlan_devs_nr;
	struct net_device      *netdev;
	bool                    is_registered;
	struct ipc_wwan_ops     ops;
	void                   *ops_instance;

	int (*timesync_cb)(void *instance, struct ipc_timesync *ts);
	void *timesync_instance;
	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
	struct mutex if_mutex;
};

/* Forward declarations */
static int ipc_wwan_add_vlan(struct ipc_wwan *this, struct net_device *dev,
		u16 vid);
static int ipc_wwan_remove_vlan(struct ipc_wwan *this, u16 vid);

/* Get struct ipc_wwan * from netdev ptr */
static struct ipc_wwan *ipc_wwan_get_instance_from_netdev(
	struct net_device *netdev)
{
	return netdev ? netdev_priv(netdev) : NULL;
}

/* Network Device notification hander. */
static int ipc_wwan_ev_handler(struct notifier_block *notifier,
		unsigned long event, void *ptr)
{
	struct net_device *notifier_dev = netdev_notifier_info_to_dev(ptr);
	struct ipc_wwan *this = NULL;
	u16 vid = 0;

	if (!notifier_dev) {
		ipc_err("Invalid pointer.");
		return NOTIFY_DONE;
	}

	if (is_vlan_dev(notifier_dev)) {
		struct vlan_dev_priv *vlan_priv = vlan_dev_priv(notifier_dev);
		struct net_device *dev = vlan_priv->real_dev;

		vid = vlan_dev_vlan_id(notifier_dev);


		if (strstr(dev->name, "wwan") && vid == IPC_WWAN_DSS_ID_4) {
			this = ipc_wwan_get_instance_from_netdev(dev);

			ipc_dbg("Device: %s event: %lu vid:%d", dev->name,
					event, vid);

			switch (event) {

			/*
			 * In the trace collection application, there is a
			 * delay between pipe open and reading of the socket
			 * due to other system call and setup that needs to be
			 * done. Due to which large trace data arriving from
			 * modem, especially at the modem have chances to get
			 * dropped at the network stack even if we have high
			 * buffers. To avoid this, the pipes are opened only
			 * when the IF UP is called on the VLAN trace device.
			 * And trace pipes are closed when IF DOWN is called.
			 */
			case NETDEV_UP:
				ipc_dbg("Received trace dev. UP");
				if (ipc_wwan_add_vlan(this, dev, vid))
					ipc_err("Failed to add VLAN ID :%d",
									 vid);
				break;

			case NETDEV_DOWN:
				ipc_dbg("Received trace dev. DOWN");
				if (ipc_wwan_remove_vlan(this, vid))
					ipc_err("Failed to remove VLAN ID :%d",
									 vid);
				break;

			default:
				ipc_dbg("Ignored event :%lu VID:%d", event,
									 vid);
				break;
			}
		}
	}

	return NOTIFY_DONE;
}

static struct notifier_block ipc_wwan_dev_notifier = {
		.notifier_call = ipc_wwan_ev_handler
};

/**
 * Checks the protocol and discards the Ethernet header or VLAN header
 * accordingly.
 *
 * @skb: SKB to be looked into.
 * @is_ip: Pointer to get whether the packet is IP or not.
 *
 * returns pulled header size on Success and 0 on Failure.
 */
static int ipc_wwan_pull_header(struct sk_buff *skb, bool *p_is_ip)
{
	__be16 proto;
	unsigned int header_size;

	if (skb->protocol == htons(ETH_P_8021Q)) {
		proto = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;

		if (skb->len < VLAN_ETH_HLEN)
			header_size = 0;
		else
			header_size = VLAN_ETH_HLEN;
	} else {
		proto = eth_hdr(skb)->h_proto;

		if (skb->len < ETH_HLEN)
			header_size = 0;
		else
			header_size = ETH_HLEN;
	}

	/* If a valid pointer */
	if ((header_size > 0) && p_is_ip) {
		*p_is_ip = (proto == htons(ETH_P_IP))
				|| (proto == htons(ETH_P_IPV6));

		/* Discard the vlan/ethernet header.
		 */
		if (unlikely(!skb_pull(skb, header_size)))
			header_size = 0;
	}

	return header_size;
}


/**
 * Get VLAN tag from IPC SESSION ID
 */
static inline u16 ipc_wwan_mux_session_to_vlan_tag(int id)
{
	return (u16)(id + IPC_MEM_VLAN_TO_SESSION);
}


/**
 * Get IPC SESSION ID from VLAN tag
 */
static inline int ipc_wwan_vlan_to_mux_session_id(u16 tag)
{
	return tag - IPC_MEM_VLAN_TO_SESSION;
}


/**
 * read through number of vlan devices and compare vlan id
 * aginst tag to find out the array index of requested tag.
 */
static int ipc_wwan_get_vlan_devs_nr(struct ipc_wwan *this, u16 tag)
{
	int i = 0;

	for (i = 0; i < this->vlan_devs_nr; i++)
		if (this->vlan_devs[i].vlan_id == tag)
			return i;

	return -EINVAL;
}

static int ipc_wwan_add_vlan(struct ipc_wwan *this, struct net_device *dev,
		u16 vid)
{
	if (unlikely(!this))
		return -EINVAL;

	ipc_dbg("vlan id = %d", vid);
	if (unlikely(vid >= 768))
		return -EINVAL;

	if (unlikely(vid == WWAN_ROOT_VLAN_TAG))
		return 0;

	if (unlikely(!this->ops.open)) {
		ipc_err("no mem ops available");
		return -EOPNOTSUPP;
	}

	mutex_lock(&this->if_mutex);

	/* get channel id */
	this->vlan_devs[this->vlan_devs_nr].ch_id =
		this->ops.open(this->ops_instance, vid);

	if (unlikely(this->vlan_devs[this->vlan_devs_nr].ch_id < 0)) {
		ipc_err("cannot connect \"%s\" & id %d  to the IPC mem layer",
			dev->name, vid);
		mutex_unlock(&this->if_mutex);
		return -ENODEV;
	}

	/* save vlan id */
	this->vlan_devs[this->vlan_devs_nr].vlan_id = vid;

	ipc_dbg("channel id %d allocated to vlan id %d",
			this->vlan_devs[this->vlan_devs_nr].ch_id,
			this->vlan_devs[this->vlan_devs_nr].vlan_id);

	this->vlan_devs_nr++;

	mutex_unlock(&this->if_mutex);

	return 0;
}

static int ipc_wwan_remove_vlan(struct ipc_wwan *this, u16 vid)
{
	int ch_nr = 0, i = 0;

	if (unlikely(!this))
		return -EINVAL;

	ch_nr = ipc_wwan_get_vlan_devs_nr(this, vid);
	if (unlikely(ch_nr < 0 || this->vlan_devs[ch_nr].ch_id < 0)) {
		ipc_err("invalid ch nr %d to kill", ch_nr);
		return -EINVAL;
	}

	if (unlikely(!this->ops.close)) {
		ipc_err("no mem ops available");
		return -EOPNOTSUPP;
	}

	mutex_lock(&this->if_mutex);

	this->ops.close(this->ops_instance, vid, this->vlan_devs[ch_nr].ch_id);
	this->vlan_devs[ch_nr].ch_id = -1;

	ipc_dbg("channel id %d & vlan id %d removed",
					this->vlan_devs[ch_nr].ch_id, vid);

	/* re-align the vlan informations as we removed one tag */
	for (i = ch_nr; i < this->vlan_devs_nr; i++)
		memcpy(&this->vlan_devs[i], &this->vlan_devs[i+1],
						sizeof(struct ipc_vlan_info));

	/* decrement the channel number */
	this->vlan_devs_nr--;

	mutex_unlock(&this->if_mutex);

	return 0;
}

/**
 * function to add new vlan device and open a channel
 */
static int ipc_wwan_vlan_rx_add_vid(struct net_device *dev,
					__be16 proto, u16 vid)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	if (unlikely(!this))
		return -ENODEV;

	ipc_dbg("VID: %u Pointers %p %p.", vid, dev, this);

	if (vid != IPC_WWAN_DSS_ID_4)
		return ipc_wwan_add_vlan(this, dev, vid);
	else
		return 0;
}

/**
 * function to remove vlan device and de-allocate channel
 */
static int ipc_wwan_vlan_rx_kill_vid(struct net_device *dev,
					__be16 proto, u16 vid)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	if (unlikely(!this))
		return -ENODEV;

	ipc_dbg("vlan id = %d", vid);

	if (unlikely(vid == WWAN_ROOT_VLAN_TAG))
		return 0;

	if (vid != IPC_WWAN_DSS_ID_4)
		return ipc_wwan_remove_vlan(this, vid);
	else
		return 0;

}

/**
 * open a wwan device
 */
static int ipc_wwan_open(struct net_device *dev)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	if (unlikely(!this))
		return -ENODEV;

	/* Octets in one ethernet addr
	 */
	if (unlikely(dev->addr_len < ETH_ALEN)) {
		ipc_err("cannot build the Ethernet address for \"%s\"",
			dev->name);
		return -ENODEV;
	}

	/* enable tx path, DL data may follow
	 */
	netif_tx_start_all_queues(dev);

	return 0;
}

/**
 * stop/release wwan device
 */
static int ipc_wwan_stop(struct net_device *dev)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	if (unlikely(!this))
		return -ENODEV;

	ipc_dbg("Stop all TX Queues");

	/* cannot transmit any more */
	netif_tx_stop_all_queues(this->netdev);
	return 0;
}


/**
 * Receive a downlink packet from CP.
 **/
int ipc_wwan_receive(struct ipc_wwan *this, struct sk_buff *skb, bool dss)
{
	int status = 0;
	struct ethhdr *eth = NULL;
	u16 tag = 0;

	if (unlikely(!this || !skb)) {
		if (skb)
			dev_kfree_skb(skb);

		ipc_err("invalid arguments");
		return -1;
	}

	eth = (struct ethhdr *)skb->data;
	if (unlikely(!eth)) {
		ipc_err("ethernet header info");
		dev_kfree_skb(skb);
		return -1;
	}

	/* Build the ethernet header.
	 */
#if (KERNEL_VERSION(3, 14, 0) <= LINUX_VERSION_CODE)
	ether_addr_copy(eth->h_dest, this->netdev->dev_addr);
	ether_addr_copy(eth->h_source, this->netdev->dev_addr);
#else
	memcpy(eth->h_dest, this->netdev->dev_addr, ETH_ALEN);
	memcpy(eth->h_source, this->netdev->dev_addr, ETH_ALEN);
#endif
	eth->h_source[ETH_ALEN-1] ^= 0x01;	/* src is us xor 1 */
	/* set the ethernet payload type: ipv4 or ipv6 or Dummy type
	 * for 802.3 frames
	 */
	eth->h_proto = htons(ETH_P_802_3);
	if (!dss) {
		if ((skb->data[ETH_HLEN] & 0xF0) == 0x40)
			eth->h_proto = htons(ETH_P_IP);
		else if ((skb->data[ETH_HLEN] & 0xF0) == 0x60)
			eth->h_proto = htons(ETH_P_IPV6);
	}

	skb->dev = this->netdev;		/* redundant */
	skb->protocol = eth_type_trans(skb, this->netdev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;	/* don't check it */

	vlan_get_tag(skb, &tag);
	/* TX stats doesn't include ETH_HLEN.
	 * eth_type_trans() functions pulls the ethernet header.
	 * so skb->len does not have ethernet header in it.
	 */
	ipc_wwan_update_stats(this, ipc_wwan_vlan_to_mux_session_id(tag),
				skb->len, false);

	ipc_dbg("tag=%d,len=%d/%d,IPv%d,prio=%d", tag, skb->len, skb->truesize,
		 ((struct iphdr *)skb->data)->version, skb->priority);

#if defined(IMC_NET_ENABLE_NAPI)
	napi_gro_receive(&this->napi, skb);
#else
#if defined(IPC_NETIF_RX_NI)
	switch (netif_rx_ni(skb)) {
#else
	switch (netif_rx(skb)) {
#endif
	case NET_RX_SUCCESS:
		break;
	case NET_RX_DROP:
		/* ipc_err("linux stack packet dropped. chid[%d] data: %p, "
		 * "len: %d", channel_id, skb->data, skb->len);
		 */
		break;
	default:
		break;
	}
#endif
	return status;
}

/* Align SKB to 32bit, if not already aligned
 */
static struct sk_buff *ipc_wwan_skb_align(struct ipc_wwan *this,
					struct sk_buff *skb)
{
	struct sk_buff *new_skb;
	unsigned int offset = (uintptr_t)skb->data & (IPC_WWAN_ALIGN - 1);

	if (likely(offset == 0))
		return skb;

	ipc_dbg("realigning skb, offset=%u, size=%d", offset, skb->len);

	/* Allocate new skb to copy into */
	new_skb = dev_alloc_skb(skb->len + (IPC_WWAN_ALIGN - 1));
	if (unlikely(!new_skb)) {
		ipc_err("Failed to reallocate skb");
		goto out;
	}

	/* Make sure newly allocated skb is aligned */
	offset = (uintptr_t)new_skb->data & (IPC_WWAN_ALIGN - 1);
	if (unlikely(offset != 0))
		skb_reserve(new_skb, IPC_WWAN_ALIGN - offset);

	/* Copy payload */
	memcpy(new_skb->data, skb->data, skb->len);

	skb_put(new_skb, skb->len);
out:
	dev_kfree_skb(skb);
	return new_skb;
}


/**
 * Transmit a packet (called by the kernel)
 */
static int ipc_wwan_transmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	int ret = -EINVAL;
	u16 tag = 0;
	bool is_ip = false;
	int idx = 0;
	int header_size;

	if (unlikely(!skb)) {
		ipc_err("Invalid skb");
		return -EINVAL;
	}

	if (unlikely(!this || !this->ops.transmit)) {
		ipc_err("No dev/transmit ops available");
		ret = -EOPNOTSUPP;
		goto exit;
	}

	/* Get VLAN tag */
	vlan_get_tag(skb, &tag);

	/* If the SKB is of WWAN root device then don't send it to device.
	 * Free the SKB and then return.
	 */
	if (unlikely(tag == WWAN_ROOT_VLAN_TAG))
		goto exit;

	/* Discard the Ethernet header or VLAN Ethernet header depending
	 * on the protocol.
	 */
	header_size = ipc_wwan_pull_header(skb, &is_ip);
	if (!header_size) {
		ipc_err("Dropped short packet");
		goto exit;
	}

	/* Get the channel number corresponding to VLAN ID */
	idx = ipc_wwan_get_vlan_devs_nr(this, tag);
	if (unlikely(idx < 0 || idx >= IPC_WWAN_MAX_VLAN_ENTRIES
	|| this->vlan_devs[idx].ch_id < 0)) {
		ipc_err("Invalid index(%d) or channel ID found during VLAN ID mapping",
			idx);
		goto exit;
	}

	/* VLAN IDs from 1 to 255 are for IP data
	 * 257 to 767 are for non-IP data
	 */
	if ((tag > 0 && tag < 256) || (tag > 512 && tag < 768)) {
		if (unlikely(!is_ip)) {
			ipc_err("IP protocol expected for VLAN ID %d", tag);
			ret = -EXDEV;
			goto exit;
		}
	} else if (tag > 256 && tag < 512) {
		if (unlikely(is_ip)) {
			ipc_err("IP protocol not expected for VLAN ID %d", tag);
			ret = -EXDEV;
			goto exit;
		}

		/* Align the SKB only for control packets if not aligned. */
		skb = ipc_wwan_skb_align(this, skb);
		if (!skb) {
			ipc_err("failed to realign packet.");
			return -EINVAL;
		}
	} else {
		/* Unknown VLAN IDs */
		ret = -EXDEV;
		goto exit;
	}

	/* Send the SKB to device for transmission */
	ret = this->ops.transmit(this->ops_instance, tag,
				this->vlan_devs[idx].ch_id, skb);

	/* Return code of zero is success */
	if (ret == 0) {
		ret = NETDEV_TX_OK;
	} else if (ret == -2) {
		/* Return code -2 is to enable re-enqueue of the skb.
		 * Re-push the stripped header before returning busy.
		 */
		if (unlikely(!skb_push(skb, header_size))) {
			ipc_err("unable to push eth hdr");
			ret = -EIO;
			goto exit;
		}

		ret = NETDEV_TX_BUSY;
	} else {
		ret = -EIO;
		goto exit;
	}

	return ret;

exit:
	/* Log any skb drop except for WWAN Root device */
	if (tag != 0)
		ipc_dbg("skb dropped.VLAN ID: %d, ret: %d", tag, ret);

	dev_kfree_skb_any(skb);
	return ret;
}

/**
 * change the MTU of the wwan device
 */
static int ipc_wwan_change_mtu(struct net_device *dev, int new_mtu)
{
	unsigned long flags = 0;
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);
	spinlock_t *lock;

	if (unlikely(!this))
		return -EINVAL;

	lock = &this->lock;

	/* check ranges */
	if (unlikely((new_mtu < IPC_MEM_MIN_MTU_SIZE) ||
		(new_mtu > IPC_MEM_MAX_MTU_SIZE))) {
		ipc_err("mtu %d out of range %d..%d", new_mtu,
			IPC_MEM_MIN_MTU_SIZE, IPC_MEM_MAX_MTU_SIZE);
		return -EINVAL;
	}

	/* Update the new MTU value in device structure */
	spin_lock_irqsave(lock, flags);
	dev->mtu = new_mtu;
	spin_unlock_irqrestore(lock, flags);
	return 0;		/* success */
}

/**
 * change the MAC address of the wwan device
 */
static int ipc_wwan_change_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	u8 *e;
	unsigned long flags = 0;
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);
	spinlock_t *lock;
	int result = 0;

	if (unlikely(!this || !p))
		return -EINVAL;

	lock = &this->lock;
	e = (u8 *)addr->sa_data;

	ipc_dbg("imc_net_change_mac_addr addr=[%pM]", e);

	spin_lock_irqsave(lock, flags);

	if (is_zero_ether_addr(e)) {
		dev->addr_len = 1;
		memset(dev->dev_addr, 0, 6);

		ipc_dbg("mac addr set to zero");
		goto exit;
	}

	result = eth_mac_addr(dev, p);
exit:
	spin_unlock_irqrestore(lock, flags);
	return result;
}

static char *ipc_wwan_time_unit_to_str(u32 time_unit)
{
	char *str = NULL;

	switch (time_unit) {
	case IPC_SEC:
		str = "sec";
		break;

	case IPC_MILLI_SEC:
		str = "milli sec";
		break;

	case IPC_NANO_SEC:
		str = "nano sec";
		break;

	case IPC_PICO_SEC:
		str = "pico sec";
		break;

	case IPC_FEMTO_SEC:
		str = "femto sec";
		break;

	case IPC_ATTO_SEC:
		str = "atto sec";
		break;

	default:
		str = "unknown";
		break;
	}

	return str;
}

/**
 * Do time sync through ioctl of wwan device
 */
static int ipc_wwan_ioctl_timesync(struct ipc_wwan *this, struct ifreq *ifr)
{
	struct sioc_ipc_time_sync req;
	struct ipc_timesync ts = { 0 };
	int rc = -EFAULT;
	char *local_time_unit_str =  NULL;
	char *remote_time_unit_str =  NULL;

	if (unlikely(copy_from_user(&req, ifr->ifr_ifru.ifru_data,
		sizeof(req)))) {
		ipc_err("copy_from_user failed");
		return rc;
	}

	/* check size of user provided structure */
	if (unlikely(req.size != sizeof(req))) {
		ipc_err("req.size doesn't match. Expected %zu, was %zu",
			sizeof(req), req.size);
		return rc;
	}

	if (unlikely(!this || !this->timesync_cb)) {
		ipc_err("no callback registered");
		return rc;
	}

	rc = this->timesync_cb(this->timesync_instance, &ts);

	if (rc >= 0) {
		req.id = ts.id;
		req.local_time = ts.local_time;
		req.remote_time = ts.remote_time;
		req.local_time_unit = ts.local_time_unit;
		req.remote_time_unit = ts.remote_time_unit;
		local_time_unit_str
			= ipc_wwan_time_unit_to_str(req.local_time_unit);
		remote_time_unit_str
			= ipc_wwan_time_unit_to_str(req.remote_time_unit);

		/* Remote timestamp and its unit in unsupported platforms will
		 * be 0.
		 */
		ipc_dbg("id=%lu local=%llu(%s) remote=%llu(%s)",
			req.id, req.local_time,
			local_time_unit_str,
			req.remote_time,
			remote_time_unit_str);

		rc = copy_to_user(ifr->ifr_ifru.ifru_data, &req, sizeof(req));
	} else {
		ipc_err("timesync req. failed: %d", rc);
	}

	return rc;
}

/**
 * Do ioctl of wwan device
 */
static int ipc_wwan_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	ipc_dbg("cmd=0x%x", cmd);

	if (!this)
		return -EOPNOTSUPP;

	switch (cmd) {
	case SIOCSIFHWADDR:
		if (dev->addr_len > sizeof(struct sockaddr))
			return -EINVAL;
		return ipc_wwan_change_mac_addr(dev, &ifr->ifr_hwaddr);
	case SIOC_IPC_TIME_SYNC:
		return ipc_wwan_ioctl_timesync(this, ifr);
	default:
		return -EOPNOTSUPP;
	}
}
/**
 * Return statistics to the caller
 */
static struct net_device_stats *ipc_wwan_get_stats(struct net_device *dev)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	if (unlikely(!this))
		return NULL;

	return &this->stats;
}

/**
 * Configuration changes (passed on by ifconfig)
 */
static int ipc_wwan_set_config(struct net_device *dev, struct ifmap *map)
{
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	if (unlikely(!this))
		return -EOPNOTSUPP;

	if (dev->flags & IFF_UP)	/* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map && (map->base_addr != dev->base_addr)) {
		ipc_err("cannot change I/O address");
		return -EOPNOTSUPP;
	}

	/* ignore other fields */
	return 0;
}

/**
 * validate mac address for wwan devices
 */
static int ipc_wwan_eth_validate_addr(struct net_device *dev)
{
	return eth_validate_addr(dev);
}

/**
 * return valid TX queue for the mapped VLAN device
 */
static u16 ipc_wwan_select_queue(struct net_device *dev, struct sk_buff *skb,
				void *accel_priv,
				select_queue_fallback_t fallback)
{
	u16 tag = 0;
	u16 txqn = 0xFFFF;
	struct ipc_wwan *this = ipc_wwan_get_instance_from_netdev(dev);

	if (unlikely(!this || !dev || !skb)) {
		ipc_err("invalid params");
		return txqn;
	}

	/* get VLAN tag for the current skb
	 * if the packet is untagged, return the default queue.
	 */
	if (vlan_get_tag(skb, &tag) < 0)
		return WWAN_DEFAULT_TXQ;

	/* TX Queues are allocated as following:
	 *
	 * if vlan ID == 0 is used for VLAN root device i.e. WWAN0.
	 * Assign default TX Queue which is 0.
	 *
	 * if vlan ID >= IMEM_WWAN_CTRL_VLAN_ID_START
	 * && <= IMEM_WWAN_DATA_LLC_ID_END then we use default
	 * TX Queue which is 0.
	 *
	 * if vlan ID >= IMEM_WWAN_DATA_VLAN_ID_START
	 * && <= IMEM_WWAN_DATA_VLAN_ID_END then allocate separate
	 * TX Queue to each VLAN ID.
	 *
	 * For any other vlan ID return invalid Tx Queue
	 *
	 * Note: this should be applicable for IOSM IP MUX sessions only.
	 * The rational behind the above allocation is that, currently uplink
	 * flow control feature is only enabled on the MUX based IP channel, so
	 * allocate each MUX based IP channels with separate TX queues so
	 * that their TX queue can be controlled seperately to achieve flow
	 * control. For control and rest of the channels we don't need
	 * currently any flow control so leave them on one default TX Queue
	 * and Let IP stack handle them.
	 * If in future, We have to enable flow control or other QoS features
	 * on any other channel then we can create additional TX Queue
	 * depending on the requirements
	 */
	if (tag >= IMEM_WWAN_DATA_VLAN_ID_START
	&& tag <= IMEM_WWAN_DATA_VLAN_ID_END)
		txqn = tag;
	else if ((tag >= IMEM_WWAN_CTRL_VLAN_ID_START
	&& tag <= IMEM_WWAN_DATA_LLC_ID_END) || tag == WWAN_ROOT_VLAN_TAG)
		txqn = WWAN_DEFAULT_TXQ;

	ipc_dbg("VLAN tag = %u, TX Queue selected %u", tag, txqn);
	return txqn;
}

static const struct net_device_ops ipc_wwandev_ops = {
	.ndo_open = ipc_wwan_open,
	.ndo_stop = ipc_wwan_stop,
	.ndo_start_xmit = ipc_wwan_transmit,
	.ndo_change_mtu = ipc_wwan_change_mtu,
	.ndo_validate_addr = ipc_wwan_eth_validate_addr,
	.ndo_do_ioctl = ipc_wwan_ioctl,
	.ndo_set_config = ipc_wwan_set_config,
	.ndo_get_stats = ipc_wwan_get_stats,
	.ndo_vlan_rx_add_vid = ipc_wwan_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = ipc_wwan_vlan_rx_kill_vid,
	.ndo_set_mac_address = ipc_wwan_change_mac_addr,
	.ndo_select_queue = ipc_wwan_select_queue,
};


/**
 * Refer to header file for description
 */
int ipc_wwan_get_vlan_stats(struct ipc_wwan *this, int id,
		bool tx, unsigned long *packets,
		unsigned long *bytes)
{
	int idx;

	if (unlikely(!this || !packets || !bytes)) {
		ipc_err("Invalid args");
		return -1;
	}

	idx = ipc_wwan_get_vlan_devs_nr(this,
		ipc_wwan_mux_session_to_vlan_tag(id));

	if (unlikely(idx < 0 || idx >= IPC_WWAN_MAX_VLAN_ENTRIES)) {
		ipc_dbg("Invalid VLAN device index %d", id);
		return -EINVAL;
	}

	if (tx) {
		*packets = this->vlan_devs[idx].stats.tx_packets;
		*bytes = this->vlan_devs[idx].stats.tx_bytes;
	} else {
		*packets = this->vlan_devs[idx].stats.rx_packets;
		*bytes = this->vlan_devs[idx].stats.rx_bytes;
	}

	return 0;
}

/**
 * Refer to header file for description
 */
int ipc_wwan_update_stats(struct ipc_wwan *this, int id, size_t len, bool tx)
{
	int idx = 0;

	if (unlikely(!this)) {
		ipc_err("No such device");
		return -ENODEV;
	}

	idx = ipc_wwan_get_vlan_devs_nr(this,
		ipc_wwan_mux_session_to_vlan_tag(id));

	if (unlikely(idx < 0 || idx >= IPC_WWAN_MAX_VLAN_ENTRIES)) {
		ipc_err("Invalid VLAN device index");
		return -EINVAL;
	}

	if (tx) {
		/* Update vlan device tx statistics */
		this->vlan_devs[idx].stats.tx_packets++;
		this->vlan_devs[idx].stats.tx_bytes += len;
		/* Update root device tx statistics */
		this->stats.tx_packets++;
		this->stats.tx_bytes += len;
	} else {
		/* Update vlan device rx statistics */
		this->vlan_devs[idx].stats.rx_packets++;
		this->vlan_devs[idx].stats.rx_bytes += len;
		/* Update root device rx statistics */
		this->stats.rx_packets++;
		this->stats.rx_bytes += len;
	}

	return 0;
}

/**
 * Refer to header file for description
 */
int ipc_wwan_tx_flowctrl(struct ipc_wwan *this, int id, bool on)
{
	u16 vid = ipc_wwan_mux_session_to_vlan_tag(id);

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return -EINVAL;
	}

	ipc_dbg("MUX session id[%d]: %s", id, on ? "Enable" : "Disable");
	if (on)
		netif_stop_subqueue(this->netdev, vid);
	else
		netif_wake_subqueue(this->netdev, vid);

	ipc_trc_ul_flowctrl_event(vid, on ? 1 : 0);

	return 0;
}

/**
 * wwan device type
 */
static struct device_type wwan_type = {
	.name	= "wwan"
};


/**
 * ipc wwan constructor
 */
static bool ipc_wwan_ctor(struct ipc_wwan *this, struct net_device *netdev,
	const struct ipc_wwan_ops *ops, void *ops_instance,
	unsigned int instance_nr, struct ipc_dbg *dbg)
{
	int ret;

	if (unlikely(!netdev || !ops || !ops_instance)) {
		ipc_err("Invalid arguments");
		return false;
	}

	this->dbg = dbg;
	this->netdev = netdev;
	this->is_registered = false;

	this->ops = *ops;
	this->vlan_devs_nr = 0;
	this->ops_instance = ops_instance;

	this->timesync_cb = NULL;
	this->timesync_instance = NULL;

	spin_lock_init(&this->lock);
	mutex_init(&this->if_mutex);

	/* allocate random ethernet address */
	eth_random_addr(netdev->dev_addr);
	netdev->addr_assign_type = NET_ADDR_RANDOM;

	snprintf(netdev->name, IFNAMSIZ, "%s%d", "wwan", instance_nr);
	netdev->netdev_ops = &ipc_wwandev_ops;
	netdev->flags |= IFF_NOARP;
	netdev->features |=
		NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_FILTER;
	SET_NETDEV_DEVTYPE(netdev, &wwan_type);

	ipc_dbg("wwan register name='%s' addr=%pM",
		netdev->name, netdev->dev_addr);

	ret = register_netdev(netdev);

	if (unlikely(ret)) {
		ipc_err("register_netdev failed, %d", ret);
		return false;
	}

	this->is_registered = true;

	register_netdevice_notifier(&ipc_wwan_dev_notifier);

	netif_device_attach(netdev);

#if (KERNEL_VERSION(4, 10, 0) < LINUX_VERSION_CODE)
	netdev->max_mtu = IPC_MEM_MAX_MTU_SIZE;
#endif


	return true;
}

/**
 * ipc wwan destructor
 */
static void ipc_wwan_dtor(struct ipc_wwan *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid args");
		return;
	}

	ipc_dbg("wwan unregister");

	unregister_netdevice_notifier(&ipc_wwan_dev_notifier);

	if (this->is_registered)
		unregister_netdev(this->netdev);
}

/**
 * Refer to header file for description
 */
struct ipc_wwan *ipc_wwan_alloc(const struct ipc_wwan_ops *imem_ops,
		void *ops_instance, unsigned int instance_nr,
		struct ipc_dbg *dbg)
{
	struct ipc_wwan *this = NULL;

	/* allocate ethernet device */
	struct net_device *netdev = alloc_etherdev_mqs(sizeof(*this),
		WWAN_MAX_TXQ, WWAN_MAX_RXQ);

	if (netdev) {
		this = netdev_priv(netdev);

		if (!ipc_wwan_ctor(this, netdev, imem_ops, ops_instance,
			instance_nr, dbg))
			ipc_wwan_dealloc(&this);
	} else {
		ipc_err("alloc_etherdev_mqs() failed");
	}

	return this;
}

/**
 * Refer to header file for description
 */
void ipc_wwan_dealloc(struct ipc_wwan **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_wwan_dtor(*this_pp);
		free_netdev((*this_pp)->netdev);
		*this_pp = NULL;
	}
}

/**
 * Refer to header file for description
 */
void ipc_wwan_flush(struct ipc_wwan *this)
{
#if defined(IMC_NET_ENABLE_NAPI)
	if (!this)
		return;

	ipc_dbg("chid[%d]", this->channel_id);
	napi_gro_flush(&this->napi, true);
#endif
}

/**
 * Refer to header file for description
 */
void ipc_wwan_register_timesync(struct ipc_wwan *this,
	int (*timesync_cb)(void *, struct ipc_timesync *), void *instance)
{
	if (!this || !timesync_cb) {
		ipc_err("Invalid arguments");
		return;
	}

	this->timesync_cb = timesync_cb;
	this->timesync_instance = instance;
}


bool ipc_wwan_is_tx_stopped(struct ipc_wwan *this, int id)
{
	u16 vid = ipc_wwan_mux_session_to_vlan_tag(id);

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return false;
	}

	return __netif_subqueue_stopped(this->netdev, vid);
}
