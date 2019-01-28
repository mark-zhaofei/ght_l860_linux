/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>

#include "imc_ipc_imem.h"
#include "imc_ipc_util.h"
#include "imc_ipc_export.h"
#include "imc_ipc_netlink.h"
#include "imc_ipc_dbg.h"


/* Structure of the private netlink data
 */
struct ipc_netlink {
	/* netlink socket */
	struct sock *sock;
	u32 seq;
	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

/* initialize netlink interface
 *
 * @this: pointer to netlink data struct
 *
 * returns zero on success
 */
static int ipc_netlink_ctor(struct ipc_netlink *this)
{
	int retval;

	struct netlink_kernel_cfg cfg = {
		.input = NULL,
		.groups = 0,
	};

	if (unlikely(!this)) {
		ipc_err("invalid argument");
		return -EINVAL;
	}

	this->sock = netlink_kernel_create(&init_net, NL_UNIT, &cfg);
	if (this->sock) {
		ipc_pr_dbg("Netlink socket successfully created");
		retval = 0;
	} else {
		ipc_err("Netlink socket creation failed");
		retval = -EAGAIN;
	}

	return retval;
}

/* cleanup netlink interface */
static void ipc_netlink_dtor(struct ipc_netlink *this)
{
	if (this && this->sock) {
		netlink_kernel_release(this->sock);
		this->sock = NULL;
		this->dbg = NULL;
		ipc_pr_dbg("Netlink socket released");
	}
}

/* send a netlink broadcast message */
static int ipc_netlink_broadcast(struct ipc_netlink *this, int type,
		void *buf, int buf_size, struct ipc_dbg *dbg)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh;
	const u32 group = 1;
	int result;

	if (unlikely(!this->sock))
		return -ENODEV;

	if (!netlink_has_listeners(this->sock, group))
		return -ESRCH;

	skb = nlmsg_new(buf_size, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ipc_err("out of memory");
		return -ENOMEM;
	}

	this->seq++;
	nlh = nlmsg_put(skb, 0, this->seq, type, buf_size, 0);
	if (!nlh) {
		kfree_skb(skb);
		ipc_err("message size error");
		return -EMSGSIZE;

	}

	memcpy(nlmsg_data(nlh), buf, buf_size);
	memset(&NETLINK_CB(skb), 0, sizeof(struct netlink_skb_parms));
	NETLINK_CB(skb).portid = 0;	/* multicast */
	NETLINK_CB(skb).dst_group = group;
	NETLINK_CB(skb).sk = this->sock;
	result = netlink_broadcast(this->sock, skb, 0, group, GFP_ATOMIC);
	if (result < 0) {
		kfree_skb(skb);
		ipc_err("netlink returned %d", result);
	}

	return result;
}

/* send an event to all listners
 */
int ipc_netlink_event(struct ipc_netlink *this, char *event,
				struct ipc_dbg *dbg)
{
	int result;

	if (unlikely(!this || !event)) {
		ipc_err("invalid arguments");
		return -EINVAL;
	}

	this->dbg = dbg;

	result = ipc_netlink_broadcast(this, NL_TYPE_EVENT,
			event, strlen(event) + 1, dbg);
	if (result == 0) {
		ipc_dbg("event %s forwarded to all listeners", event);
		return 0;
	}

	ipc_dbg("no listeners for event %s", event);
	return result;
}


/**
 * header file for description
 */
struct ipc_netlink *ipc_netlink_alloc(void)
{
	struct ipc_netlink *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("memory allocation");
		goto ret_fail;
	}

	if (ipc_netlink_ctor(this)) {
		ipc_err("netlink initialization");
		goto init_fail;
	}

	return this;

init_fail:
	ipc_util_kfree(this);
ret_fail:
	return NULL;
}

/**
 * header file for description
 */
void ipc_netlink_dealloc(struct ipc_netlink **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_netlink_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
