/*
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_MMAP_H
#define IMC_IPC_MMAP_H

struct ipc_mmap;
struct ipc_pcie;
struct ipc_dbg;


/* Callbacks to trigger functionality outside of ipc_mmap module. */
struct ipc_mmap_ops {
	/* This callback is expected to send a "map(region_id, size, addr)"-
	 * message to the device,
	 * instance will be preset with the value defined as ops_instance in
	 * ipc_mmap_alloc. Return 0 on success, < 0 on failure
	 */
	int (*send_map_msg)(void *instance, unsigned int region_id, size_t size,
		unsigned long addr);

	/* This callback is expected to send a "unmap(region_id)"-message to the
	 * device,
	 * instance will be preset with the value defined as ops_instance in
	 * ipc_mmap_alloc. Return 0 on success, < 0 on failure
	 */
	int (*send_unmap_msg)(void *instance, unsigned int region_id);
};

/*
 * Allocate an ipc_mmap instance.
 *
 * @ops: pointer to callback functions for sending map/unmap messages to device
 * @ops_instance: instance pointer for callback functions
 * @pcie: pcie instance
 * @instance_nr: modem instance number
 * @dbg: pointer to ipc_dbg structure
 *
 * returns address of ipc_mmap instance
 */
struct ipc_mmap *ipc_mmap_alloc(const struct ipc_mmap_ops *ops,
	void *ops_instance, struct ipc_pcie *pcie, unsigned int instance_nr,
	struct ipc_dbg *dbg);

/*
 * Free allocated imc_mmap instance, invalidating the pointer.
 *
 * @this_pp: pointer to pointer to imc_mmap instance
 */
void ipc_mmap_dealloc(struct ipc_mmap **this_pp);

#endif /* IMC_IPC_MMAP_H */
