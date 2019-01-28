/*
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef _IMC_IPC_GPIO_HANDLER_H
#define _IMC_IPC_GPIO_HANDLER_H


/*
 *  GPIO signals signalled to host driver on change
 */
enum ipc_mdm_ctrl_gpio_signal {
	IPC_MDM_CTRL_RESET_DET,
	IPC_MDM_CTRL_WAKE,
};


#if defined(IPC_EXTERNAL_BUILD) || !defined(IPC_GPIO_MDM_CTRL)

#define ipc_gpio_handler_alloc(a, b, c) NULL
#define ipc_gpio_handler_dealloc(a)
#define ipc_gpio_handler_suspend(a)
#define ipc_gpio_handler_resume(a)
#define ipc_mdm_gpio_module_signal_perst(a, b, c)

#define ipc_mdm_ctrl_register_notify(a)
#define ipc_mdm_ctrl_unregister_notify(a)
#define ipc_mdm_gpio_module_config_s3(a, b)
#define ipc_mdm_gpio_module_signal_perst(a, b, c)

#else

#include "imc_ipc_gpio_handler_priv.h"

#endif /* IPC_EXTERNAL_BUILD */

#endif /* _IMC_IPC_GPIO_HANDLER_H */

