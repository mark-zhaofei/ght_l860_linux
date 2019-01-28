/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_EXPORT_H
#define IMC_IPC_EXPORT_H

#define NL_UNIT			(MAX_LINKS - 1)

/*
 * Command and binary header types are unused
 * and should be removed later. They are referenced
 * in our test code. We are maintaining them
 * in order to avoid the changes in the application
 * layer and maintain backward compatibility.
 */
/* Netlink header types */
#define NL_TYPE_CMD		1	/* payload is cmd string */
#define NL_TYPE_BIN		2	/* payload is binary */
#define NL_TYPE_EVENT		3	/* payload is event string */

/* Baseband reset command */
#define NL_CMD_BB_RESET		"RESET"	/* perform baseband reset */

/* Baseband event strings */
#define NL_EVENT_MDM_NOT_READY		"MDM_NOT_READY"
#define NL_EVENT_ROM_READY		"ROM_READY"
#define NL_EVENT_MDM_READY		"MDM_READY"
#define NL_EVENT_CRASH			"CRASH"
#define NL_EVENT_CD_READY		"CD_READY"
#define NL_EVENT_CD_READY_LINK_DOWN	"CD_READY_LINK_DOWN"
#define NL_EVENT_MDM_TIMEOUT		"MDM_TIMEOUT"

/* Trigger time sync procedure.
 *
 *  Usage:
 *
 *  int fd = socket(AF_PACKET, SOCK_DGRAM, 0);
 *  struct sioc_ipc_time_sync ts = { 0 };
 *  struct ifreq ifr;
 *
 *  ts.size = sizeof(ts);
 *  strncpy(ifr.ifr_ifrn.ifrn_name, "wwan0", sizeof(ifr.ifr_ifrn.ifrn_name));
 *  ifr.ifr_ifru.ifru_data = (void *)&ts;
 *  ioctl(fd, SIOC_IPC_TIME_SYNC, (caddr_t)&ifr);
 */
#define SIOC_IPC_TIME_SYNC		SIOCDEVPRIVATE

/* Set region ID for the next memory region mapped through mmap() call.
 *
 * Usage:
 *
 * int fd = open("/dev/imc_ipc0_mmap0", O_RDWR);
 * ioctl(fd, SIOC_IPC_REGION_ID_SET, region_id);
 * mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
 */
#define SIOC_IPC_REGION_ID_SET		(SIOCDEVPRIVATE + 1)


/**
 * Time Unit
 */
enum sioc_ipc_time_unit {
	SIOC_IPC_TIME_UNIT_SEC = 0,
	SIOC_IPC_TIME_UNIT_MILLI_SEC = 1,
	SIOC_IPC_TIME_UNIT_MICRO_SEC = 2,
	SIOC_IPC_TIME_UNIT_NANO_SEC = 3,
	SIOC_IPC_TIME_UNIT_PICO_SEC = 4,
	SIOC_IPC_TIME_UNIT_FEMTO_SEC = 5,
	SIOC_IPC_TIME_UNIT_ATTO_SEC = 6,
	SIOC_IPC_TIME_UNIT_UNKNOWN = 7
};


/**
 * Structure for the time synchronization.
 */
struct sioc_ipc_time_sync {
	size_t size;     /* in: size of this struct, to be filled by caller*/
	unsigned long id; /* out: tsync id returned by IOSM driver */
	unsigned long long local_time; /* out: local timestamp */
	unsigned long long remote_time; /* out: remote timestamp */
	unsigned int local_time_unit; /* out: local timestamp unit */
	unsigned int remote_time_unit; /* out: remote timestamp unit */
};

#endif				/* IMC_IPC_EXPORT_H */
