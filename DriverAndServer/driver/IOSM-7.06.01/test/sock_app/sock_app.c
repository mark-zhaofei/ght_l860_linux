/*
 * sock_app.c
 *
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <netinet/ip.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

#include "../safeclib/safe_str_lib.h"
/* Default receive buffer size */
#define DEFAULT_BUFFER_SIZE (128 * 1024)

/* VLAN default MTU
 *
 * Note: The default MTU should be changed when the driver default MTU size
 * changes.
 */

#define DEFAULT_VLAN_MTU 16384

/* Allowed min VLAN MTU */
#define MIN_VLAN_MTU 1024

/* Allowed max VLAN MTU */
#define MAX_VLAN_MTU 65535

/* ROOT MTU */
#define ROOT_MTU 65535

/* Ethernet header length */
#define HDR_LEN 14

/* Procfs entry to read from to get all the network interfaces. */
#define NET_PROCFS "/proc/net/dev"

/* Trace VLAN id */
#define TRACE_VLAN_ID 261

static const char *vlan_name_default = "wwan0.trc0";
#define IF_NAMESIZE 10

char buff[16384];

#define err(fmt, args...) \
	fprintf(stderr, "line %d: " fmt "\n", __LINE__, ##args)

#define log(fmt, args...) \
	fprintf(stdout, "line %d: " fmt "\n", __LINE__, ##args)

/* Reader thread which reads sockets and writes output to a file */
pthread_t reader_thread;

/* Arguments to the thread. */
struct sock_app_data {
	int socket_fd;
	unsigned int tput_interval;
	unsigned int recv_buff_size;
	unsigned int mtu_size;
	char *output_file_name;
	FILE *output_file;
	const char *vlan_dev_name;
	const char *root_dev_name;
	int trace_vlan_id;
	char *recv_buffer;
	size_t rx_bytes;
	int has_thread_terminated;
	int wait_modem_ready;
	unsigned int stats;
	unsigned int poll;
};

/* Forward declarations. */
int configure_interface(const char *root_name, const char *vlan_dev_name,
		int trace_vlan_id, int wait_modem_ready, int mtu_size, int *if_index);
int open_trace_socket(int if_index);
int bring_up_trace_interface(int socket_fd, const char *vlan_dev_name);

/* Print statistics from the VLAN network device. */
static void print_stats(void)
{
	FILE *file,*temp_file;
	const char *filename = NET_PROCFS, *temp_filename = "temp.txt";
	char buf[1024];
	unsigned long long rx_bytes, rx_packets, tx_bytes , tx_packets;
	unsigned long rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, tx_compressed;
	unsigned long rx_multicast, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier;
	int rd=0, wr=0, ws=0, ret;
	char *str_ptr;

	file = fopen(filename, "r");
	if(!file) {
		err("Unable to open procfs");
		return;
	}

	/* First two lines only contain headers. */
	fgets(buf, sizeof(buf), file);
	fgets(buf, sizeof(buf), file);

	/* Loop for all the lines. */
	while (fgets(buf, sizeof(buf), file))
		if (strstr_s(buf, 1024, vlan_name_default, IF_NAMESIZE, &str_ptr)==EOK)
			break;
	log("buf %s", buf);

	while (rd < strnlen_s(buf,1024))
		if (buf[rd++] == ':')
			break;

	while (rd < strnlen_s(buf,1024)) {
		if(isdigit(buf[rd])) {
			if (ws)
				buf[wr++] = ' ';
			ws = 0;
			buf[wr++] = buf[rd];
		}

		if (isspace(buf[rd]))
			ws = 1;

		rd++;
	}

	buf[wr] = '\0';

	temp_file = fopen(temp_filename,"w+");

	if(!temp_file)
	{
		err("Unable to open temp file");
		fclose(file);
		return;
	}

	fwrite(buf,1,sizeof(buf),temp_file);
	rewind(temp_file);

	ret = fscanf(temp_file, "%llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu %lu",
			&rx_bytes, &rx_packets, &rx_errs, &rx_drop,
			&rx_fifo, &rx_frame, &rx_compressed,
			&rx_multicast, &tx_bytes, &tx_packets,
			&tx_errs, &tx_drop, &tx_fifo,
			&tx_colls, &tx_carrier,
			&tx_compressed);

	if(ret)
		log("Rx bytes:%llu packets:%llu Tx bytes: %llu packets:%llu",
				rx_bytes, rx_packets, tx_bytes, tx_packets);
	fclose(temp_file);

	if(remove(temp_filename)!=0)
		log("Error in deleting temp file");

	fclose(file);
}

/* Cleanup function for reader thread */
static void cleanup_function(void *_arg_p)
{
	struct sock_app_data *arg_p = _arg_p;

	if (arg_p)
		arg_p->has_thread_terminated = 1;
}

static int configure_after_modem_reset(struct sock_app_data *arg_p)
{
	int len, if_index;

	close(arg_p->socket_fd);

	if (configure_interface(arg_p->root_dev_name, arg_p->vlan_dev_name,
		arg_p->trace_vlan_id, 1, arg_p->mtu_size, &if_index) != 0) {
		err("unable to configure the trace interface");
		return -1;

	}

	arg_p->socket_fd = open_trace_socket(if_index);
	if (arg_p->socket_fd == -1)
		return -1;

	if (bring_up_trace_interface(arg_p->socket_fd, arg_p->vlan_dev_name) != 0) {
		err("Error bring up trace interface");
		return -1;
	}

	/* First read should always result into an error, because we
	 * do bind and then if_up.
	 */
	len = read(arg_p->socket_fd, arg_p->recv_buffer, arg_p->recv_buff_size);
	if (len >= 0 ||  errno != ENETDOWN) {
		err("Fatal error. Network down not received.");
		return -1;
	}

	return 0;
}

/* Reader thread function. */
static void *copy_function(void *_arg_p)
{
	struct sock_app_data *arg_p = _arg_p;
	char *temp;
	int len;

	if (!arg_p)
		return NULL;

	temp = &arg_p->recv_buffer[HDR_LEN];
	pthread_cleanup_push(&cleanup_function, arg_p);

	if (configure_after_modem_reset(arg_p) != 0) {
		err("unable to configure modem. Terminating");
		return NULL;
	}

	log("Getting data from VLAN device. Press Ctrl-C for exit.");

	while (1) {
		/* Read from the socket. */
		len = read(arg_p->socket_fd, arg_p->recv_buffer,
				arg_p->recv_buff_size);

		/* Check for error on reading */
		if (len < 0) {
			err("Error reading : %d %s", errno, strerror(errno));
			if ((errno == ENETDOWN) && (arg_p->poll)) {
				arg_p->rx_bytes = -1;

				if (configure_after_modem_reset(arg_p) != 0) {
					err("unable to configure modem. Terminating");
					break;
				}

				log("continue to read after modem reset");
				continue;
			} else
				break;
		}

		len -= HDR_LEN;

		/* Write to the file excluding ethernet header */
		if (fwrite(temp, sizeof(char), len, arg_p->output_file) != len)
			break;

		arg_p->rx_bytes += len;

	}

	pthread_cleanup_pop(1);
	return NULL;
}

/*
 * Deletes a VLAN device
 *
 * @socket_fd: open socket
 * @vlan_name: vlan device name
 *
 * returns -1 on failure, 0 on success
 */
static int del_vlan_device(struct sock_app_data *data)
{
	struct vlan_ioctl_args if_request;

	if (data->socket_fd < 0) {
		err("socket() failed, errno %d", errno);
		return -1;
	}

	if(data->stats)
		print_stats();

	memset(&if_request, 0, sizeof(if_request));

	strncpy_s(if_request.device1, sizeof(if_request.device1), data->vlan_dev_name, IF_NAMESIZE);
	if_request.cmd = DEL_VLAN_CMD;

	if (ioctl(data->socket_fd, SIOCSIFVLAN, &if_request) < 0) {
		log("Did not delete VLAN device : %s Reason: %d %s",
				data->vlan_dev_name, errno, strerror(errno));
		close(data->socket_fd);
		return -1;
	}

	log("Deleted vlan device : %s", data->vlan_dev_name);

	return 0;
}

/* signal handler to  make sure we are gracefully releasing any resources
 * before aborting
 */
static void sighandler(int signo)
{
	switch (signo) {

	/* kill the reader thread */
	case SIGINT:
		pthread_kill(reader_thread, SIGUSR1);
		break;

	/* Reader thread on signal handling should exit the thread. */
	case SIGUSR1:
		pthread_exit(NULL);
		return;

	default:
		break;
	}
}

/*
 * Adds a VLAN device to root network device
 *
 * @socket_fd: open socket
 * @root_dev: root device name
 * @vlan_name: vlan device name
 * @vlan_id: vlan id
 *
 * returns -1 on failure, 0 on success
 */
static int add_vlan_device(int socket_fd, const char *root_dev,
		const char *vlan_name, int vlan_id)
{
	struct vlan_ioctl_args if_request;
	struct ifreq req;
	char raw_vlan_name[IFNAMSIZ];

	/* Check if VLAN device exists. */
	memset(&if_request, 0, sizeof(if_request));


	snprintf(if_request.device1, sizeof(if_request.device1),
                       "%s", vlan_name);

	if_request.cmd = GET_VLAN_VID_CMD;
	if (ioctl(socket_fd, SIOCSIFVLAN, &if_request) == 0) {
		if (vlan_id == if_request.u.VID) {
			if_request.cmd = GET_VLAN_REALDEV_NAME_CMD;
			if (ioctl(socket_fd, SIOCSIFVLAN, &if_request) == 0 &&
					strncmp(if_request.u.device2, root_dev,
						sizeof(if_request.u.device2)) == 0) {

				/* If the VLAN device already exists, then we
				 * will never get the network down event in
				 * the copy function. The logic will fail.
				 */
				err("Vlan Device %s already exists.",
						vlan_name);
				return -1;
			}
		}
	}

	/* Add a VLAN device. */
	memset(&if_request, 0, sizeof(if_request));
	strncpy_s(if_request.device1, sizeof(if_request.device1), root_dev, IF_NAMESIZE);
	if_request.u.VID = vlan_id;
	if_request.cmd = ADD_VLAN_CMD;

	if (ioctl(socket_fd, SIOCSIFVLAN, &if_request) < 0) {
		err("Adding vlan device %s on %s with id %d failed : %d %s.",
				vlan_name, root_dev, vlan_id,
				errno, strerror(errno));
		return -1;
	}

	snprintf(raw_vlan_name, IFNAMSIZ, "%s.%d", root_dev, vlan_id);

	/* Change the name of the VLAN device */
	memset(&req, 0, sizeof(req));
	strncpy_s(req.ifr_newname, sizeof(req.ifr_newname), vlan_name, IF_NAMESIZE);
	strncpy_s(req.ifr_name, sizeof(req.ifr_name), raw_vlan_name, IFNAMSIZ);

	if (ioctl(socket_fd, SIOCSIFNAME, &req) < 0) {
		err("Adding vlan device %s (%s) with id %d failed.",
				vlan_name, raw_vlan_name, vlan_id);
		return -1;
	}

	log("Added vlan device %s with VLAN id %d", vlan_name, vlan_id);

	return 0;
}

/*
 * Installs a signal handlers for the application
 *
 * returns -1 on failure, 0 on success
 */
static int install_sig_handler(void)
{
	struct sigaction sa;
	memset(&sa,0,sizeof(sa));
	/* Install sighandler */
	sa.sa_handler = sighandler;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) < 0) {
		err("failed to install SIGINT sighandler");
		return -1;
	}

	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		err("failed to install SIGUSR1 sighandler");
		return -1;
	}

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		err("failed to install SIGTERM sighandler");
		return -1;
	}

	return 0;
}

/*
 * Checks if the network device exists
 *
 * @socket_fd: socket file desc.
 * @device_name: network device name
 *
 * return 0 if exists, otherwise -1
 */
static int check_if_device_exists(int socket_fd, const char *device_name)
{
	int i, numif;
	struct ifconf ifc;
	struct ifreq *ifr;
	FILE *fh;
	int indicator=0;

	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;
	if (ioctl(socket_fd, SIOCGIFCONF, &ifc) < 0) {
		err("SIOCGIFCONF: %s\n", strerror(errno));
		return -1;
	}

	numif = ifc.ifc_len / sizeof(*ifr);
	ifr = (struct ifreq *)buff;

	for (i = 0; i < numif ; i++) {
		if(strcmp_s(ifr[i].ifr_name,strnlen_s(ifr[i].ifr_name, IF_NAMESIZE), device_name, &indicator) == EOK) {
			if (!indicator) {
				log("Device found : %s", ifr[i].ifr_name);
				return 0;
			}
		}
	}

	/* Read the interfaces from procfs entry */
	fh = fopen(NET_PROCFS, "r");
	if (!fh) {
		err("Unable to open Procfs entry");
		return -1;
	}

	/* Discard first two lines */
	fgets(buff, sizeof(buff), fh);
	fgets(buff, sizeof(buff), fh);

	while (fgets(buff, sizeof(buff), fh)) {
		char *read_ptr = buff;
		char *write_ptr = buff;

		/* Find the name of the interface. Discard rest */
		while (read_ptr != NULL && *read_ptr != ':' && read_ptr < &buff[16384]) {
			if (!isspace(*read_ptr))
				*write_ptr++ = *read_ptr;
			read_ptr++;
		}

		*write_ptr = '\0';

		if (strcmp_s(device_name, strnlen_s(device_name, IF_NAMESIZE), buff, &indicator)==EOK) {
			if(!indicator) {
				log("Device found : %s", buff);
				fclose(fh);
				return 0;
			}
		}
	}

	/* Device not found. */
	fclose(fh);
	return -1;
}

/*
 * configures root network device and adds a vlan device to it
 *
 * @root_name: root network device name
 * @vlan_name: vlan device name
 * @vlan_id: vlan id
 *
 * returns -1 on failure, 0 on success
 */
static int config_root_device(const char *root_name,
		const char *vlan_name, int vlan_id, int socket_fd)
{
	struct ifreq req;

	/* Check if root device is available. */
	if (check_if_device_exists(socket_fd, root_name)) {
		err("Root device does not exist. Is the modem powered and flashed?");
		goto root_dev_err;
	}

	/* Get the MTU size of root device */
	memset(&req, 0, sizeof(req));
	strncpy_s((char *)req.ifr_ifrn.ifrn_name, sizeof(req.ifr_ifrn.ifrn_name),(char *)root_name, IF_NAMESIZE);
	if (ioctl(socket_fd, SIOCGIFMTU, &req) < 0) {
		err("ioctl() SIOCGIFMTU failed %d", errno);
		goto root_dev_err;
	}

	/* Set the MTU size if required. */
	if (req.ifr_ifru.ifru_mtu != ROOT_MTU) {

		log("Set ROOT MTU %d", ROOT_MTU);
		req.ifr_ifru.ifru_mtu = ROOT_MTU;
		if (ioctl(socket_fd, SIOCSIFMTU, &req) < 0) {
			err("ioctl() SIOCSIFMTU failed %d", errno);
			goto root_dev_err;
		}
	}

	/* Get the network interface set flags */
	req.ifr_flags = 0;
	strncpy_s((char *)req.ifr_ifrn.ifrn_name,sizeof(req.ifr_ifrn.ifrn_name),(char *)root_name, IF_NAMESIZE);
	if (ioctl(socket_fd, SIOCGIFFLAGS, &req) < 0) {
		err("ioctl() SIOCSIFFLAGS failed %d :%s",
				errno, strerror(errno));
		goto root_dev_err;
	}

	/* Bring up the network interface, if not already UP */
	if (!(req.ifr_flags & IFF_UP)) {
		req.ifr_flags |= IFF_UP;
		strncpy_s((char *)req.ifr_ifrn.ifrn_name, sizeof(req.ifr_ifrn.ifrn_name),(char *)root_name, IF_NAMESIZE);
		if (ioctl(socket_fd, SIOCSIFFLAGS, &req) < 0) {
			err("ioctl() SIOCSIFFLAGS failed %d :%s",
					errno, strerror(errno));
			goto root_dev_err;
		}
	}

	/* Add a VLAN device */
	if (add_vlan_device(socket_fd, root_name, vlan_name, vlan_id)) {
		err("Unable to create VLAN id");
		goto root_dev_err;
	}

	return 0;

root_dev_err:
	return -1;
}

static void disable_ipv6(const char *netdev_name)
{
	char procfs_path[2000];
	int proc_fd;

	snprintf(procfs_path, 2000,
			"/proc/sys/net/ipv6/conf/%s/disable_ipv6",
			netdev_name);

	proc_fd = open(procfs_path, O_WRONLY);
	if (proc_fd < 0) {
		log("IPv6 entry not available:%s.", procfs_path);
		return;
	}

	if((write(proc_fd, "1", 1)) != 1)
		log("Error in write...");

	close(proc_fd);
}

/*
 * configure vlan device
 *
 * @vlan_name: vlan device name
 * @vlan_id: vlan id of the device
 * @if_index: pointer to integer where it returns IF index of the device
 *
 * returns -1 on failure, 0 on success
 */
static int config_vlan_device(const char *vlan_name, int socket_fd,
		int vlan_id, int *if_index, unsigned int mtu_size)
{
	struct ifreq req;

	/* Get device index */
	memset(&req, 0, sizeof(req));
	strncpy_s((char *)req.ifr_ifrn.ifrn_name, sizeof(req.ifr_ifrn.ifrn_name),(char *)vlan_name, IF_NAMESIZE);
	log("get dev. interface index");
	if (ioctl(socket_fd, SIOCGIFINDEX, &req) < 0) {
		err("ioctl() SIOCGIFINDEX failed %d : %s",
				errno, strerror(errno));
		goto vlan_dev_err;
	}

	*if_index = req.ifr_ifindex;

	/* Disable IPv6 on ProcFs */
	disable_ipv6(vlan_name);

	/* Set VLAN MTU */
	req.ifr_ifru.ifru_mtu = mtu_size;
	strncpy_s((char *)req.ifr_ifrn.ifrn_name,sizeof(req.ifr_ifrn.ifrn_name),(char *)vlan_name, IF_NAMESIZE);
	log("Set MTU %d", mtu_size);

	if (ioctl(socket_fd, SIOCSIFMTU, &req) < 0) {
		err("ioctl() SIOCSIFMTU failed %d", errno);
		goto vlan_dev_err;
	}

	return 0;

vlan_dev_err:
	return -1;
}

/*
 * Check if IOSM driver version if greater than V5.
 *
 * return 0 if driver version >= 6, -1 otherwise.
 *
 */
static int verify_iosm_version(void)
{
	char *version_info_file = "/sys/module/imc_ipc/version";
	char version[100];
	char *src_ver = "1A_V";
	char *read_ptr = NULL, *write_ptr = version;
	float fl_version;
	FILE *sysfs_fd = NULL;
	int file_exists;
	errno_t err;
	/* Check if file exists. */


	/* Read the version information */
	sysfs_fd = fopen(version_info_file, "rx");

	if (sysfs_fd == NULL) {
		err("Unable to open the version info file.");
		file_exists = access(version_info_file, F_OK);
		if (file_exists == -1) {
			err("Version file does not exist. Did you load IPC driver?");
		}
		return -1;
	}

	/* Get the driver version */
	if((fgets(version, 100, sysfs_fd)) !=  NULL) {
		size_t len = strnlen_s(version,100);
		/* remove the newline charcater from fgets output*/
		if(len > 0 && version[len-1] == '\n')
			version[len-1]='\0';
		log("IMC IPC version : %s", version);
	}

	/* Get the driver version */
	err = strstr_s(version,100, src_ver,strnlen_s(src_ver,100),&read_ptr);
	if (err != EOK) {
		err("Unexpected version of the driver : %s", version);
		goto ret_err;
	}

	/* Skip 1A_V string */
	read_ptr += 4;
	while (read_ptr != NULL && (isdigit(*read_ptr) || *read_ptr == '.') &&
			read_ptr < &version[100])
		*write_ptr++ = *read_ptr++;

	*write_ptr = '\0';
	fl_version = strtof(version, NULL);

	if (fl_version < 6) {
		err("Unsupported driver version: %s. Expected version greater than v6.",
				version);
		goto ret_err;
	} else {
		fclose(sysfs_fd);
		return 0;
	}

ret_err :
	if(sysfs_fd)
		fclose(sysfs_fd);
	return -1;
}

/*
 * Gets the options from the user.
 *
 * @argc: argc from main
 * @argv: argv from main
 * @optt: pointer to user options struct
 *
 * returns zero success -1 on error
 */
int get_user_options(int argc, char **argv, struct sock_app_data *data)
{
	int c;


	while ((c = getopt(argc, argv, "d:o:m:r:t:hnsp")) != -1) {
		switch (c) {

		case 'd':
			data->vlan_dev_name = optarg;
			break;

		case 'o':
			data->output_file_name = optarg;
			break;

		case 'm':
			data->mtu_size = strtoul(optarg, NULL, 0);
			break;

		case 'r':
			data->recv_buff_size = strtoul(optarg, NULL, 0);
			break;

		case 'n':
			data->wait_modem_ready = 1;
			break;

		case 't':
			data->tput_interval = strtoul(optarg, NULL, 0);
			break;
		case 's':
			data->stats = 1;
			break;
		case 'p':
			data->poll = 1;
			break;
		case 'h':
			log("Usage: %s [OPTION]...\n"
				"Copies data from trace device into file.\n"
				"\n"
				"Options:\n"
				" -d <vlan device name>     Name of the Trace device. Default is '%s'\n"
				" -m <VLAN MTU size>        Maximum Transmission Unit for trace device. Default is %d bytes\n"
				" -r <Receive buffer size>  Specify size of the receive buffer. Default is %d bytes\n"
				" -o <output file>          Filename to write trace data to.\n"
				" -n                        Wait till modem is ready\n"
				" -t <secs>                 Report throughput every n seconds\n"
				" -s                        Print trace capture statistics since the last reset\n"
				" -p                        Poll after modem reset\n"
				" -h                        Display help\n",
				argv[0], vlan_name_default, DEFAULT_VLAN_MTU,
				DEFAULT_BUFFER_SIZE);
			exit(0);
			break;

		case '?':
			if ((optopt == 'o') || (optopt == 'm') || (optopt == 't'))
				err("Option -%c requires an argument.", optopt);
			else if (isprint (optopt))
				err("Unknown option `-%c'.", optopt);
			else
				err("Unknown option character `\\x%x'", optopt);
			return -1;

		default:
			return -1;

		}
	}

	if (data->output_file_name == NULL) {
		err("Output file not specified");
		return -1;
	}

	if (data->vlan_dev_name == NULL) {
		data->vlan_dev_name = vlan_name_default;
		log ("using default VLAN device :%s", data->vlan_dev_name);
	}

	if (data->mtu_size == 0) {
		data->mtu_size = DEFAULT_VLAN_MTU;
		log("Selecting Default MTU Size : %d", data->mtu_size);
	} else if ((data->mtu_size < MIN_VLAN_MTU) ||
			(data->mtu_size > MAX_VLAN_MTU)) {
		err("MTU size must be between [%d, %d].",
				MIN_VLAN_MTU, MAX_VLAN_MTU);
	}

	if (data->recv_buff_size == 0) {
		data->recv_buff_size = DEFAULT_BUFFER_SIZE;
		log("Selecting Default Buffer Size : %d", data->recv_buff_size);
	}

	return 0;
}

/*
 * Check if trace file already exists from socat.
 *
 * return 1 if trace file exist, 0 otherwise
 */
static int trace_file_exists(void)
{
	char *trace_file1 = "/dev/trc";
	char *trace_file2 = "/dev/trc0";

	/* Check if file exists. */
	if ((access(trace_file1, F_OK) == -1) &&
			(access(trace_file2, F_OK) == -1))
		return 0;
	else
		return 1;
}

static char *read_modem_state(void)
{
	const char *filename = "/sys/kernel/debug/imc_ipc0/mdm_state";
	char temp[120];
	char *ret_value = NULL;
	int fd;
	int len;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		err("Failed to open debugfs entry %s", filename);
		return NULL;
	}

	memset(temp,0,sizeof(temp));
	len = read(fd, temp, sizeof(temp)-1);
	if (len <= 0) {
		err("Failed to read debugfs entry");
		close(fd);
		return NULL;
	}

	temp[len]='\0';

	ret_value = malloc(strnlen_s(temp,120) + 1);
	if (!ret_value)
		err("unable to allocate string of size: %zu", strnlen_s(temp,120) + 1);
	else
		strncpy_s(ret_value, 120, temp,sizeof(temp));

	close(fd);
	return ret_value;
}

static int wait_till_modem_ready(void)
{
	struct sockaddr_nl nlsaddr;
	struct pollfd pfd;
	char buf[512];
	char *mdm_state;
	char *str_ptr;
	int indicator=0;

	memset(&nlsaddr, 0, sizeof(struct sockaddr_nl));
	nlsaddr.nl_family = AF_NETLINK;
	nlsaddr.nl_pid = getpid();
	nlsaddr.nl_groups = -1;

	pfd.events = POLLIN;
	pfd.fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (pfd.fd < 0) {
		err("Netlink Socket Open failed.");
		return -1;
	}

	if (bind(pfd.fd, (void *)&nlsaddr, sizeof(struct sockaddr_nl))) {
		err("Netlink Socket bind failed.");
		close(pfd.fd);
		return -1;
	}

	/* First check if modem ready is already reached. */
	mdm_state = read_modem_state();

	/* Check if the modem is in ready state. */
	if (mdm_state) {
		if (strcmp_s(mdm_state,strnlen_s(mdm_state,20),"MDM_READY",&indicator) == EOK) {
			if (!indicator) {
				log("Modem is in ready state.");
				free(mdm_state);
				goto mdm_ready;
			}
		}

		free(mdm_state);
	}

	log ("Waiting for Modem ready netlink event.");

	while (poll(&pfd, 1, -1) != -1 ) {
		int i, len;
		len  = recv(pfd.fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (len == -1) {
			err("Receive failed.");
			close(pfd.fd);
			return -1;
		}

		i = 0;
		while( i < len ) {
			if (strstr_s(buf+i,512, "MDM_READY",sizeof("MDM_READY"),&str_ptr) == EOK ) {
				log("Ready state received.");
				goto mdm_ready;
			}
			i += strnlen_s((buf+i),512) + 1;
		}
	}

mdm_ready:
	close(pfd.fd);
	return 0;
}

int configure_interface(const char *root_name, const char *vlan_dev_name,
		int trace_vlan_id, int wait_modem_ready,
		int mtu_size, int *if_index)
{
	int socket_fd;
	int ret_val = -1;

	/* Open a raw socket. */
	socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (socket_fd < 0) {
		err("socket() failed, errno %d", errno);
		goto ret_result;
	}

	if (wait_modem_ready == 1)
       		wait_till_modem_ready();

	/* Configure the root device and add a new VLAN id to root device */
	if (config_root_device(root_name, vlan_dev_name, trace_vlan_id,
				socket_fd)) {
		err("Error configuring root device");
		goto close_sock;
	}

	/* Configure VLAN device */
	if (config_vlan_device(vlan_dev_name, socket_fd, trace_vlan_id,
				if_index, mtu_size)) {
		err("Error configuring vlan device");
		goto close_sock;
	}

	ret_val = 0;

close_sock:
	close(socket_fd);
ret_result:
	return ret_val;

}

int open_trace_socket(int if_index)
{
	int socket_fd;
	struct sockaddr_ll dest;

	memset(&dest, 0, sizeof(struct sockaddr_ll));
	dest.sll_family = PF_PACKET;
	dest.sll_protocol = htons(ETH_P_ALL);
	dest.sll_ifindex = if_index;

	/* Configuration complete, open socket for communication. */
	socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (socket_fd < 0) {
		err("socket() failed, errno %d", errno);
		return -1;
	}

	if (bind(socket_fd, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
		err("bind() failed %d", errno);
		close(socket_fd);
		return -1;
	}

	return socket_fd;
}

int bring_up_trace_interface(int socket_fd, const char *vlan_dev_name)
{
	struct ifreq req;

	memset(&req, 0, sizeof(req));
	strncpy_s(req.ifr_name, sizeof(req.ifr_name), vlan_dev_name, IF_NAMESIZE);

	/* Bring up the network interface */
	/* Get the network interface set flags */
	if (ioctl(socket_fd, SIOCGIFFLAGS, &req) < 0) {
		err("ioctl() SIOCSIFFLAGS failed %d :%s",
				errno, strerror(errno));
		return -1;
	}

	req.ifr_flags |= IFF_UP | IFF_PROMISC;
	strncpy_s(req.ifr_name, sizeof(req.ifr_name), vlan_dev_name, IF_NAMESIZE);
	if (ioctl(socket_fd, SIOCSIFFLAGS, &req) < 0) {
		err("ioctl() SIOCSIFFLAGS failed %d :%s", errno, strerror(errno));
		return -1;
	}

	return 0;
}


/*
 * Main function
 */
int main(int argc, char **argv)
{
	const char *root_name = "wwan0";
	int ret_val = -1;
	struct sock_app_data data;

	/* Reset to zero */
	memset(&data, 0, sizeof(struct sock_app_data));

	/* Get user supplied options. */
	if (get_user_options(argc, argv, &data)) {
		err("Invalid user option. Use -h to display help.");
		goto ret_result;
	}

	data.root_dev_name = root_name;
	data.trace_vlan_id = TRACE_VLAN_ID;
	data.rx_bytes = -1;
	data.has_thread_terminated = 0;

	/* Verify IOSM driver version */
	if (verify_iosm_version()) {
		err("IOSM driver version fail");
		goto ret_result;
	}

	/* Check if trace file already exists */
	if (trace_file_exists()) {
		err("Is trace file created via socat or imc_start_trc script?");
		goto ret_result;
	}

	/* Install the signal handler. */
	if (install_sig_handler()) {
		err("Failed to install sig. handler");
		goto ret_result;
	}

	data.output_file = fopen(data.output_file_name, "w+");
	if (!data.output_file) {
		err("unable to open output file");
		goto ret_result;
	}

	data.recv_buffer = malloc(sizeof(char) * data.recv_buff_size);
	if (!data.recv_buffer) {
		err("Unable to allocate receive buffer");
		goto close_output;
	}

	if (pthread_create(&reader_thread, NULL, copy_function, &data) != 0) {
		err("Unable to create the trace collection thread.");
		goto release_mem;
	}

	if (data.tput_interval > 0) {
		log("Throughput calculation interval is %d seconds",
				data.tput_interval);

		while (!data.has_thread_terminated) {
			sleep(data.tput_interval);
			/* Wait till the interface is brought up and
			 * trace data is collected in the thread.
			 */
			if (data.rx_bytes != -1) {
				log("Rx %ld bytes/s",
					(data.rx_bytes + data.tput_interval / 2)
					/ data.tput_interval);
				data.rx_bytes = 0;
			}
		}
	}

	log("waiting for thread to join.");
	pthread_join(reader_thread, NULL);

	/* We come here, in case the thread terminated. */
	log("Closing the socket interface and output file.");

	/* Delete VLAN device */
	del_vlan_device(&data);

	/* Flush output file */
	fflush(data.output_file);
	fsync(fileno(data.output_file));

	log("exit");
	ret_val = 0;

	close(data.socket_fd);

release_mem:
	/* Release the memory. */
	free(data.recv_buffer);

close_output:
	/* Close the output file */
	fclose(data.output_file);

ret_result:
	return ret_val;
}

