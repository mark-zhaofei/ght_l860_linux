/*this is for socket ipc  system*/
#ifndef __SOCKET_IPC_HEADER__
#define __SOCKET_IPC_HEADER__


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>

#define MAXLINE     1024
#define LISTENQ     5
#define SIZE        10
#define PATH_LEN    20

/****
support cmd
*****/
#define MDM_POWER_ON "MDM_POWER_ON"
#define MDM_POWER_OFF "MDM_POWER_OFF"
#define MDM_WARM_RESET "MDM_WARM_RESET"
#define MDM_COLD_RESET "MDM_COLD_RESET"
#define MDM_STATUS_QUERY "MDM_STATUS_QUERY"

typedef struct server_context_st
{
    int cli_cnt;            /*客户端个数*/
    int clifds[SIZE];       /*客户端的个数*/
    fd_set allfds;          /*句柄集合*/
    int maxfd;              /*句柄最大值*/
} server_context_st;

typedef struct clint_struct{
	  int fd;
	  char path[PATH_LEN];
}clint_struct;


int create_server_proc(const char* socket_path);
int accept_client_proc(int srvfd);
int server_broadcast(char* message);
int handle_client_msg(int fd, char *buf);
void recv_client_msg(fd_set *readfds);
void * handle_client_proc(void *args);
void server_uninit();
int server_init();


#endif
