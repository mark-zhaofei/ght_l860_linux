#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <sys/ioctl.h>
//for syslog debug
#include "logs.h"

#include "socket-ipc.h"
#include <pthread.h>

#define false 0
#define true 1
//#define CRM_LOOP_BACK 1
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
typedef size_t  rsize_t;


#define NL_EVENT_MDM_NOT_READY		"MDM_NOT_READY"
#define NL_EVENT_ROM_READY		"ROM_READY"
#define NL_EVENT_MDM_READY		"MDM_READY"
#define NL_EVENT_CRASH			"CRASH"
#define NL_EVENT_CD_READY		"CD_READY"
#define NL_EVENT_CD_READY_LINK_DOWN	"CD_READY_LINK_DOWN"
#define NL_EVENT_MDM_TIMEOUT		"MDM_TIMEOUT"

#define PORT_START      "sh /usr/local/bin/IOSM/scripts/imc_start &"
#define PORT_STOP       "sh /usr/local/bin/IOSM/scripts/imc_stop &"
#define IOSM_INSTALL    "/sbin/insmod /usr/local/bin/IOSM/imc_ipc.ko &"
#define MCD_INSTALL     ""

typedef int errno_t;
#define ESNULLP         ( 400 )       /* null ptr                    */
#define ESZEROL         ( 401 )       /* length is zero              */
#define ESLEMAX         ( 403 )       /* length exceeds max          */
#define RSIZE_MAX_STR      ( 4UL << 10 )      /* 4KB */
#define EOK             ( 0 )
#define ESNOTFND        ( 409 )       /* not found                   */

#define RCNEGATE(x)  ( -(x) )

/* IOCTL commands list */
#define MDM_CTRL_MAGIC	0x87 /* FIXME: Revisit */

#define MDM_CTRL_POWER_OFF      _IO(MDM_CTRL_MAGIC, 0)
#define MDM_CTRL_POWER_ON       _IO(MDM_CTRL_MAGIC, 1)
#define MDM_CTRL_WARM_RESET     _IO(MDM_CTRL_MAGIC, 2)
#define MDM_CTRL_COLD_RESET     _IO(MDM_CTRL_MAGIC, 3)
#define MDM_CTRL_SET_STATE      _IO(MDM_CTRL_MAGIC, 4)
#define MDM_CTRL_GET_STATE      _IO(MDM_CTRL_MAGIC, 5)
#define MDM_CTRL_RESERVED       _IO(MDM_CTRL_MAGIC, 6)
#define MDM_CTRL_FLASHING_WARM_RESET _IO(MDM_CTRL_MAGIC, 7)
#define MDM_CTRL_GET_HANGUP_REASONS  _IO(MDM_CTRL_MAGIC, 8)
#define MDM_CTRL_CLEAR_HANGUP_REASONS _IO(MDM_CTRL_MAGIC, 9)
#define MDM_CTRL_SET_POLLED_STATES _IO(MDM_CTRL_MAGIC, 10)
#define MDM_CTRL_SET_CFG  _IO(MDM_CTRL_MAGIC, 11)
#define MDM_CTRL_GET_CFG  _IO(MDM_CTRL_MAGIC, 12)


typedef enum hal_events {
    /* PCIE events */
    EV_MDM_OFF,          // NL_EVENT_MDM_NOT_READY
    EV_MDM_FLASH,        // NL_EVENT_ROM_READY
    EV_MDM_RUN,          // NL_EVENT_MDM_READY
    EV_MDM_CRASH,        // NL_EVENT_CRASH
    EV_MDM_DUMP_READY,   // NL_EVENT_CD_READY
    EV_MDM_LINK_DOWN,    // NL_EVENT_CD_READY_LINK_DOWN
    EV_MDM_LINK_TIMEOUT, // NL_EVENT_MDM_TIMEOUT
    EV_NUM
} hal_events_t;

/////////////////////////////////////////////////////////////////////


int32_t fd;
struct pollfd pfd;
int32_t res;
uint32_t i,status;
uint32_t len;
char buf[4096];
struct sockaddr_nl nls;
uint8_t found = false;
uint8_t count = 0;
char *str_ptr;

int modemstate = EV_NUM;

pthread_t thread1,thread2;
int  srvfd;
/////////////////////////////////////////////////////////////////////

errno_t
strstr_s (char *dest, rsize_t dmax,
          const char *src, rsize_t slen, char **substring)
{
    rsize_t len;
    rsize_t dlen;
    int i;

    if (substring == NULL) {
        LOGI("strstr_s: substring is null\n");
        return RCNEGATE(ESNULLP);
    }
    *substring = NULL;

    if (dest == NULL) {
        LOGI("strstr_s: dest is null\n");
        return RCNEGATE(ESNULLP);
    }

    if (dmax == 0) {
        LOGI("strstr_s: dmax is 0\n");
        return RCNEGATE(ESZEROL);
    }

    if (dmax > RSIZE_MAX_STR) {
        LOGI("strstr_s: dmax exceeds max\n");
        return RCNEGATE(ESLEMAX);
    }

    if (src == NULL) {
        LOGI("strstr_s: src is null\n");
        return RCNEGATE(ESNULLP);
    }

    if (slen == 0) {
        LOGI("strstr_s: slen is 0\n");
        return RCNEGATE(ESZEROL);
    }

    if (slen > RSIZE_MAX_STR) {
        LOGI("strstr_s: slen exceeds max\n");
        return RCNEGATE(ESLEMAX);
    }

    /*
     * src points to a string with zero length, or
     * src equals dest, return dest
     */
    if (*src == '\0' || dest == src) {
        *substring = dest;
        return RCNEGATE(EOK);
    }

    while (*dest && dmax) {
        i = 0;
        len = slen;
        dlen = dmax;

        while (src[i] && dlen) {

            /* not a match, not a substring */
            if (dest[i] != src[i]) {
                break;
            }

            /* move to the next char */
            i++;
            len--;
            dlen--;

            if (src[i] == '\0' || !len) {
                *substring = dest;
                return RCNEGATE(EOK);
            }
        }
        dest++;
        dmax--;
    }

    /*
     * substring was not found, return NULL
     */
    *substring = NULL;
    return RCNEGATE(ESNOTFND);
}




//mcd driver ctrol
int mcd_fd = 0;

//mcd contrl cfg
struct mdm_ctrl_cfg{
	unsigned int  board;
	unsigned int type;
	unsigned int power_on;
	unsigned int usb_type;
}cfg = { 2, 7, 2, 0 };
/*
 mcd open
 */
int mcd_open(void)
{
    mcd_fd = open("/dev/mdm_ctrl0", O_WRONLY);
    if (mcd_fd < 0){
       LOGE("[MCD]  open failed\n");
       return -1;
    }
    LOGI("[MCD] open ok\n");
    return 0;
}

/*
 mcd cfg
 */
int mcd_cfg(void)
{
   if (ioctl(mcd_fd, MDM_CTRL_SET_CFG, &cfg) < 0){
      LOGE("[MCD] ==> MCD config failed\n");
      return -1;
   }
   LOGI("[MCD] MCD config ok\n");
   return 0;
}

/*
 mcd power off
 */
int mcd_power_off(void)
{
   if (ioctl(mcd_fd, MDM_CTRL_POWER_OFF) < 0){
      LOGE("[MCD] ==> Power off failed\n");
      return -1;
   }
   LOGI("[MCD] ==> Power off success\n");
   return 0;
}

/**
 mcd power on
 * */
int mcd_power_on(void)
{
   if (ioctl(mcd_fd, MDM_CTRL_POWER_ON) < 0){
      LOGE("[MCD] ==> Power ON failed\n");
      return -1;
    }
   LOGI("[MCD] ==> Power ON success\n");
   return 0;
}

/**
 mcd cold reset
 * */

int mcd_cold_reset(void)
{
   if (ioctl(mcd_fd, MDM_CTRL_COLD_RESET) < 0){
      LOGE("[MCD] ==> cold reset failed\n");
      return -1;
    }
   LOGI("[MCD] ==> cold reset success\n");
   return 0;
}

/**
 mcd warm reset
 * */

int mcd_warm_reset(void)
{
   if (ioctl(mcd_fd, MDM_CTRL_WARM_RESET) < 0){
      LOGE("[MCD] ==> WARM reset failed\n");
      return -1;
    }
   LOGI("[MCD] ==> WARM reset success\n");
   return 0;
}

/**
 *  mcd closed
 *   * */

int mcd_closed(void)
{
    close(mcd_fd);
    LOGI("[MCD] ==> mcd driver closed \n");
    return 0;
}
/**
 * for ctrl c to closed mcd
 * */
void signal_handler(int sig)
{
    mcd_closed();
    _exit(0);

}

int create_netlink_proc(void)
{
    pfd.events = POLLIN;
    pfd.fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (pfd.fd == 1){
      LOGI("netlink socket create error. \n");
      return -1;
    }
    memset(&nls, 0, sizeof(nls));
    nls.nl_family = AF_NETLINK;
    nls.nl_pid = getpid();
    nls.nl_groups = 1;
    res = bind(pfd.fd, (struct sockaddr *)&nls, sizeof(nls));
    if (res == -1) {
      LOGI("netlink socket bind error. \n");
      return -1;
    }

}

void * handle_mdm_message(void * arg)
{
  while (poll(&pfd, 1, -1) != -1 )
  {
    memset(&buf[0],0x00,4096);
    len = recv(pfd.fd, buf, sizeof(buf), 0);
    count = 0;
    //LOGI("first found %s len = %d\n",&buf[0],len);
    for(i = 0; i < len; i++)
    {
      if (strstr_s(buf+i,512, "MDM_READY",sizeof("MDM_READY"),&str_ptr) == EOK ){
            if(modemstate != EV_MDM_RUN){
                LOGI("MDM_READY state received. \n");
                modemstate = EV_MDM_RUN;
                server_broadcast("EV_MDM_RUN");

                if ( access("/dev/iat",0) != 0 ){
                  LOGI("MDM ready and /dev/iat file dosent exist so will imc_start. \n");
                  system(PORT_START);
                }
            }
      }
      else if(strstr_s(buf+i,512, NL_EVENT_MDM_NOT_READY,sizeof(NL_EVENT_MDM_NOT_READY),&str_ptr) == EOK){
            if(modemstate != EV_MDM_OFF){
                LOGI("NL_EVENT_MDM_NOT_READY state received.\n");
                modemstate = EV_MDM_OFF;
                server_broadcast("EV_MDM_OFF");
                if ( !access("/dev/iat",0) ){
                    system(PORT_STOP);
                    LOGI("imc_stop\n");
                }
            }

      }
      else if(strstr_s(buf+i,512, NL_EVENT_ROM_READY,sizeof(NL_EVENT_ROM_READY),&str_ptr) == EOK){
            if(modemstate != EV_MDM_FLASH){
                LOGI("NL_EVENT_ROM_READY state received. \n");
                modemstate = EV_MDM_FLASH;
                server_broadcast("EV_MDM_FLASH");
            }

      }
      else if (strstr_s(buf+i,512, NL_EVENT_CRASH,sizeof(NL_EVENT_CRASH),&str_ptr) == EOK ){
            if(modemstate != EV_MDM_CRASH){
                LOGI("NL_EVENT_CRASH state received.\n");
                modemstate = EV_MDM_CRASH;
                server_broadcast("EV_MDM_CRASH");
            }
      }
      else if(strstr_s(buf+i,512, NL_EVENT_CD_READY,sizeof(NL_EVENT_CD_READY),&str_ptr) == EOK){
            if(modemstate != EV_MDM_DUMP_READY){
                LOGI("NL_EVENT_CD_READY state received.\n");
                modemstate = EV_MDM_DUMP_READY;
                server_broadcast("EV_MDM_DUMP_READY");
                if ( !access("/dev/iat",0) ){
                    system(PORT_STOP);
                    LOGI("imc_stop\n");
                }
                mcd_warm_reset();

            }
      }
      else if(strstr_s(buf+i,512, NL_EVENT_CD_READY_LINK_DOWN,sizeof(NL_EVENT_CD_READY_LINK_DOWN),&str_ptr) == EOK){
            if(modemstate != EV_MDM_LINK_DOWN){
                LOGI("NL_EVENT_CD_READY_LINK_DOWN state received. \n");
                modemstate = EV_MDM_LINK_DOWN;
                server_broadcast("EV_MDM_LINK_DOWN");
            }

     }
      else if(strstr_s(buf+i,512, NL_EVENT_MDM_TIMEOUT,sizeof(NL_EVENT_MDM_TIMEOUT),&str_ptr) == EOK){
            if(modemstate != EV_MDM_LINK_TIMEOUT){
                LOGI("NL_EVENT_MDM_TIMEOUT state received. \n");
                modemstate = EV_MDM_LINK_TIMEOUT;
                server_broadcast("EV_MDM_LINK_TIMEOUT");

                if ( !access("/dev/iat",0) ){
                  system(PORT_STOP);
                  LOGI("modem timeout imc_stop and cold reset \n");
                }

                mcd_cold_reset();

           }

      }
      else{
            continue;
      }
    }

  }
  close(pfd.fd);

}

int main()
{
    char *socket_path = "/tmp/server.socket";
    clint_struct CLINT_INFO[SIZE];
    server_context_st *s_srv_ctx = NULL;
    /*初始化服务端context*/
    if (server_init() < 0) {
        return -1;
    }
    /*创建服务,开始监听客户端请求*/
    srvfd = create_server_proc(socket_path);
    if (srvfd < 0) {
        fprintf(stderr, "socket create or bind fail.\n");
        goto err;
    }

    if(create_netlink_proc() < 0){
        return -1;
    }

    LOGI("MCD_INSTALL. \n");
    system(MCD_INSTALL);
		//mcd init
		mcd_open();
		mcd_cfg();

    LOGI("IOSM_INSTALL. \n");
    system(IOSM_INSTALL);

    signal(SIGINT,signal_handler);

    pthread_create(&thread1, NULL, handle_client_proc, &srvfd);

		pthread_create(&thread2, NULL, handle_mdm_message, NULL);


    pthread_join(thread1,NULL);
		pthread_join(thread2,NULL);

    server_uninit();
    return 0;
err:
    server_uninit();
    return -1;




}
