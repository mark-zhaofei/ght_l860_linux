
#include "socket-ipc.h"
//for syslog debug
#include "logs.h"

clint_struct CLINT_INFO[SIZE];

server_context_st *s_srv_ctx = NULL;
/*===========================================================================
 * ==========================================================================*/
int create_server_proc(const char* socket_path)
{
    int  fd;
		struct sockaddr_un serun;
		int listenfd, connfd, size;

		if ((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
				LOGE("socket error");
				exit(1);
		}

    /*一个端口释放后会等待两分钟之后才能再被使用，SO_REUSEADDR是让端口释放后立即就可以被再次使用。*/
    int reuse = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        return -1;
    }

		memset(&serun, 0, sizeof(serun));
		serun.sun_family = AF_UNIX;
		strcpy(serun.sun_path, socket_path);
		size = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path);
		unlink(socket_path);
		if (bind(listenfd, (struct sockaddr *)&serun, size) < 0) {
				LOGE("bind error");
				exit(1);
		}
		LOGI("UNIX domain socket bound\n");

    listen(listenfd,LISTENQ);

    return listenfd;
}

int accept_client_proc(int srvfd)
{

		socklen_t cliun_len;
    int clifd = -1;
		struct sockaddr_un  cliun;
		cliun_len = sizeof(cliun);

    LOGI("accpet clint proc is called.\n");

ACCEPT:
		clifd = accept(srvfd, (struct sockaddr *)&cliun, &cliun_len);


    if (clifd == -1) {
        if (errno == EINTR) {
            goto ACCEPT;
        } else {
            LOGE("accept fail,error:%s\n", strerror(errno));
            return -1;
        }
    }

    LOGI("accept a new client: %d:%s\n",clifd,cliun.sun_path);

    //将新的连接描述符添加到数组中
    int i = 0;
    for (i = 0; i < SIZE; i++) {
        if (s_srv_ctx->clifds[i] < 0) {
            s_srv_ctx->clifds[i] = clifd;
            s_srv_ctx->cli_cnt++;
						CLINT_INFO[i].fd = clifd;
						strcpy(CLINT_INFO[i].path,cliun.sun_path);
            break;
        }
    }

    if (i == SIZE) {
        LOGE("too many clients.\n");
        return -1;
    }
}

int server_broadcast(char* message)
{

    int i ;
    for (i=0;i < SIZE; i++) {
			if(s_srv_ctx->clifds[i]>0){
				LOGI("server broadcast message is :%s\n", message);
				LOGI("clint id is:%d  clint_path is :%s\n", s_srv_ctx->clifds[i],CLINT_INFO[i].path);
				write(s_srv_ctx->clifds[i], message, strlen(message) +1);
			}

    }

    return 0;
}

int handle_client_msg(int fd, char *buf)
{
    //assert(buf);
    LOGI("recv buf is :%s\n", buf);
		if(strcmp(buf,MDM_POWER_ON) == 0){
			LOGI("will call :MDM_POWER_ON\n");
		}
		else if(strcmp(buf,MDM_POWER_OFF) == 0){
			LOGI("will call :MDM_POWER_OFF\n");
		}
		else if(strcmp(buf,MDM_WARM_RESET) == 0){
			LOGI("will call :MDM_WARM_RESET\n");
		}
		else if(strcmp(buf,MDM_COLD_RESET) == 0){
			LOGI("will call :MDM_COLD_RESET\n");
		}
		else if(strcmp(buf,MDM_STATUS_QUERY) == 0){
			LOGI("will call :MDM_STATUS_QUERY\n");
		}
		else{
			LOGI("Error it's a unsupported cmd : %s\n",buf);
		}
		write(fd, "OK", 3);
    //write(fd, buf, strlen(buf) +1);
		//server_broadcast(broadcast_message );
    return 0;
}

void recv_client_msg(fd_set *readfds)
{
    int i = 0, n = 0;
    int clifd;
    char buf[MAXLINE] = {0};
    for (i = 0;i <= s_srv_ctx->cli_cnt;i++) {
        clifd = s_srv_ctx->clifds[i];
        if (clifd < 0) {
            continue;
        }
        /*判断客户端套接字是否有数据*/
        if (FD_ISSET(clifd, readfds)) {
            //接收客户端发送的信息
            n = read(clifd, buf, MAXLINE);
            if (n <= 0) {
                /*n==0表示读取完成，客户都关闭套接字*/
                FD_CLR(clifd, &s_srv_ctx->allfds);
                close(clifd);
                s_srv_ctx->clifds[i] = -1;
								CLINT_INFO[i].fd = -1;
								strcpy(CLINT_INFO[i].path,"");
                continue;
            }
            handle_client_msg(clifd, buf);
        }
    }
}
void * handle_client_proc(void *args)
{
    int  srvfd ;
		int  clifd = -1;
    int  retval = 0;

    srvfd = (int)(*((int*)args));

    fd_set *readfds = &s_srv_ctx->allfds;
    struct timeval tv;
    int i = 0;

    while (1) {
        /*每次调用select前都要重新设置文件描述符和时间，因为事件发生后，文件描述符和时间都被内核修改啦*/
        FD_ZERO(readfds);
        /*添加监听套接字*/
        FD_SET(srvfd, readfds);
        s_srv_ctx->maxfd = srvfd;

        tv.tv_sec = 30;
        tv.tv_usec = 0;
        /*添加客户端套接字*/
        for (i = 0; i < s_srv_ctx->cli_cnt; i++) {
            clifd = s_srv_ctx->clifds[i];
            /*去除无效的客户端句柄*/
            if (clifd != -1) {
                FD_SET(clifd, readfds);
            }
            s_srv_ctx->maxfd = (clifd > s_srv_ctx->maxfd ? clifd : s_srv_ctx->maxfd);
        }

        /*开始轮询接收处理服务端和客户端套接字*/
        retval = select(s_srv_ctx->maxfd + 1, readfds, NULL, NULL, &tv);
        if (retval == -1) {
            LOGE( "select error:%s.\n", strerror(errno));
            break;
        }
        if (retval == 0) {
            LOGE("select is timeout.\n");
            continue;
        }
        if (FD_ISSET(srvfd, readfds)) {
            /*监听客户端请求*/
            accept_client_proc(srvfd);
        } else {
            /*接受处理客户端消息*/
            recv_client_msg(readfds);
        }
    }
}

void server_uninit()
{
    if (s_srv_ctx) {
        free(s_srv_ctx);
        s_srv_ctx = NULL;
    }
}

int server_init()
{
    s_srv_ctx = (server_context_st *)malloc(sizeof(server_context_st));
    if (s_srv_ctx == NULL) {
        return -1;
    }

    memset(s_srv_ctx, 0, sizeof(server_context_st));

    int i = 0;
    for (;i < SIZE; i++) {
        s_srv_ctx->clifds[i] = -1;
				CLINT_INFO[i].fd = -1;
				strcpy(CLINT_INFO[i].path,"");
    }

    return 0;
}
void * test(void * arg)
{
	while(1)
	{
		LOGI("main test 1\n");
		sleep(1);
		LOGI("main test 2\n");
	}

}

#if 0
int main(int argc,char *argv[])
{
		pthread_t thread1,thread2;
		int  srvfd;
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

		pthread_create(&thread1, NULL, handle_client_proc, &srvfd);

		pthread_create(&thread2, NULL, test, NULL);


    pthread_join(thread1,NULL);
		pthread_join(thread2,NULL);

    server_uninit();
    return 0;
err:
    server_uninit();
    return -1;
}
#endif
