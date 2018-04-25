#ifndef TCP_CON_SCAN_H_H
#define TCP_CON_SCAN_H_H

void* tcp_con_scan_sonthread(void *argv)
{
	int confd;
	struct sockaddr_in *dst_addr=(struct sockaddr_in*)argv;
	confd=socket(AF_INET, SOCK_STREAM, 0);
	unsigned short port_now=ntohs(dst_addr->sin_port);		//当前扫描的端口号
	if (confd<0)
	{
		perror("connect socket");
		exit(0);
	}
	//成功建立socket
	if ( connect(confd, (struct sockaddr*)dst_addr, sizeof(struct sockaddr_in)) < 0 )
	{
		//connect失败，端口关闭(或放火墙阻挡)
		pthread_mutex_lock(&connect_printf_mutex);
		//printf("port\t%d\t is closed\n",port_now);
		pthread_mutex_unlock(&connect_printf_mutex);
	}
	else
	{	
		//connect连接成功
		struct list *p=(struct list*)malloc(sizeof(struct list));
		p->data=port_now;
		p->next=NULL;		//将当前端口号连入结果链表
		pthread_mutex_lock(&connect_printf_mutex);
		//printf("port\t%d\t is opened\n",port_now);
		p->next=exist_port;
		exist_port=p;
		pthread_mutex_unlock(&connect_printf_mutex);
	}
	free(dst_addr);		//扫描进程很多，需要释放空间
	pthread_mutex_lock(&connect_num_mutex);
	con_cnt--;		//结束一个子进程，进程计数减一
	pthread_mutex_unlock(&connect_num_mutex);
	close(confd);	//关闭连接
}
void* tcp_con_scan(void *argv)
{
	int i;  
    struct scansock *curscan = (struct scansock *)argv;  
    struct sockaddr_in *dst_addr;  
    pthread_t pidth;  
    int err;  
    pthread_attr_t attr;  
  
    exist_port = NULL;  
    con_cnt = 0; 
	for (i=curscan->start_port;i<=curscan->end_port;i++)
	{
		dst_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));  
        dst_addr->sin_family = AF_INET;		//设置ipv4协议
        inet_pton(AF_INET, curscan->dst_ip, &dst_addr->sin_addr);  
  
        dst_addr->sin_port = htons(i);  
  
        pthread_attr_init(&attr);		//子线程设置成可分离的  
        err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);  
        if(err != 0)  
        {  
            	printf("pthread_attr_setdetachstate:%s\n", strerror(err));  
            	exit(0);  
        }  
        err = pthread_create(&pidth, &attr, tcp_con_scan_sonthread, (void*)dst_addr);		//创建子线程  
        if(err != 0)  
        {  
           	printf("pthread_create:%s\n", strerror(err));  
          	exit(0);  
        }  
        pthread_attr_destroy(&attr);  
        pthread_mutex_lock(&connect_num_mutex);		//线程安全方式计数  
        con_cnt++;  
        pthread_mutex_unlock(&connect_num_mutex);  
        while(con_cnt > 50)	//如果线程池中线程太多  
            usleep(900);
	}
	while(con_cnt > 0)//等待connectCnt为0则扫描结束    
        usleep(900);
			
	//输出扫描结果
	printf("----------\n");
	printf("detect open port:\n");
	struct list *temp_queue;
	if (exist_port==NULL)
		printf("all ports are closed!\n");
	while(exist_port!=NULL)
	{
		printf("%d\n",exist_port->data);
		temp_queue=exist_port;
		exist_port=exist_port->next;
		free(temp_queue);
	}
	printf("----------\n");
	printf("*scan finish!\n");  
}

#endif
