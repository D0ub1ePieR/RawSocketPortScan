#ifndef TCP_SYN_SCAN_H_H
#define TCP_SYN_SCAN_H_H

//输出接收到的报文信息 十六进制输出
void print_buf(unsigned char recvbuf[maxbuf], int len)
{
	int i;
	for(i = 0 ; i < len ; i++)  
    {  
    	printf("%02x ", recvbuf[i]);  
        if( (i+1)%12 == 0)  
        	printf("\n");  
    }  
    printf("\n");
}

//扫描子进程控制
void* tcp_syn_scan_sonthread(void *argv)
{
	int synfd;
	unsigned int ip_len, tcp_len, pseu_len, len;
	struct scanbody *curscan=(struct scanbody*)argv;
	unsigned char sendbuf[maxbuf];
	struct sockaddr_in dst_addr;
	struct pseudohdr *ppseuh;
	struct tcphdr *ptcp;
	ppseuh=(struct pseudohdr*)sendbuf;
	ptcp=(struct tcphdr*)(sendbuf+sizeof(struct pseudohdr));
	dst_addr.sin_family = AF_INET;  
    inet_pton(AF_INET, curscan->dst_ip, &dst_addr.sin_addr);  
    dst_addr.sin_port = htons(curscan->dst_port);  
    synfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);//原始套接字 tcp协议，这样接收的都是tcp包  
    if(synfd < 0)  
    {  
        pthread_mutex_lock(&syn_printf_mutex);  
        perror("syn socket");  
        pthread_mutex_unlock(&syn_printf_mutex);  
    }  
	
	//构造tcp伪报文头部
    inet_pton(AF_INET, curscan->dst_ip, &ppseuh->dst_ip);  
    inet_pton(AF_INET, curscan->src_ip, &ppseuh->src_ip);  
    ppseuh->protocol = IPPROTO_TCP;  
    ppseuh->zero = 0;  
//  ppseuh->length = htons(sizeof(struct tcphdr)); 
    ppseuh->length = htons(40);  
//  memset(ptcp, 0, sizeof(struct tcphdr));  
    memset(ptcp, 0, 60-20); 
	//构造tcp报文首部
    ptcp->source = htons(curscan->src_port);  
    ptcp->dest = htons(curscan->dst_port);  
    ptcp->seq = htonl(123456+curscan->dst_port);  	//设置序列号为123456加上当前扫描的端口号
    ptcp->ack_seq = 0;  //无确认号
    ptcp->doff = 10; 
//  ptcp->doff = 0; 
    ptcp->syn = 1;  	//发送syn请求
    ptcp->ack = 0;  	//ack位为0
    ptcp->window = htons(65535);//!!!  
    ptcp->check = 0;  
//  ptcp->check = checksum((unsigned char*)sendbuf, sizeof(struct pseudohdr)+sizeof(struct tcphdr));  
    ptcp->check = checksum((unsigned char*)sendbuf, sizeof(struct pseudohdr)+40);  		//计算校验和

	//向目标发送报文
    len = sendto(synfd, (void *)ptcp, 40, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));  
    if(len <= 0)  
    {  
        pthread_mutex_lock(&syn_printf_mutex);  
        perror("sendto");  
        pthread_mutex_unlock(&syn_printf_mutex);  
    }  
    free(curscan); 	//释放扫描标量
    close(synfd);	//释放子进程
}

//扫描接收控制
void* tcp_syn_scan_recv(void *argv)
{
	unsigned char recvbuf[maxbuf];  
    char recvip[INET_ADDRSTRLEN];  
    int len;  
    struct tcphdr *ptcp;  
    struct ip *pip;  
    struct scansock *curscan = (struct scansock*)argv;  
      
    int synfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);  
      
    int num_port = curscan->end_port - curscan->start_port + 1;  
  
    unsigned short port_now; 
    while(1)//线程自己一直处在不断接收的状态，直到别的线程杀掉它  
    {  
        memset(recvbuf, 0, maxbuf);  
		//尝试从目标地址接收报文
        len = recvfrom(synfd, recvbuf, maxbuf, 0, NULL, NULL);  
        if(len <= 0)  
        {  
            pthread_mutex_lock(&syn_printf_mutex);  
            perror("recvfrom\n");  
            pthread_mutex_unlock(&syn_printf_mutex);  
        }  
        else  
        {    
            if(len >= sizeof(struct iphdr) + sizeof(struct tcphdr))  
            {  
                ptcp = (struct tcphdr*)(recvbuf + sizeof(struct ip));  
  
                port_now = ntohs(ptcp->source);  
              
                if( (curscan->start_port <= port_now) && (port_now <= curscan->end_port) )
                {  
                    /*pthread_mutex_lock(&syn_printf_mutex);
                    printf("port now = %d\n", port_now);  
					//输出接收到的报文信息
                    if(flag_err == 1)  
                    	print_buf(recvbuf,len);
                    pthread_mutex_unlock(&syn_printf_mutex);*/
  
                    if( (ptcp->syn == 1)&&( ntohl(ptcp->ack_seq) == 123456+port_now+1) )	//收到ack，端口开放  
                    {  
                        //pthread_mutex_lock(&syn_printf_mutex);  
                        //printf("open\n");  
                        //pthread_mutex_unlock(&syn_printf_mutex);  
  
                        if(flag_port[port_now] == 0)	//防止重复记录，只对没收到过ack的记录  
                        {  
                            struct list *p = (struct list*)malloc(sizeof(struct list));  
                            p->data = port_now;  
                            p->next = NULL;  
  
                            flag_port[port_now] = 1;  
                            pthread_mutex_lock(&syn_num_mutex);  
                            syn_cnt--;  
                            p->next = exist_port ;  
                            exist_port = p;  
                            pthread_mutex_unlock(&syn_num_mutex);  
                        }  
  
                    }  
                    else if( ptcp->syn == 0)	//收到rst，端口关闭  
                    {  
                        //pthread_mutex_lock(&syn_printf_mutex);  
                        //printf("close\n");  
                        //pthread_mutex_unlock(&syn_printf_mutex);  
  
                        pthread_mutex_lock(&syn_num_mutex);  
                        syn_cnt--;  
                        flag_port[port_now] = 2;  
                        pthread_mutex_unlock(&syn_num_mutex);  
                    }  
                    //else  
                    //{  
    					//pthread_mutex_lock(&syn_printf_mutex);  
                        //printf("!!!3\n");  
                        //pthread_mutex_unlock(&syn_printf_mutex);  
  
                        //pthread_mutex_lock(&syn_printf_mutex);  
                        //print_buf(recvbuf,len);  
                        //pthread_mutex_unlock(&syn_printf_mutex);  
                    //}  
                }  
            }  
        }  
    }  
}

//
void* tcp_syn_scan(void *argv)
{
	int cnt_delay=0, i, err, recv_th;
	flag_err=0;
	struct scansock *curscan = (struct scansock *)argv;
	struct scanbody *scan_addr;
	pthread_t pidth;
	pthread_attr_t attr;
	exist_port=NULL;
	
	//产生接收包的进程
	recv_th = pthread_create(&pidth, NULL, tcp_syn_scan_recv, argv);
	if (recv_th!=0)
	{
		printf("pthread_create:%s!\n",strerror(recv_th));
		exit(0);
	}
	
	memset(flag_port, 0, sizeof(flag_port));
	syn_cnt=0;
	resend:
		for (i=curscan->start_port;i<=curscan->end_port;i++)
		{	
			//只对还未得出结果或还未发送过的端口处理
			if (flag_port[i]==0)
			{	
				//构造扫描目标、源端口、ip结构体
				scan_addr=(struct scanbody*)malloc(sizeof(struct scanbody)); 
            	strncpy(scan_addr->dst_ip, curscan->dst_ip, INET_ADDRSTRLEN);
            	strncpy(scan_addr->src_ip, curscan->src_ip, INET_ADDRSTRLEN);   
            	scan_addr->dst_port = i;  
            	scan_addr->src_port = 1024+i;  
  
            	pthread_attr_init(&attr);  
            	err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);  
            	if(err != 0)  
            	{  
                	printf("pthread_attr_setdetachstate:%s\n", strerror(err));  
                	exit(0);  
            	}  
            	err = pthread_create(&pidth, &attr, tcp_syn_scan_sonthread, (void*)scan_addr);  	//传入子进程进行发包
            	if(err != 0)  
            	{  
                	printf("pthread_create:%s\n", strerror(err));  
                	exit(0);  
            	}  
            	pthread_attr_destroy(&attr);  
            	if(flag_err == 0)  
            	{  
                	pthread_mutex_lock(&syn_num_mutex);  
                	syn_cnt++;  
                	flag_port[i] = 0;  
                	pthread_mutex_unlock(&syn_num_mutex);  
  
            	}  
            	while(syn_cnt > 100) 	//当前线程过多，等待1秒 
                	sleep(1);
			}
		}
		while (syn_cnt>0)
		{	
			//当前进程未执行完，等待1秒
			sleep(1);
			cnt_delay++;
			if (cnt_delay==4)	//设置延时，判断是否丢包
			{
				cnt_delay=0;
				flag_err=1;
				goto resend;	//重传
			}
		}
		//扫描结束输出结果
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
		pthread_cancel(recv_th);	//关闭进程
}

#endif
