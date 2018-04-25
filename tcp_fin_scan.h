#ifndef TCP_FIN_SCAN_H_H
#define TCP_FIN_SCAN_H_H

//扫描子进程控制
void* tcp_fin_scan_sonthread(void *argv)  
{  
    int finfd;  
    uint ip_len, tcp_len, pseu_len, len;  
    struct scanbody *curscan = (struct scanbody*)argv;  
  
    unsigned char sendBuf[200];  
  
    struct sockaddr_in dst_addr;  
    struct pseudohdr *ppseuh;  
    struct tcphdr *ptcp;  
    ppseuh = (struct pseudohdr*)sendBuf;  
    ptcp = (struct tcphdr*)(sendBuf + sizeof(struct pseudohdr));  
//  memset(&dst_addr, 0, sizeof(dst_addr));  
    dst_addr.sin_family = AF_INET;  
    inet_pton(AF_INET, curscan->dst_ip, &dst_addr.sin_addr);  
    dst_addr.sin_port = htons(curscan->dst_port);  
    finfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);  
    if(finfd < 0)  
    {  
        pthread_mutex_lock(&fin_printf_mutex);  
        perror("fin socket");  
        pthread_mutex_unlock(&fin_printf_mutex);  
    }  

	//构造tcp伪首部218.94.136.185
    inet_pton(AF_INET, curscan->dst_ip, &ppseuh->dst_ip);  
    inet_pton(AF_INET, curscan->src_ip, &ppseuh->src_ip);  
    ppseuh->protocol = IPPROTO_TCP;  
    ppseuh->zero = 0;  
//  ppseuh->length = htons(sizeof(struct tcphdr)); 
    ppseuh->length = htons(40);//!!!  
//  memset(ptcp, 0, sizeof(struct tcphdr));  
    memset(ptcp, 0, 60-20);  
	//构造tcp首部
    ptcp->source = htons(curscan->src_port);  
    ptcp->dest = htons(curscan->dst_port);  
    ptcp->seq = htonl(123456+curscan->dst_port); 
    ptcp->ack_seq = 0;  
    ptcp->doff = 10;  
    ptcp->fin = 1;  
    ptcp->ack = 0;  
    ptcp->window = htons(65535);
    ptcp->check = 0;  
//  ptcp->check = checksum((unsigned char*)sendBuf, sizeof(struct pseudohdr)+sizeof(struct tcphdr));  
    ptcp->check = checksum((unsigned char*)sendBuf, sizeof(struct pseudohdr)+40);  
  
    //发送数据包
    len = sendto(finfd, (void *)ptcp, 40, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));  
    if(len <= 0)  
    {  
		//发送失败
        pthread_mutex_lock(&fin_printf_mutex);  
        perror("sendto");  
        pthread_mutex_unlock(&fin_printf_mutex);  
    }  
    free(curscan);  	//释放报文
    close(finfd);  		//结束进程
}  
 
//接收控制进程
void* tcp_fin_scan_recv(void *argv)  
{  
    unsigned char recvbuf[maxbuf];  
    char recv_ip[INET_ADDRSTRLEN];  
    int len;  
    struct tcphdr *ptcp;  
    struct ip *pip;  
    struct scansock *curscan = (struct scansock*)argv;  
      
    int finfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);  
      
    int num_port = curscan->end_port - curscan->start_port + 1;  
  
    unsigned short port_now;  

    while(1)  
    {  
        memset(recvbuf, 0, maxbuf);  
		//接收
        len = recvfrom(finfd, recvbuf, maxbuf, 0, NULL, NULL);  
        if(len <= 0)  
        {  
            pthread_mutex_lock(&fin_printf_mutex);  
            perror("recvfrom\n");  
            pthread_mutex_unlock(&fin_printf_mutex);  
        }  
        else  
        {  
			//接收到回复报文
            if(len >= sizeof(struct iphdr) + sizeof(struct tcphdr))  
            {  
                ptcp = (struct tcphdr*)(recvbuf + sizeof(struct ip));  
                port_now = ntohs(ptcp->source);               
                if( (curscan->start_port <= port_now) && (port_now <= curscan->end_port) ) 
                {  
                    /*pthread_mutex_lock(&fin_printf_mutex);  
                    printf("port now = %d\t", port_now);  
                    if(flag_err >= 1)  
						print_buf(recvbuf,len);  
                    pthread_mutex_unlock(&fin_printf_mutex);*/  
					
					//接收到RST报文
                    if( (ptcp->ack == 1)&&( ntohl(ptcp->ack_seq) == 123456+port_now+1) && (ptcp->rst == 1) )  
                    {  
                        /*pthread_mutex_lock(&fin_printf_mutex);  
                        printf("close\n");  
                        pthread_mutex_unlock(&fin_printf_mutex); */ 
  
                        flag_port[port_now] = 2;  

						//struct list *p = (struct list*)malloc(sizeof(struct list));  
                        //p->data = port_now;  
                        //p->next = NULL;  
                        pthread_mutex_lock(&fin_num_mutex);  
                        //p->next = exist_port;  
                       // exist_port = p;   
                        fin_cnt--; 		//当前进程数减一 
                        pthread_mutex_unlock(&fin_num_mutex);  
  
                    }  
                    /*else  
                    {  
                        pthread_mutex_lock(&fin_printf_mutex);  
                        printf("!!!3\n");  
                        pthread_mutex_unlock(&fin_printf_mutex);  
  
                        pthread_mutex_lock(&fin_printf_mutex);  
                        print_buf(recvbuf,len);  
                        printf("\n");  
                        pthread_mutex_unlock(&fin_printf_mutex);  
                    }  */
                }  
            }  
        }  
    }  
}  

//扫描主控制进程
void* tcp_fin_scan(void *argv)  
{  
    int cnt_delay = 0;   
    flag_err = 0;  
    struct scansock *curscan = (struct scansock*)argv;  
    int i;  
    struct scanbody *scan_addr;  
    pthread_t pidth;  
    int err;  
    pthread_attr_t attr;  
 
    int recv_th;  
    recv_th = pthread_create(&pidth, NULL, tcp_fin_scan_recv, argv);  
    if(recv_th != 0)  
    {  
        printf("pthread_create:%s\n", strerror(recv_th));  
        exit(0);  
    }  
    memset(flag_port, 0, sizeof(flag_port));      
    fin_cnt = 0;  
resend:  
    for(i = curscan->start_port ; i <= curscan->end_port ; i++)  
    {  
        if(flag_port[i] == 0)  
        {   
            scan_addr = (struct scanbody*)malloc(sizeof(struct scanbody));  
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
            
			//传入发送进程
            err = pthread_create(&pidth, &attr, tcp_fin_scan_sonthread, (void*)scan_addr);  
            if(err != 0)  
            {  
                printf("pthread_create:%s\n", strerror(err));  
                exit(0);  
            }  
            pthread_attr_destroy(&attr);  
            if(flag_err == 0)  
            {  
                pthread_mutex_lock(&fin_num_mutex);  
                fin_cnt++;  
                flag_port[i] = 0;  
                pthread_mutex_unlock(&fin_num_mutex);  
  
            }  
            //while(fin_cnt > 100)  
                //usleep(500);  
        }  
    }  
    while(fin_cnt > 0)  
    {  

        usleep(900);  
        cnt_delay++;  
        if(cnt_delay == 10)  	//设置重传阈值
        {  
            cnt_delay = 0;  
            flag_err++;  
            if(flag_err > 1)  
            {  
				//成功检测到的开放端口
                for(i = curscan->start_port ; i <= curscan->end_port ; i++)  
                {  
                    if(flag_port[i] == 0)  
                    {  
                        struct list *p = (struct list*)malloc(sizeof(struct list));  
                        p->data = i;  
                        p->next = NULL;  
                        pthread_mutex_lock(&fin_num_mutex);  
                        p->next = exist_port;  
                        exist_port = p;  
                        pthread_mutex_unlock(&fin_num_mutex);  
                    }  
                }  
                break;  
            }  
  
            goto resend;  
        }  
        /*pthread_mutex_lock(&fin_printf_mutex);  
        printf("cnt_delay = %d\tflag_err = %d\n", cnt_delay, flag_err);  
        pthread_mutex_unlock(&fin_printf_mutex); */ 
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
    pthread_cancel(recv_th);  
} 

#endif
