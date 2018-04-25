
#include"include_header.h"
#include"src_dst_ip.h"
#include"tcp_con_scan.h"
#include"tcp_syn_scan.h"
#include"tcp_fin_scan.h"

//判断目标ip和源ip是否在同一网段内
int checkip(char ip1[maxbuf],char ip2[maxbuf])
{
	char *index1,*index2;
	int i;
	index1=strrchr(ip1,'.');
	index2=strrchr(ip2,'.');
	if (index1-ip1!=index2-ip2)
		return 0;
	else
		for (i=0;i<ip1-index1;i++)
			if (ip1[i]!=ip2[i])
				return 0;
	return 1;
}

int main(int argc,char** argv)
{
	struct scansock scan; 
	int err,cmd;
	if ( argc != 4 )
	{
		printf("usage: %s target_ip start_port end_port\n",argv[0]);
		exit(1);
	}
	strcpy(scan.dst_ip,argv[1]);
	scan.start_port=atoi(argv[2]);
	scan.end_port=atoi(argv[3]);
	get_my_ip(scan.src_ip);
	/*if (!checkip(scan.src_ip,scan.dst_ip) && scan.end_port-scan.start_port>300)
	{
		//不在同一网段ip扫描过多端口，容易产生段错误
		printf("!!! source ip and destination ip is not in the same wlan!\n");
		printf("!!! your port_scan_width is more than 300 (%d-%d)\n",scan.start_port,scan.end_port);
		printf("!!! it may cause segmentation fault! (suggest 200 or less,max 500)\n");
		printf("!!! please give the new start_port and end_port:");
		scanf("%d%d",&scan.start_port,&scan.end_port);
	}*/
	printf(">>>0-tcp_connect_scan\n");
	printf(">>>1-tcp_syn_scan\n");
	printf(">>>2-tcp_fin_scan\n");
	while (1)
	{
		printf("input your choice:");
		scanf("%d",&cmd);
		if (cmd>=0 && cmd<=2)
			break;
		else
			printf("error select!\n");
	}
	printf("-------------------------\n");
	printf("*source IP is %s\n",scan.src_ip);
	printf("*target IP is %s\n",scan.dst_ip);
	if (ping_target_by_shell(scan.dst_ip) == -1)
	{
		printf("---the target ip ( %s ) is not reachable!\n",scan.dst_ip);
		return 0;
	}
	else
		printf("---can connect the target!\n");

	pthread_t pidth;
	void* (*scanfunction[3])(void *argv);
	scanfunction[0]=tcp_con_scan;
	scanfunction[1]=tcp_syn_scan;
	scanfunction[2]=tcp_fin_scan;
	err=pthread_create(&pidth,NULL,scanfunction[cmd],(void*)&scan);
	if (err != 0)
	{
		printf("pthread_create:%s\n",strerror(err));
		exit(0);
	}
	err=pthread_join(pidth,NULL);
	if (err != 0)
	{
		printf("pthread_join:%s\n",strerror(err));
		exit(0);
	}
	return 0;
}
