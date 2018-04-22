#include"include_header.h"
#include"src_dst_ip.h"
#include"tcp_con_scan.h"
#include"tcp_syn_scan.h"

int main(int argc,char** argv)
{
	struct scansock scan; 
	if ( argc != 4 )
	{
		printf("usage: %s target_ip start_port end_port\n",argv[0]);
		exit(1);
	}
	strcpy(scan.dst_ip,argv[1]);
	scan.start_port=atoi(argv[2]);
	scan.end_port=atoi(argv[3]);
	get_my_ip(scan.src_ip);
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
	int err,cmd=1;
	void* (*scanfunction[4])(void *argv);
	scanfunction[0]=tcp_con_scan;
	scanfunction[1]=tcp_syn_scan;
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
