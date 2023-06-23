#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include    <stdlib.h>

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0; 

void display_usage(char *commandname)
{
	printf("Usage 1: %s \n", commandname);
	printf("Usage 2: %s -x saddr -y daddr -m srcport -n dstport \n", commandname);
}

int getpara(int argc, char *argv[]){
	int optret;
	unsigned short tmpport;
	//getopt中，argc是参数数量，argv是保留所有输入参数的二维数组
    //其函数的返回值是输入字符串的首字符
    optret = getopt(argc,argv,"pxymnh");
	while( optret != -1 ) {
//			printf(" first in getpara: %s\n",argv[optind]);
        	switch( optret ) {
            //以下用到了getopt函数的外部变量
                //char *optarg：如果有参数，则包含当前选项参数字符串
                //int optind：argv的当前索引值。当getopt函数在while循环中使用时，剩下的字符串为操作数，下标从optind到argc-1。
                //int opterr：这个变量非零时，getopt()函数为“无效选项”和“缺少参数选项，并输出其错误信息。
                //int optopt：当发现无效选项字符之时，getopt()函数或返回 \’ ? \’ 字符，或返回字符 \’ : \’ ，并且optopt包含了所发现的无效选项字符。
                //原文链接：https://blog.csdn.net/men_wen/article/details/61934376
        	case 'p':
        		if (strncmp(argv[optind], "ping",4) == 0 )
					controlled_protocol = 1;
				else if ( strncmp(argv[optind], "tcp",3) == 0  )
					controlled_protocol = 6;
				else if ( strncmp(argv[optind], "udp",3) == 0 )
					controlled_protocol = 17;
				else {
					printf("Unkonwn protocol! please check and try again! \n");
					exit(1);
				}
        		break;
         case 'x':   //get source ipaddr 
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_saddr) == 0){
					printf("Invalid source ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'y':   //get destination ipaddr
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_daddr) == 0){
					printf("Invalid destination ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'm':   //get destination ipaddr
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_srcport = htons(tmpport);
         	break;
        case 'n':   //get destination ipaddr
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_dstport = htons(tmpport);
         	break;
         case 'h':   /* fall-through is intentional */
         case '?':
         	display_usage(argv[0]);
         	exit(1);;
                
         default:
				printf("Invalid parameters! \n ");
         	display_usage(argv[0]);
         	exit(1);;
        	}
		optret = getopt(argc,argv,"pxymnh");
	}
}

int main(int argc, char *argv[]){
	//指针就是地址，在32位机中，一次处理32位2进制，一个字节8位，所以一个指针（地址）4个字节
    //类似的，64位机中一个指针8个字节
    char controlinfo[32];
	int controlinfo_len = 0;

	//file director 用具体的整数数字来指代具体文件
    int fd;

    //stat这个结构体是用来描述一个linux系统文件系统中的文件属性的结构
    //stat函数获取文件的所有相关信息，一般情况下，我们关心文件大小和创建时间、访问时间、修改时间。
    //首先还是先来所用到的struct stat结构体函数原型：
    //
    //int stat(const char *path, struct stat *buf);
    //int lstat(const char *path, struct stat *buf);
    //
    //这些两个函数返回关于文件的信息。两个函数的第一个参数都是文件的路径，第二个参数是struct stat的指针。返回值为0，表示成功执行。
    //原文链接：https://blog.csdn.net/chen1415886044/article/details/102887154
	struct stat buf;
	
	if (argc == 1) //输入为空
		controlinfo_len = 0; //cancel the filter
	else if (argc > 1){
		getpara(argc, argv);
        //（int*）强制转换成整形指针
		*(int *)controlinfo = controlled_protocol;
		*(int *)(controlinfo + 4) = controlled_saddr;
		*(int *)(controlinfo + 8) = controlled_daddr;
		*(int *)(controlinfo + 12) = controlled_srcport;
		*(int *)(controlinfo + 16) = controlled_dstport;
		controlinfo_len = 20;
	}
	
//	printf("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);

	if (stat("/dev/controlinfo",&buf) != 0)
    {
		if (system("mknod /dev/controlinfo c 124 0") == -1){
			printf("Cann't create the devive file ! \n");
			printf("Please check and try again! \n");
			exit(1);
		}
	}
	fd =open("/dev/controlinfo",O_RDWR,S_IRUSR|S_IWUSR);
	if (fd > 0)
	{
		//将controlinfo写入到文件fd(/dev/controlinfo)中，写入的长度是controlinfo_len个字节
        write(fd,controlinfo,controlinfo_len);
	}
	else {
		perror("can't open /dev/controlinfo \n");
	 	exit(1);
	}
	close(fd);
}
