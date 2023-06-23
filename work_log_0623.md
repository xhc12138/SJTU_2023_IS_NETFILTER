work_log_0623

当前主要理解难点在于configure.c的main函数



1.具体来说，main函数中对于stat函数的使用意义不明：

if (stat("/dev/controlinfo",&buf) != 0)
   {
    if (system("mknod /dev/controlinfo c 124 0") == -1){
       printf("Cann't create the devive file ! \n");
       printf("Please check and try again! \n");
       exit(1);
    }
}

我知道stat是获取文件的信息，但获取完之后又干了什么呢？



2.在configure.c的main函数中完成了将controlinfo写入到/dev/controlinfo中

具体来说，是先有getpara函数利用getopt读取用户输入的指令，存到controlled_protocol、controlled_srcport等变量中，之后一起写入在main函数中定义的controlinfo[32]中，最后将其写入/dev/controlinfo



3.在mod_firewall.c中

![image-20230623224830778](C:\Users\xhc\AppData\Roaming\Typora\typora-user-images\image-20230623224830778.png)