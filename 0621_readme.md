0621情况说明

（工程文件中的汉字注释均使用GBK编码）

1.在白名单制度下实现网页通信，需要最起码支持两对目标和源ip地址（因为两者之间的通信都是相互的）

​	黑名单不会出现这种问题，因为只要把交互时双向中的任意一项切断就可以中止通信

2.当前方案：

​	黑名单：

​	首先port_check和ipaddr_check用于检测输入的源—目标对是否和用户通过指令输入、存储在控制文件中的内容一致，如果一致返回MATCH，反之返回NMATCH

​	对于icmp_check,tcp_check,udp_check,他们依靠上述两者返回的MATCH/NMATCH的情况来判读接收到的skb,

最终返回NF_DROP或者NF_ACCEPT



​	白名单：（0621暂未实现）

​	为实现用户只输入一条口令的情况下允许两者双向通信，构造如下：

​		1.port_check&ipaddr_check(返回值为MATCH,NMATCH)

​		2.port_check_white&ipaddr_check_white(返回值为PASS/FAIL)

​		特殊之处在于，即使接收到的目标ip和用户提交的源ip吻合，就给它PASS

​		3.icmp_check&tcp_check&udp_check

3.hook函数的认识：不同点挂载的hook可以有不同功能

