0622工作日志



1.原本的设想：

​	针对用户不完整的输入：

​	比如：-p -x 112.112.11.12 -y 113.113.12.13

​	此时没有输入-m -n 的相关信息

​	在黑名单中，对于这种情况，是默认放行的

​	对于白名单，建立了新的判断函数ipaddr_check_white和port_check_white

​	原本的想法是对于不完整输入直接返回NPASS（即不放行）

​	但发现这样做对于实际的网页访问是不现实的，因为一次网页访问需要用到多种协议类型和多种端口



2.改进方法：对于协议类型和端口号都默认放行，只筛选ip地址

​	因此定义了新的判断函数ipaddr_check_white_simplified和port_check_white_simplified

​	ipaddr_check_white_simplified直接返回PASS

​	port_check_white_simplified调用port_check_white的返回结果



3.同时对昨天的单向ip地址无法实现通信的问题进行了解决，解决方法如下：

	if(((controlled_saddr == saddr) && (controlled_daddr == daddr))||((controlled_saddr == daddr) && (controlled_daddr == saddr)))
	return PASS;