#define _CRT_SECURE_NO_WARNINGS

#include "pcap.h"
#include<stdio.h>
#include<stdbool.h>
#include<time.h>

 /*IP地址 */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/*Mac地址*/
typedef struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

 /*从数据包中提取出来的信息*/
typedef struct PackInf {
	struct tm* Time;	  //数据包的时间
	mac_address SrcMac; //源mac地址
	mac_address DesMac;//目的mac地址
	ip_address SrcIp;//源ip地址
	ip_address DesIp;//目的ip地址
	int Len;//帧长度
}PackInf;

 /*记录流量的结构体*/
typedef struct Flow {
	mac_address Mac;
	ip_address IP;
	int Len;
}Flow;

#define MaxLen 2048  //发出流量警告的最小流量
#define StopTime 10000   //统计流量的时间间隔 单位：毫秒
FILE* fp = NULL;     //日志文件指针
Flow* RecFlow = NULL;   //指向接收流量的指针
Flow* SendFlow = NULL;   //指向发送流量的指针
int LenOfRec = 0;   //发送流量列表长度
int LenOfSend = 0;   //接收流量列表长度

clock_t OutPutTime, CurrentTime;     //输出统计时的时间、当前时间

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);//分析数据包

bool MacEqual(mac_address m1, mac_address m2);//mac地址是否相同
bool IPEqual(ip_address ip1, ip_address ip2);//ip地址是否相同

void RecFlowRecord(PackInf* pack);//接收流量统计
void SendFlowRecord(PackInf* pack);//发送流量统计

void OutPutFlow();//输出统计的流量信息

int main()
{
	pcap_if_t* alldevs;//pcap_if_t由pcap_if重命名得来
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];//存放错误信息的缓冲
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	/* Retrieve the device list */  //获得设备列表
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */   //打印设备列表
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */   //判断用户是否选择了正确的适配器
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */  //paca_open_live用于获取数据包捕获描述符以查看网络上的数据包
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)//检查链接层，因为只支持以太网
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)//指向接口地址列表中第一个元素的指针
		/* Retrieve the mask of the first address of the interface */  //子网掩码：将某个IP地址分成网络地址和主机地址两部分
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter  编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);



	/*打开日志文件*/
	fp = fopen("TheLog.csv", "w");
	if (fp == NULL)
	{
		printf("错误：文件打开失败\n");
		exit(-1);
	}

	
	fprintf(fp, "时间,源MAC,源IP,目标MAC,目标IP,帧长度\n");//输出日志行信息

	OutPutTime = clock();//初始化输出统计时间为当前时间

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	//创建数据包信息结构体
	struct PackInf* pack = (struct PackInf*)malloc(sizeof(struct PackInf));
	if (pack == NULL)
	{
		printf("错误：空间不足！！！\n");
		exit(-1);
	}

	//收集数据包的信息

	//时间信息
	time_t local_tv_sec = header->ts.tv_sec;
	pack->Time = localtime(&local_tv_sec);
	//mac地址信息
	pack->SrcMac = *(mac_address*)(pkt_data + 0x06);
	pack->DesMac = *(mac_address*)(pkt_data);
	//ip地址信息
	pack->SrcIp = *(ip_address*)(pkt_data + 0x1A);
	pack->DesIp = *(ip_address*)(pkt_data + 0x1E);
	//帧长度
	pack->Len = header->len;

	//获取当前时间、判断是否对一段最近一段时间内的流量进行输出
	CurrentTime = clock();//获取当前时间
	if (CurrentTime - OutPutTime > StopTime)
	{
		printf("\n\n  前%d秒内的流量统计：\n", StopTime / 1000);
		OutPutFlow();//输出

		OutPutTime = clock();//更新输出时间
		//释放接收流量列表
		free(RecFlow);
		LenOfRec = 0;
		RecFlow = NULL;
		//释放发送流量列表
		free(SendFlow);
		LenOfSend = 0;
		SendFlow = NULL;
	}

	//输出信息
	//时间
	printf("Time:%4d-%2d-%2d ", (1900 + pack->Time->tm_year), (1 + pack->Time->tm_mon), pack->Time->tm_mday);
	printf("%2d:%2d:%2d   ", pack->Time->tm_hour, pack->Time->tm_min, pack->Time->tm_sec);
	//源mac、目的mac
	printf("Srcmac:%02X-%02X-%02X-%02X-%02X-%02X  ", pack->SrcMac.byte1, pack->SrcMac.byte2, pack->SrcMac.byte3, pack->SrcMac.byte4, pack->SrcMac.byte5, pack->SrcMac.byte6);
	printf("Destmac:%02X-%02X-%02X-%02X-%02X-%02X   ", pack->DesMac.byte1, pack->DesMac.byte2, pack->DesMac.byte3, pack->DesMac.byte4, pack->DesMac.byte5, pack->DesMac.byte6);
	//源ip、目的ip
	printf("Srcip:%3d.%3d.%3d.%3d  ", pack->SrcIp.byte1, pack->SrcIp.byte2, pack->SrcIp.byte3, pack->SrcIp.byte4);
	printf("Destip:%3d.%3d.%3d.%3d   ", pack->DesIp.byte1, pack->DesIp.byte2, pack->DesIp.byte3, pack->DesIp.byte4);
	//帧长度
	printf("Len:%d", pack->Len);
	printf("\n");

	//输出到文件
	//时间
	fprintf(fp, "%d-%d-%d  %d.%d.%d,", (1900 + pack->Time->tm_year), (1 + pack->Time->tm_mon), pack->Time->tm_mday, pack->Time->tm_hour, pack->Time->tm_min, pack->Time->tm_sec);
	//源mac,源ip
	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,", pack->SrcMac.byte1, pack->SrcMac.byte2, pack->SrcMac.byte3, pack->SrcMac.byte4, pack->SrcMac.byte5, pack->SrcMac.byte6);
	fprintf(fp, "%d.%d.%d.%d,", pack->SrcIp.byte1, pack->SrcIp.byte2, pack->SrcIp.byte3, pack->SrcIp.byte4);
	//目的mac，目的ip
	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,", pack->DesMac.byte1, pack->DesMac.byte2, pack->DesMac.byte3, pack->DesMac.byte4, pack->DesMac.byte5, pack->DesMac.byte6);
	fprintf(fp, "%d.%d.%d.%d,", pack->DesIp.byte1, pack->DesIp.byte2, pack->DesIp.byte3, pack->DesIp.byte4);
	//帧长度
	fprintf(fp, "%d\n", pack->Len);

	//统计发送、接收的流量
	SendFlowRecord(pack);
	RecFlowRecord(pack);
	
	//释放数据包信息结构体
	free(pack);
}

/*mac地址是否相等*/
bool MacEqual(mac_address m1, mac_address m2)
{
	if ((m1.byte1 == m2.byte1) && (m1.byte2 == m2.byte2) && (m1.byte3 == m2.byte3) && (m1.byte4 == m2.byte4) && (m1.byte5 == m2.byte5) && (m1.byte6 == m2.byte6))
		return true;
	else
		return false;
}

/*ip地址是否相等*/
bool IPEqual(ip_address ip1, ip_address ip2)
{
	if ((ip1.byte1 == ip2.byte1) && (ip1.byte2 == ip2.byte2) && (ip1.byte3 == ip2.byte3) && (ip1.byte4 == ip2.byte4))
		return true;
	else
		return false;
}

/*接收流量统计*/
void RecFlowRecord(PackInf* pack)
{
	int i;
	//判断mac和ip是否已记录在列表中
	for (i = 0; i < LenOfRec; i++)
	{
		if (MacEqual(pack->DesMac, (RecFlow + i)->Mac) && (IPEqual(pack->DesIp, (RecFlow + i)->IP)))
		{
			(RecFlow + i)->Len += pack->Len;//已记录，对流量进行累积
			break;
		}
	}

	//记录第一次出现的mac和ip
	if (i == LenOfRec)
	{
		LenOfRec++;
		if (LenOfRec == 1)
			RecFlow = (struct Flow*)malloc(sizeof(struct Flow));
		else
			RecFlow = (struct Flow*)realloc(RecFlow, sizeof(Flow) * LenOfRec);

		(RecFlow + LenOfRec - 1)->Mac.byte1 = pack->DesMac.byte1;
		(RecFlow + LenOfRec - 1)->Mac.byte2 = pack->DesMac.byte2;
		(RecFlow + LenOfRec - 1)->Mac.byte3 = pack->DesMac.byte3;
		(RecFlow + LenOfRec - 1)->Mac.byte4 = pack->DesMac.byte4;
		(RecFlow + LenOfRec - 1)->Mac.byte5 = pack->DesMac.byte5;
		(RecFlow + LenOfRec - 1)->Mac.byte6 = pack->DesMac.byte6;

		(RecFlow + LenOfRec - 1)->IP.byte1 = pack->DesIp.byte1;
		(RecFlow + LenOfRec - 1)->IP.byte2 = pack->DesIp.byte2;
		(RecFlow + LenOfRec - 1)->IP.byte3 = pack->DesIp.byte3;
		(RecFlow + LenOfRec - 1)->IP.byte4 = pack->DesIp.byte4;

		(RecFlow + LenOfRec - 1)->Len = pack->Len;
	}
}

/*发送流量统计*/
void SendFlowRecord(PackInf* pack)
{
	int i;
	for (i = 0; i < LenOfSend; i++)
	{
		if (MacEqual(pack->SrcMac, (SendFlow + i)->Mac) && IPEqual(pack->SrcIp, (SendFlow + i)->IP))
		{
			(SendFlow + i)->Len += pack->Len;
			break;
		}
	}

	if (i == LenOfSend)
	{
		LenOfSend++;
		if (LenOfSend == 1)
			SendFlow = (struct Flow*)malloc(sizeof(struct Flow));
		else
			SendFlow = (struct Flow*)realloc(SendFlow, sizeof(struct Flow) * LenOfSend);

		(SendFlow + LenOfSend - 1)->Mac.byte1 = pack->SrcMac.byte1;
		(SendFlow + LenOfSend - 1)->Mac.byte2 = pack->SrcMac.byte2;
		(SendFlow + LenOfSend - 1)->Mac.byte3 = pack->SrcMac.byte3;
		(SendFlow + LenOfSend - 1)->Mac.byte4 = pack->SrcMac.byte4;
		(SendFlow + LenOfSend - 1)->Mac.byte5 = pack->SrcMac.byte5;
		(SendFlow + LenOfSend - 1)->Mac.byte6 = pack->SrcMac.byte6;

		(SendFlow + LenOfSend - 1)->IP.byte1 = pack->SrcIp.byte1;
		(SendFlow + LenOfSend - 1)->IP.byte2 = pack->SrcIp.byte2;
		(SendFlow + LenOfSend - 1)->IP.byte3 = pack->SrcIp.byte3;
		(SendFlow + LenOfSend - 1)->IP.byte4 = pack->SrcIp.byte4;

		(SendFlow + LenOfSend - 1)->Len = pack->Len;
	}
}

/*输出统计*/
void OutPutFlow()
{
	printf("**********接收统计**********\n");

	for (int i = 0; i < LenOfRec; i++)
	{/*输出*/
		printf("MAC:%02X-%02X-%02X-%02X-%02X-%02X   ", (RecFlow + i)->Mac.byte1, (RecFlow + i)->Mac.byte2, (RecFlow + i)->Mac.byte3, (RecFlow + i)->Mac.byte4, (RecFlow + i)->Mac.byte5, (RecFlow + i)->Mac.byte6);
		printf("IP:%3d.%3d.%3d.%3d   ", (RecFlow + i)->IP.byte1, (RecFlow + i)->IP.byte2, (RecFlow + i)->IP.byte3, (RecFlow + i)->IP.byte4);
		printf("Len:%d   ", (RecFlow + i)->Len);
		/*流量超过阈值则进行警告*/
		if ((RecFlow + i)->Len > MaxLen)
			printf("Warning:The flow is more than %dB", MaxLen);
		printf("\n");
	}
	printf("**********接收统计**********\n\n\n");


	printf("**********发送统计**********\n");

	for (int i = 0; i < LenOfSend; i++)
	{
		printf("MAC:%02X-%02X-%02X-%02X-%02X-%02X   ", (SendFlow + i)->Mac.byte1, (SendFlow + i)->Mac.byte2, (SendFlow + i)->Mac.byte3, (SendFlow + i)->Mac.byte4, (SendFlow + i)->Mac.byte5, (SendFlow + i)->Mac.byte6);
		printf("IP:%3d.%3d.%3d.%3d   ", (SendFlow + i)->IP.byte1, (SendFlow + i)->IP.byte2, (SendFlow + i)->IP.byte3, (SendFlow + i)->IP.byte4);
		printf("Len:%d   ", (SendFlow + i)->Len);

		if ((SendFlow + i)->Len > MaxLen)
			printf("Warning:The flow is more than %dB", MaxLen);
		printf("\n");
	}
	printf("**********发送统计**********\n\n\n");
}
