#define _CRT_SECURE_NO_WARNINGS
#ifndef _XKEYCHECK_H
#define _XKEYCHECK_H
#define HAVE_REMOTE

#endif
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")
#define WIN32
#include <sstream>
#include <fstream>
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
//#include <remote-ext.h>
#include <iostream>
#include <iomanip> 
#include <map>
#include <cstdio>
#include <time.h>
#include <cstdlib>  
using namespace std;
#define threshold 100
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

map<string, string[3]> ftp;
ofstream out("log.csv");

string get_request_m_ip_message(const u_char* pkt_data);
string get_response_m_ip_message(const u_char* pkt_data);
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void print(const struct pcap_pkthdr* header,const u_char* pkt_data, string m_ip_message);
int main()
{
	pcap_if_t* alldevs;//pcap_if_t由pcap_if重命名得来
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];//存放错误信息的缓冲
	u_int netmask;
	char packet_filter[] = "tcp";
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

	out << "FTP,USR,PAS,STA" << endl;
	//回调函数
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{

	int combegin= 54;//14位以太网头，20位ip头，20位tcp头  
				  //选择出command为USER和PASS的包，当然这里就简单的以首字母来代表了，反正其他的  
				  //command 没有以U和P开头的  
	string com;
	for (int i = 0; i < 4; i++)
		com += (char)pkt_data[combegin + i];
//	cout << com << endl;
	//判断
	if (com == "USER")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string user;
		ostringstream sout;
		for (int i = combegin + 5; pkt_data[i] != 13; i++)
		{
			sout << pkt_data[i];
		}
		user = sout.str();
		
		ftp[m_ip_message][0] = user;
	}
	else if (com == "PASS")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string password;
		ostringstream sout;
		for (int i = combegin +5; pkt_data[i] != 13; i++)
		{
			sout << pkt_data[i];
		}

		password = sout.str();
	
		ftp[m_ip_message][1] = password;
	}
	else if (com == "230 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "SUCCEED";
		
		print(header, pkt_data, m_ip_message);
	}
	else if (com == "530 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "FAILED";
	
		print(header,pkt_data,m_ip_message);
	}
	
}

string get_request_m_ip_message(const u_char* pkt_data)
{
	mac_address SrcMac, DesMac;
	ip_address SrcIp, DesIp;
	SrcMac = *(mac_address*)(pkt_data + 0x06);
	DesMac = *(mac_address*)(pkt_data);

	SrcIp = *(ip_address*)(pkt_data + 0x1A);
	DesIp = *(ip_address*)(pkt_data + 0x01E);

	string m_ip_message;
	ostringstream sout;

	sout << hex << (int)(SrcMac.byte1) << "-" << hex << (int)(SrcMac.byte2) << "-" << hex << (int)(SrcMac.byte3) << "-" << hex << (int)(SrcMac.byte4) << "-" << hex << (int)(SrcMac.byte5) << "-" << hex << (int)(SrcMac.byte6) << ",";
	sout << dec << (int)(SrcIp.byte1) << "." << dec << (int)(SrcIp.byte2) << "." << dec << (int)(SrcIp.byte3) << "." << dec << (int)(SrcIp.byte4) << ",";
	sout << hex << (int)(DesMac.byte1) << "-" << hex << (int)(DesMac.byte2) << "-" << hex << (int)(DesMac.byte3) << "-" << hex << (int)(DesMac.byte4) << "-" << hex << (int)(DesMac.byte5) << "-" << hex << (int)(DesMac.byte6) << ",";
	sout << dec << (int)(DesIp.byte1) << "." << dec << (int)(DesIp.byte2) << "." << dec << (int)(DesIp.byte3) << "." << dec << (int)(DesIp.byte4) << ",";

	m_ip_message = sout.str();

	return m_ip_message;
}

string get_response_m_ip_message(const u_char* pkt_data)
{
	mac_address SrcMac, DesMac;
	ip_address SrcIp, DesIp;
	SrcMac = *(mac_address*)(pkt_data + 0x06);
	DesMac = *(mac_address*)(pkt_data);

	SrcIp = *(ip_address*)(pkt_data + 0x1A);
	DesIp = *(ip_address*)(pkt_data + 0x01E);

	string m_ip_message;
	ostringstream sout;

	sout << hex << (int)(DesMac.byte1) << "-" << hex << (int)(DesMac.byte2) << "-" << hex << (int)(DesMac.byte3) << "-" << hex << (int)(DesMac.byte4) << "-" << hex << (int)(DesMac.byte5) << "-" << hex << (int)(DesMac.byte6) << ",";
	sout << dec << (int)(DesIp.byte1) << "." << dec << (int)(DesIp.byte2) << "." << dec << (int)(DesIp.byte3) << "." << dec << (int)(DesIp.byte4) << ",";
	sout << hex << (int)(SrcMac.byte1) << "-" << hex << (int)(SrcMac.byte2) << "-" << hex << (int)(SrcMac.byte3) << "-" << hex << (int)(SrcMac.byte4) << "-" << hex << (int)(SrcMac.byte5) << "-" << hex << (int)(SrcMac.byte6) << ",";
	sout << dec << (int)(SrcIp.byte1) << "." << dec << (int)(SrcIp.byte2) << "." << dec << (int)(SrcIp.byte3) << "." << dec << (int)(SrcIp.byte4) << ",";

	m_ip_message = sout.str();

	return m_ip_message;
}

void print(const struct pcap_pkthdr* header, const u_char* pkt_data, string m_ip_message)
{
	struct tm* Time;
	time_t local_tv_sec = header->ts.tv_sec;
	Time = localtime(&local_tv_sec);

	//时间
	printf("%4d-%2d-%2d ", (1900 + Time->tm_year), (1 + Time->tm_mon), Time->tm_mday);
	printf("%2d:%2d:%2d   ", Time->tm_hour, Time->tm_min, Time->tm_sec);
	//地址
	cout << m_ip_message;
	cout << ftp[m_ip_message][0] << ",";
	cout << ftp[m_ip_message][1] << ",";
	cout << ftp[m_ip_message][2] << endl;

ip_address IP= *(ip_address*)(pkt_data + 0x1A);

out << dec << (int)(IP.byte1) << "."<<dec << (int)(IP.byte2) << "."<<dec << (int)(IP.byte3) << "."<<dec << (int)(IP.byte4) << ",";
	out<< ftp[m_ip_message][0] << ",";
	out<< ftp[m_ip_message][1] << ",";
	out<< ftp[m_ip_message][2] << endl;

	ftp.erase(m_ip_message);
}
