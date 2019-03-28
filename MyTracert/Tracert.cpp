#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

#define ICMP_PACKET_SIZE 40
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_TIME_TO_LIVE_EXCEEDED 11
#define TOTAL_SENDING_COUNT 20
#define PACKETS_FOR_ONE_ROUTER 5

typedef struct ICMP_Header
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short  id;
	unsigned short seq; 
} ICMP_Header;

typedef struct IP_Header
{
	unsigned char vesion_headlen;
	unsigned char service_field;
	unsigned short total_len;
	unsigned short id;
	unsigned short flags;
	unsigned char TTL;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int source;
	unsigned int dest;
} IP_Header;

int SetFlag(bool *Flag, int argc, char **argv)
{
	if (argc == 2)
	{
		*Flag = TRUE;
		return 0;
	}
	else 
		if (argc == 3)
			if (!strcmp(argv[1],"-d"))
			{
				*Flag = FALSE;
				return 0;
			}
			else
			{
				printf("Unknown argument %s\n", argv[1]);
				return 1;
			}
		else
		{
			printf("Invalid number of arguments\n");
			return 1;
		}
			
}

int GetAddress(char *Name, unsigned long *Address)
{
	HOSTENT *HostInfo;
	if (isalpha(Name[0]))
	{
		HostInfo = gethostbyname(Name);
		if (HostInfo != NULL)
		{
			if (HostInfo->h_addrtype == AF_INET)
			{
				*Address = *(unsigned long *)HostInfo->h_addr_list[0];
				return 0;
			}
		}
		else
		{
			printf("gethostbyname return error: %d\n", WSAGetLastError());
			return 1;
		}
	}
	else
	{
		*Address = inet_addr(Name);
		return 0;
	}
}

unsigned short CalcChecksum(unsigned short *buf)
{
	int size = ICMP_PACKET_SIZE, checksum = 0;
	while (size > 1) 
	{
		checksum = checksum + *(buf++);
		size = size - sizeof(unsigned short);
	}
	if (size)
		checksum += *(unsigned char *)buf;
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum = (checksum >> 16) + (checksum & 0xffff);
	return (unsigned short)checksum;	
}

void PacketDecryption(IP_Header *hdrIP, IP_Header *resIP, ICMP_Header *resICMP)
{
	ICMP_Header *hdrICMP;
	int len = (*(char *)hdrIP & 0xf) * 4;
	hdrICMP = (ICMP_Header *)((char *)hdrIP + len);
	*resIP = *hdrIP;
	*resICMP = *hdrICMP;
}

int SendICMPPacket(int seq, SOCKET Socket, sockaddr_in SendTo)
{
	ICMP_Header *hdrICMP;
	hdrICMP = (ICMP_Header *)malloc(ICMP_PACKET_SIZE);
	hdrICMP->type = ICMP_ECHO_REQUEST;
	hdrICMP->code = 0;
	hdrICMP->checksum = 0;
	hdrICMP->id = 1;
	hdrICMP->seq = seq;
	hdrICMP->checksum =	~CalcChecksum((unsigned short *)hdrICMP);

	int ErrRes = sendto(Socket,(char *)hdrICMP, ICMP_PACKET_SIZE, 0, (SOCKADDR *)&SendTo, sizeof(SendTo));
	if (ErrRes == SOCKET_ERROR) 
	{
		printf("sendto return error: %d\n", WSAGetLastError());
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	WSADATA wsaData;

	bool NameResolution = FALSE;

	if (SetFlag(&NameResolution, argc, argv))
		return 1;

	if (int ErrRes=WSAStartup(MAKEWORD(2,2), &wsaData))
	{
		printf("WSAStartup return error: %d\n", ErrRes);
		return 1;
	}

	SOCKET Socket = INVALID_SOCKET;
	Socket = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if (Socket == INVALID_SOCKET)
	{
		printf("socket return error: %d\n",WSAGetLastError());
		WSACleanup();
		return 1;
	}

	sockaddr_in SendToAddr, RecvFromAddr;
	ZeroMemory(&SendToAddr,sizeof(SendToAddr));
	SendToAddr.sin_family=AF_INET;
	if (GetAddress(argv[argc-1],&SendToAddr.sin_addr.s_addr))
		return 1;
	
	unsigned short seq = 0, SendingCount = 0;
	int TimeToLive = 0;
	TIMEVAL WaitingTime;
	WaitingTime.tv_sec = 2;
	WaitingTime.tv_usec = 0;

	fd_set RecvSocketList;

	void *RecvBuf = malloc(512);
	IP_Header IPPacketBuf;
	ICMP_Header ICMPPacketBuf;	
	char HostName[NI_MAXHOST], ServName[NI_MAXSERV];

	bool EndPoint = FALSE;
	do
	{
		TimeToLive++;
		
		if(setsockopt(Socket,IPPROTO_IP,IP_TTL,(char *)&TimeToLive,sizeof(int)))
		{
			printf("setscokopt return error: %d\n",WSAGetLastError());
			return 1;
		}
		printf("%d   ", ++SendingCount);

		sockaddr_in *AddressBuf;
		for (int i = 0; i < PACKETS_FOR_ONE_ROUTER; i++)
		{
			seq++;

			RecvSocketList.fd_count = 1;
			RecvSocketList.fd_array[0] = Socket;

			int StartTime = GetTickCount();
			SendICMPPacket(seq, Socket, SendToAddr);
			if (int ErrRes = select(0, &RecvSocketList, NULL, NULL, &WaitingTime))
			{
				if (ErrRes == SOCKET_ERROR)
				{
					printf("select return error: %d\n", WSAGetLastError());
				}
				else
				{
					int RecvFromLen = sizeof(RecvFromAddr);
					recvfrom(Socket,(char *)RecvBuf,512,0, (SOCKADDR *)&RecvFromAddr, &RecvFromLen);
					int EndTime = GetTickCount();
					PacketDecryption((IP_Header *)RecvBuf, &IPPacketBuf, &ICMPPacketBuf);
					if (ICMPPacketBuf.type == ICMP_TIME_TO_LIVE_EXCEEDED || ICMPPacketBuf.type == ICMP_ECHO_REPLY)
					{
						AddressBuf = &RecvFromAddr;
						if (EndTime-StartTime)
							printf("  %d ms ", EndTime-StartTime);
						else
							printf("  <1 ms ");
						if (ICMPPacketBuf.type == ICMP_ECHO_REPLY)
							EndPoint = TRUE;
					}
				}
			}
			else
				printf("  *  ");
		}
		if (AddressBuf !=NULL)
		{
			if (NameResolution && !getnameinfo((SOCKADDR *)AddressBuf, sizeof(SOCKADDR), HostName, NI_MAXHOST, ServName, NI_MAXSERV, NI_NAMEREQD))
				printf(" %s ", HostName);
			printf(" %s ", inet_ntoa(AddressBuf->sin_addr));
			printf("\n");
		}
	}
	while (!EndPoint && SendingCount != TOTAL_SENDING_COUNT);

	puts("\nTracing completed\n");
	return 0;
}