/*
端口映射

PortTransfer_三种模式。
(1) PortTransfer Port Dest_IP Port
在运行本程序的计算机上监听Port端口，并将所有连接请求转到Dest_IP的Port去
(2) PortTransfer ctrlIP ctrlPort Dest_IP Port
和模式3配合用，程序将先主动连接ctrlIP:ctrlPort,之后所有在模式3的ServerPort端口的请求转到Dest_IP:Port去
(3) PortTransfer ctrlPort ServerPort
在执行模式2前先执行，将监听ctrlPort和ServerPort 端口,ctrlPort供模式2使用，ServerPort提供服务.

模式1适合在网关上运行，将内网IP的端口映射到网关上，
如：PortTransfer 88 192.168.0.110 80
那么网关将开启88端口，所有在88端口的请求将转到内网的192.168.0.110的80端口

模式2和模式3联合使用可以将内网的IP和端口映射到指定的IP和端口上，
一般在公网IP(假设61.1.1.1)上执行模式3，如：PortTransfer 99 80, 80是映射过来的端口
内网用户执行模式2如：PortTransfer 61.1.1.1 99 127.0.0.1 80，
那么程序在内网将先连接61.1.1.1:99建立个连接，并等待接收命令。

之后当61.1.1.1的80端口有请求，将通过99端口命令内网机子和公网机子建立条新的数据连接，
并将请求通过新建的连接将请求转发到内网机.
*/
/*
fix by baijin 2008.5
*/
#include "stdafx.h"

#include <boost/asio.hpp> 
#include <boost/array.hpp>
#include <string> 

#include <WINSOCK2.H>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "port_ran.h"

#pragma comment(lib, "ws2_32.lib")

#define MAXBUFSIZE 8192
#define ADDRSIZE 32

struct SOCKINFO
{
	SOCKET ClientSock;
	SOCKET ServerSock;
};
struct ADDRESS
{
	char szIP[ADDRSIZE];
	WORD wPort;
	SOCKET s;
};

////////A simple class of stack operator. code start.....
template<typename T>
class STACK
{
#define MAXSTACK 1024*2

private:
	int top;
	T Data[MAXSTACK];
public:

	STACK()
	{
		top = -1;
	}

	bool IsEmpty()
	{
		return top < 0;
	}

	bool IsFull()
	{
		return top >= MAXSTACK;
	}

	bool Push(T data)
	{
		if (IsFull())
			return false;
		top++;
		Data[top] = data;
		return true;
	}

	T Pop()
	{
		return Data[top--];
	}

};/////////////////////stack end
//////////////////////////////////////////////////////////////////Transfer some Parameters
template<typename X, typename Y>
class TransferParam
{
public:
	X GlobalData;
	STACK<Y> LocalData;
public:
	TransferParam();
	virtual ~TransferParam();
	bool Push(Y data);
	Y Pop();

};

template<typename X, typename Y>
TransferParam<X, Y>::TransferParam()
{
	memset(this, 0, sizeof(TransferParam));
}

template<typename X, typename Y>
TransferParam<X, Y>::~TransferParam()
{
}

template<typename X, typename Y>
bool TransferParam<X, Y>::Push(Y data)
{
	return LocalData.Push(data);
}

template<typename X, typename Y>
Y TransferParam<X, Y>::Pop()
{
	return LocalData.Pop(data);
}
///////////////////////////////////////////////////TransferParam end

int nTimes = 0;

int DataSend(SOCKET s, char *DataBuf, int DataLen)//将DataBuf中的DataLen个字节发到s去
{
	int nBytesLeft = DataLen;
	int nBytesSent = 0;
	int ret;
	//set socket to blocking mode
	int iMode = 0;
	ioctlsocket(s, FIONBIO, (u_long FAR*) &iMode);
	while (nBytesLeft > 0)
	{
		ret = send(s, DataBuf + nBytesSent, nBytesLeft, 0);
		if (ret <= 0)
			break;
		nBytesSent += ret;
		nBytesLeft -= ret;
	}
	return nBytesSent;
}

DWORD WINAPI TransmitData(LPVOID lParam)//在两个SOCKET中进行数据转发
{
	SOCKINFO socks = *((SOCKINFO*)lParam);
	SOCKET ClientSock = socks.ClientSock;
	SOCKET ServerSock = socks.ServerSock;
	char RecvBuf[MAXBUFSIZE] = { 0 };
	fd_set Fd_Read;
	int ret, nRecv;

	while (1)
	{
		FD_ZERO(&Fd_Read);
		FD_SET(ClientSock, &Fd_Read);
		FD_SET(ServerSock, &Fd_Read);
		ret = select(0, &Fd_Read, NULL, NULL, NULL);
		if (ret <= 0)
			goto error;
		if (FD_ISSET(ClientSock, &Fd_Read))
		{
			nRecv = recv(ClientSock, RecvBuf, sizeof(RecvBuf), 0);
			if (nRecv <= 0)
				goto error;
			ret = DataSend(ServerSock, RecvBuf, nRecv);
			if (ret == 0 || ret != nRecv)
				goto error;
		}
		if (FD_ISSET(ServerSock, &Fd_Read))
		{
			nRecv = recv(ServerSock, RecvBuf, sizeof(RecvBuf), 0);
			if (nRecv <= 0)
				goto error;
			ret = DataSend(ClientSock, RecvBuf, nRecv);
			if (ret == 0 || ret != nRecv)
				goto error;
		}
	}//end while
error:
	closesocket(ClientSock);
	closesocket(ServerSock);
	return 0;
}

SOCKET ConnectHost(char *szIP, WORD wPort)//连接指定IP和端口
{
	SOCKET sockid;

	if ((sockid = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		return 0;
	struct sockaddr_in srv_addr;
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.S_un.S_addr = inet_addr(szIP);
	srv_addr.sin_port = htons(wPort);
	if (connect(sockid, (struct sockaddr*)&srv_addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
		goto error;
	return sockid;
error:
	closesocket(sockid);
	return 0;
}

SOCKET CreateSocket(DWORD dwIP, WORD wPort)//在dwIP上绑定wPort端口
{
	SOCKET sockid;

	if ((sockid = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		return 0;
	struct sockaddr_in srv_addr = { 0 };
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.S_un.S_addr = dwIP;
	srv_addr.sin_port = htons(wPort);
	if (bind(sockid, (struct sockaddr*)&srv_addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
		goto error;
	listen(sockid, 3);
	return sockid;
error:
	closesocket(sockid);
	return 0;
}

SOCKET CreateTmpSocket(WORD *wPort)//创建一个临时的套接字,指针wPort获得创建的临时端口
{
	struct sockaddr_in srv_addr = { 0 };
	int addrlen = sizeof(struct sockaddr_in);

	SOCKET s = CreateSocket(INADDR_ANY, 0);
	if (s <= 0)
		goto error;

	if (getsockname(s, (struct sockaddr*)&srv_addr, &addrlen) == SOCKET_ERROR)
		goto error;
	*wPort = ntohs(srv_addr.sin_port);
	return s;
error:
	closesocket(s);
	return 0;
}

BOOL InitSocket()
{
	WSADATA wsadata;
	return WSAStartup(MAKEWORD(2, 2), &wsadata) == 0;
}

DWORD WINAPI PortTransfer_2(LPVOID lParam)
{
	TransferParam<ADDRESS, SOCKET> *ConfigInfo = (TransferParam<ADDRESS, SOCKET> *)lParam;
	SOCKET ClientSocket, ServerSocket;
	SOCKINFO socks;

	ClientSocket = ConfigInfo->LocalData.Pop();
	printf("ThreadID: %d ==> Connect to Server...", nTimes);
	//连接到目标计算机的服务
	ServerSocket = ConnectHost(ConfigInfo->GlobalData.szIP, ConfigInfo->GlobalData.wPort);
	if (ServerSocket <= 0)
	{
		printf("Error.\r\n");
		closesocket(ClientSocket);
		return 0;
	}
	std::cout << "OK.\r\nStarting TransmitData\r\n" << nTimes << std::endl;
	socks.ClientSock = ClientSocket;//公网计算机的套接字
	socks.ServerSock = ServerSocket;//目标计算机服务的套接字
									//进入纯数据转发状态
	return TransmitData((LPVOID)&socks);
}

BOOL PortTransfer_2(char *szCtrlIP, WORD wCtrlPort, char *szIP, WORD wPort)
{
	int nRecv;
	int nCount = 0;
	unsigned long lRecv;
	long nRet;
	bool fCtrlConnected = false;
	WORD ReqPort;
	HANDLE hThread;
	DWORD dwThreadId;
	SOCKET CtrlSocket;

	TransferParam<ADDRESS, SOCKET> ConfigInfo;
	_snprintf_s(ConfigInfo.GlobalData.szIP, ADDRSIZE, "%s", szIP);
	ConfigInfo.GlobalData.wPort = wPort;

	while (1)
	{
		while (!fCtrlConnected) {
			//printf("Creating a ctrlconnection...");
			//与PortTransfer_3模式（工作在公网）的计算机建立控制管道连接
			CtrlSocket = ConnectHost(szCtrlIP, wCtrlPort);
			if (CtrlSocket <= 0) {
				//printf("Failed.\r\n");
				Sleep(3000);
			}
			else {
				ConfigInfo.GlobalData.s = CtrlSocket;
				//printf("OK.\r\n");
				fCtrlConnected = true;
			}
		}

		//接收来自公网计算机的1byte命令，表示建立一个新通道
		nRet = ioctlsocket(CtrlSocket, FIONREAD, &lRecv);
		if (lRecv>0) {
			nRecv = recv(CtrlSocket, (char*)&ReqPort, 1, 0);
			fCtrlConnected = false;
			nCount = 0;
			if (nRecv <= 0) {
				closesocket(CtrlSocket);
				continue; //接收失败
			}
			nTimes++;
			ConfigInfo.LocalData.Push(CtrlSocket);//传递信息的结构
			hThread = CreateThread(NULL, 0, PortTransfer_2, (LPVOID)&ConfigInfo, NULL, &dwThreadId);
			if (hThread)
				CloseHandle(hThread);
			else
				Sleep(1000);
		}
		else {
			nCount++;
			if (nCount >= 0x1000) {
				nCount = send(CtrlSocket, (char *)&nCount, 1, 0);
				if (nCount == SOCKET_ERROR) {
					printf("send error:%d\r\n", WSAGetLastError());
					closesocket(CtrlSocket);
					fCtrlConnected = false;
				}
			}
		}
		Sleep(2);
	}
	//error:
	printf("Error.\r\n");
	closesocket(CtrlSocket);
	return false;
}

/***********************************************************/

boost::asio::io_service io_service;
boost::asio::ip::tcp::resolver resolver(io_service);
boost::asio::ip::tcp::socket sock(io_service);
boost::array<char, 4096> buffer;
uint16_t ser_prot = 0;

//链接服务器 得到服务器分配的端口
void resolve_handler(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it)
{
	if (!ec)
	{
		sock.async_connect(*it, 
			[](const boost::system::error_code &ec)
			{
				if (!ec)
				{
					sock.async_read_some(boost::asio::buffer(buffer), 
						[](const boost::system::error_code &ec, std::size_t bytes)
						{
							if (!ec)
							{
								ser_prot = std::atoi(buffer.data());
							}
						});
				}
			});
	}
}

DWORD WINAPI PortTransfer(LPVOID lParam)
{
	char* remot_ip = (char*)lParam;
	boost::asio::ip::tcp::resolver::query query(remot_ip, "30080");
	resolver.async_resolve(query, resolve_handler);
	io_service.run();
	std::cout << "连接中...Server IP:" << remot_ip << " port:" << ser_prot << std::endl;
	if (!InitSocket())
		return 0;
	const char* local_ip = "127.0.0.1";
	if (ser_prot)
		PortTransfer_2(remot_ip, ser_prot, (char*)local_ip, 31080);

	sock.close();
	WSACleanup();
	return 0;
}