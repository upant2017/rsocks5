/**
* @file boost_socks5.cpp
* @brief Simple SOCKS5 proxy server realization using boost::asio library
* @author philave (philave7@gmail.com)
*/
#include "stdafx.h"
#include <cstdlib>
#include <string>
#include <memory>
#include <utility>
#include <fstream>
#include <thread>

#include <boost/asio.hpp>


using boost::asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session>
{
public:
	Session(tcp::socket in_socket, tcp::socket out_socket, size_t buffer_size)
		: in_socket_(std::move(in_socket)),
		out_socket_(std::move(out_socket)),
		in_buf_(buffer_size),
		out_buf_(buffer_size)
	{
	}

	void start()
	{
		do_read(3); // 读取两个 sockets 进入无限数据交换中
	}

private:
	void do_read(int direction)
	{
		auto self(shared_from_this());

		// 在同一个套接字上，我们必须按方向分开读，不允许第二个读调用。第一次调用 direction = 3 (&1 &2 都执行)
		if (direction & 0x1)
			in_socket_.async_receive(boost::asio::buffer(in_buf_),
				[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				//std::ostringstream what; what << "--> " << std::to_string(length) << " bytes";
				//std::cout << what.str() << std::endl;
				//将客户端发来的信息 发给 服务器
				do_write(1, length);
			}
			else
			{
				std::cout << "closing session. Client socket read error:" << ec.message() << std::endl;
				in_socket_.close(); out_socket_.close();
			}

		});

		if (direction & 0x2)
			out_socket_.async_receive(boost::asio::buffer(out_buf_),
				[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				//std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";
				//std::cout << what.str() << std::endl;
				//将服务器发来的信息 发给客户端
				do_write(2, length);
			}
			else
			{
				std::cout << "closing session. Remote socket read error:" << ec.message() << std::endl; 
				in_socket_.close(); out_socket_.close();
			}
		});
	}

	void do_write(int direction, std::size_t Length)
	{
		auto self(shared_from_this());

		switch (direction)
		{
		case 1:
			boost::asio::async_write(out_socket_, boost::asio::buffer(in_buf_, Length),
				[this, self, direction](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
					do_read(direction);
				else
				{
					std::cout << "closing session. Client socket write error:" << ec.message() << std::endl;
					in_socket_.close(); out_socket_.close();
				}
			});
			break;
		case 2:
			boost::asio::async_write(in_socket_, boost::asio::buffer(out_buf_, Length),
				[this, self, direction](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
					do_read(direction);
				else
				{
					std::cout << "closing session. Remote socket write error:" << ec.message() << std::endl;
					in_socket_.close(); out_socket_.close();
				}
			});
			break;
		}
	}

	tcp::socket in_socket_;
	tcp::socket out_socket_;

	std::vector<char> in_buf_;
	std::vector<char> out_buf_;
};

class Server
{
public:
	Server(boost::asio::io_service& io_service,std::string& ip, short c_port, short s_port, unsigned buffer_size, short verbose)
		: io_service_(io_service), acceptor_(io_service, tcp::endpoint(tcp::v4(), c_port)),
		acceptor2_(io_service, tcp::endpoint(tcp::v4(), s_port)),
		in_socket_(io_service), out_socket_(io_service), buffer_size_(buffer_size), time(io_service)
	{
		do_in_accept();
	}

private:
	//等待客户端链接
	void do_in_accept()
	{
		acceptor_.async_accept(in_socket_,
			[this](boost::system::error_code ec)
		{
			if (!ec)
			{
				do_out_accept();
			}
			else
				std::cout << "Error: do_in_accept --> " << ec.message() << std::endl;
		});
	}

	//定时，2分钟测试一次 链接是否还存在
	//如果在等待外部链接的时候 in_sock 断开，我们就不再递归，结束所有退出, 自动退出 io_service
	void do_time_run()
	{
		time.expires_from_now(boost::posix_time::seconds(60));
		time.async_wait([&](const boost::system::error_code &ec)
		{
			if (!ec)
			{
				//std::cout << "timer start!" << std::endl;
				boost::asio::async_write(in_socket_, boost::asio::buffer("check"),
					[this](boost::system::error_code ec, std::size_t length)
				{
					if (ec) //如果错误
					{
						std::cout << "Error: in_socket_ send --> " << ec.message() << std::endl;
						in_socket_.close();
						out_socket_.close();
						acceptor2_.cancel();
					}
				});
				do_time_run();
			}
			else
			{
				//std::cout << "timer.cancel() !" << std::endl;
			}
		});
	}
	//等待 外部 链接
	void do_out_accept()
	{
		//std::cout << "do_out_accept ok! " << std::endl;
		acceptor2_.async_accept(out_socket_,
			[this](boost::system::error_code ec)
		{
			time.cancel();
			if (!ec)
			{
				do_Session();
			}
			else
				std::cout << "Error: do_out_accept --> " << ec.message() << std::endl;
		});
		//开启检测
		do_time_run();
	}
	void do_Session()
	{
		//std::cout << "do_Session ok! " << std::endl;
		boost::asio::async_write(in_socket_, boost::asio::buffer("1"),
			[this](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					std::make_shared<Session>(std::move(in_socket_), std::move(out_socket_), buffer_size_)->start();
				}
				else
				{
					std::cout << "Error: do_Session --> " << ec.message() << std::endl;
					in_socket_.close();
					out_socket_.close();
				}
				//递归循环
				do_in_accept();
			});
	}
	boost::asio::io_service& io_service_;
	boost::asio::deadline_timer time;
	tcp::acceptor acceptor_;
	tcp::acceptor acceptor2_;
	short c_port_, s_port_;
	tcp::socket in_socket_;
	tcp::socket out_socket_;
	std::vector<char> buf_;
	size_t buffer_size_;
};

struct ip_port {
	std::string ip;
	uint16_t port;
};

std::vector<ip_port> all_clens_ip;
int main_thread(std::string ipstr, uint16_t ctrlport, uint16_t serport)
{
	std::cout << "客户端IP:" << ipstr << ":" << ctrlport << " -- 服务 端口:" << serport << std::endl;
	ip_port cip;
	cip.ip = ipstr;
	cip.port = serport;
	all_clens_ip.push_back(cip);

	short verbose = 0;
	size_t buffer_size = 8192; // Default buffer_size
	try
	{
		boost::asio::io_service io_service;
		Server server(io_service, ipstr,ctrlport, serport,buffer_size, verbose);
		io_service.run();
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
	catch (...)
	{
		std::cout << "exception..." << std::endl;
	}

	if (all_clens_ip.size())
	{
		all_clens_ip.erase(std::remove_if(all_clens_ip.begin(), all_clens_ip.end(),
										[serport](auto x){ return x.port == serport ? true : false;}),
			all_clens_ip.end());
	}
	std::cout << "客户端退出 --> IP:" << ipstr << " 端口:" << ctrlport
		<< " 分配端口:" << serport << std::endl;
	return 0;
}

//-------------------------------------------
#include <IPHlpApi.h>
#pragma comment(lib, "Iphlpapi.lib")
//依赖lib库 Iphlpapi.lib Ws2_32.lib  

//获取Tcp端口状态  
BOOL GetTcpPortState(ULONG nPort, ULONG *nStateID)
{
	MIB_TCPTABLE TcpTable[100];
	DWORD nSize = sizeof(TcpTable);
	if (NO_ERROR == GetTcpTable(&TcpTable[0], &nSize, TRUE))
	{
		DWORD nCount = TcpTable[0].dwNumEntries;
		if (nCount > 0)
		{
			for (DWORD i = 0; i<nCount; i++)
			{
				MIB_TCPROW TcpRow = TcpTable[0].table[i];
				DWORD temp1 = TcpRow.dwLocalPort;
				int temp2 = temp1 / 256 + (temp1 % 256) * 256;
				if (temp2 == nPort)
				{
					*nStateID = TcpRow.dwState;
					return TRUE;
				}
			}
		}
		return FALSE;
	}
	return FALSE;
}

//获取Udp端口状态  
BOOL GetUdpPortState(ULONG nPort, ULONG *nStateID)
{
	MIB_UDPTABLE UdpTable[100];
	DWORD nSize = sizeof(UdpTable);
	if (NO_ERROR == GetUdpTable(&UdpTable[0], &nSize, TRUE))
	{
		DWORD nCount = UdpTable[0].dwNumEntries;
		if (nCount > 0)
		{
			for (DWORD i = 0; i<nCount; i++)
			{
				MIB_UDPROW TcpRow = UdpTable[0].table[i];
				DWORD temp1 = TcpRow.dwLocalPort;
				int temp2 = temp1 / 256 + (temp1 % 256) * 256;
				if (temp2 == nPort)
				{
					return TRUE;
				}
			}
		}
		return FALSE;
	}
	return FALSE;
}
//-------------------------------------------------------------

void do_accept(tcp::acceptor& acceptor, tcp::socket& sock, uint16_t& ctrlport, uint16_t& serverport)
{
	//std::cout << " port async_accept start ..." << std::endl;
	acceptor.async_accept(sock,
		[&](boost::system::error_code ec)
	{
		if (!ec)
		{
			//获取IP 查看端口是否使用过量
			std::string ipstr = sock.remote_endpoint().address().to_string();
			if (ctrlport < 40000)
			{
				ULONG portstate;
				ctrlport += 2;
				serverport += 2;
				while (GetTcpPortState(ctrlport, &portstate)) ++ctrlport;
				while (GetTcpPortState(serverport, &portstate)) ++serverport;
			}
			else
			{
				ctrlport = 38000;
				serverport = 28000;
			}
			boost::asio::write(sock, boost::asio::buffer(std::to_string(ctrlport)));
			std::make_shared<std::thread>(main_thread, ipstr, ctrlport, serverport)->detach();
		}
		else
			std::cout << " Error: port do_accept ---> " << ec.message() << std::endl;

		sock.close();
		do_accept(acceptor, sock, ctrlport, serverport);
	});
}

void do_accept2(tcp::acceptor& acceptor, tcp::socket& sock)
{
	acceptor.async_accept(sock,
		[&](boost::system::error_code ec)
	{
		if (!ec)
		{
			std::string send_data = "HTTP/1.1 200 OK\r\nContent-Length: ";
			std::string ips;
			if (all_clens_ip.size())
			{
				for (auto i : all_clens_ip)
				{
					ips = ips + i.ip + ":";
					ips += std::to_string(i.port);
					ips += "\r\n";
				}
				send_data += std::to_string(ips.length());
				send_data += "\r\n\r\n";
				send_data += ips;
			}
			else
			{
				send_data += "8\r\n\r\nNo Data!";
			}

			boost::asio::write(sock, boost::asio::buffer(send_data));
			sock.close();
			do_accept2(acceptor,sock);
		}
	});
}


int main()
{
	boost::asio::io_service io_service;

	//http 8080 端口，用于查询客户端链接情况
	tcp::acceptor acceptor2(io_service, tcp::endpoint(boost::asio::ip::tcp::v4(), 8080));
	tcp::socket sock2(io_service);
	do_accept2(acceptor2, sock2);

	//监听端口 分配端口 给客户端
	tcp::acceptor acceptor(io_service, tcp::endpoint(boost::asio::ip::tcp::v4(), 30080));
	tcp::socket sock(io_service);
	uint16_t ctrlport = 38000;
	uint16_t serverport = 28000;
	do_accept(acceptor, sock, ctrlport, serverport);
	std::cout << "服务运行...等待客户链接！查看端口8080!" << std::endl;
	io_service.run();

	system("pause");
}
