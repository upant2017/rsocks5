/**
* @file boost_socks5.cpp
* @brief Simple SOCKS5 proxy server realization using boost::asio library
* @author philave (philave7@gmail.com)
*/
#include "stdafx.h"

#include <cstdlib>
#include <string>
#include <array>

#include <boost/asio.hpp>

#include "port_ran.h"

using boost::asio::ip::tcp;

class MySession : public std::enable_shared_from_this<MySession>
{
public:
	MySession(tcp::socket in_socket, tcp::socket out_socket)
		: in_socket_(std::move(in_socket)), out_socket_(std::move(out_socket))
	{

	}

	void start()
	{
		do_read(3);
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
				//std::cout << "do_read 1!" << std::endl;
				//将客户端发来的信息 发给 服务器
				do_write(1, length);
			}
			else //if (ec != boost::asio::error::eof)
			{
				//std::cout << "Error: do_read 1!" << std::endl;
				in_socket_.close(); out_socket_.close();
			}
		});

		if (direction & 0x2)
			out_socket_.async_receive(boost::asio::buffer(out_buf_),
				[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				//std::cout << "do_read 2!" << std::endl;
				//将服务器发来的信息 发给客户端
				do_write(2, length);
			}
			else //if (ec != boost::asio::error::eof)
			{
				//std::cout << "Error: do_read 2!" << std::endl;
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
				//std::cout << "do_write 1!" << std::endl;
				if (!ec)
					do_read(direction);
				else
				{
					//std::cout << "Error: do_write 1!" << std::endl;
					in_socket_.close(); out_socket_.close();
				}
			});
			break;
		case 2:
			boost::asio::async_write(in_socket_, boost::asio::buffer(out_buf_, Length),
				[this, self, direction](boost::system::error_code ec, std::size_t length)
			{
				//std::cout << "do_write 2!" << std::endl;
				if (!ec)
					do_read(direction);
				else
				{
					//std::cout << "Error: do_write 2!" << std::endl;
					in_socket_.close(); out_socket_.close();
				}
			});
			break;
		}
	}

	tcp::socket in_socket_;
	tcp::socket out_socket_;
	std::array<char, 8192> in_buf_;
	std::array<char, 8192> out_buf_;
};

class MyServer
{
public:
	MyServer(boost::asio::io_service& p_io_service, size_t buffer_size, char *szCtrlIP, WORD wCtrlPort, char *szIP, WORD wPort)
		: in_socket_(p_io_service), out_socket_(p_io_service),resolver_(p_io_service),ctrl_ip_(szCtrlIP), ctrl_port_(wCtrlPort),
		local_ip_(szIP), local_port_(wPort),buf_(buffer_size)
	{
		do_resolve();
	}

private:
	void do_resolve()
	{
		tcp::resolver::iterator iterator = resolver_.resolve(tcp::resolver::query({ ctrl_ip_, std::to_string(ctrl_port_) }));
		tcp::endpoint endpoint = *iterator;
		do_connect(iterator);
	}

	void do_connect(tcp::resolver::iterator it)
	{
		in_socket_.async_connect(*it,
			[this, it](const boost::system::error_code &ec)
		{
			if (!ec)
			{
				std::cout << "connect server OK!" << std::endl;
				in_socket_.async_receive(boost::asio::buffer(buf_),
					[this, it](const boost::system::error_code &ec, std::size_t bytes)
				{
					if (!ec)
					{
						tcp::resolver::iterator iterator = resolver_.resolve(tcp::resolver::query({ local_ip_, std::to_string(local_port_) }));
						out_socket_.async_connect(*iterator,
							[this, it](const boost::system::error_code &ec)
						{
							if (!ec)
							{
								std::cout << "connect localhost OK!" << std::endl;
								std::make_shared<MySession>(std::move(in_socket_), std::move(out_socket_))->start();
								do_connect(it);
							}
							else
							{
								std::cout << "Error: do_out_connect! :" << ec << std::endl;
							}
						});
					}
				});
			}
			else
			{
				std::cout << "Error: do_connect!" << std::endl;
				Sleep(2000);
			}
		});
	}

	tcp::socket in_socket_;
	tcp::socket out_socket_;
	std::string ctrl_ip_;
	WORD ctrl_port_;
	std::string local_ip_;
	WORD local_port_;
	tcp::resolver resolver_;
	std::vector<char> buf_;
};
/***********************************************************/
boost::asio::io_service io_service;
tcp::resolver resolver(io_service);
tcp::socket sock(io_service);
std::array<char, 4096> buffer;
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
	while (!ser_prot)
	{
		boost::asio::ip::tcp::resolver::query query(remot_ip, "30080");
		resolver.async_resolve(query, resolve_handler);
		io_service.run();
		Sleep(3000);
	}
	const char* local_ip = "127.0.0.1";
	std::cout << "连接中...Server IP:" << remot_ip << " port:" << ser_prot << std::endl;
	try
	{
		while (1)
		{
			boost::asio::io_service io_service2;
			MyServer server(io_service2, 8192, remot_ip, ser_prot, (char*)local_ip, 31080);
			io_service2.run();
		}
	}
	catch (...)
	{
		std::cout << "连接异常..." << std::endl;
	}
	return 0;
}
