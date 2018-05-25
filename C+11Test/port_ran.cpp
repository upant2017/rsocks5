/**
* @file boost_socks5.cpp
* @brief Simple SOCKS5 proxy server realization using boost::asio library
* @962072900@qq.com
*/
#include "stdafx.h"

#include <cstdlib>
#include <string>
#include <array>
#include <thread>
#include <chrono>

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
				std::cout << "Error:1 do_read over!" << std::endl;
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
				std::cout << "Error:2 do_read over!" << std::endl;
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
					std::cout << "Error: 2 do_write over!" << std::endl;
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
					std::cout << "Error: 2 do_write over!" << std::endl;
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
	MyServer(boost::asio::io_service& p_io_service, char *szCtrlIP, WORD wCtrlPort, char *szIP, WORD wPort)
		: in_socket_(p_io_service), out_socket_(p_io_service),resolver_(p_io_service),ctrl_ip_(szCtrlIP), ctrl_port_(wCtrlPort),
		local_ip_(szIP), local_port_(wPort), timer(p_io_service)
	{
		do_resolve();
	}

private:
	void do_resolve()
	{
		tcp::resolver::iterator iterator = resolver_.resolve(tcp::resolver::query({ ctrl_ip_, std::to_string(ctrl_port_) }));
		do_connect(iterator);
	}

	void do_connect(tcp::resolver::iterator it)
	{
		in_socket_.async_connect(*it,
			[this](const boost::system::error_code &ec)
		{
			if (!ec)
			{
				do_read();
			}
			else
			{
				std::cout << "Error: MyServer::do_connect! -->" << ec.message() << std::endl;
			}
		});
	}
	//定时，3分钟没链接 断开重连
	void do_time_run()
	{
		timer.expires_from_now(boost::posix_time::seconds(180));
		timer.async_wait([&](const boost::system::error_code &ec)
		{
			
			if (!ec)
			{
				in_socket_.close();
				do_resolve();
				//std::cout << "timer ok!" << std::endl;
			}
			else
			{
				//std::cout << "timer.cancel() !" << std::endl;
			}
		});
	}

	void do_read()
	{
		//TOUO: 时间长服务器无法发送
		in_socket_.async_receive(boost::asio::buffer(buf_),
			[this](const boost::system::error_code &ec, std::size_t bytes)
		{
			timer.cancel();
			if (!ec)
			{
				//如果是 保连 验证，重新进入等待
				if (std::string(buf_.data()) == "check")
				{
					do_read();
				}
				else
				{
					do_connect_socks5();
				}
			}
			else
			{
				std::cout << "Error: do_read 0!" << ec.message() << std::endl;
			}
		});
		do_time_run();
	}
	void do_connect_socks5()
	{
		tcp::resolver::iterator iterator = resolver_.resolve(tcp::resolver::query({ local_ip_, std::to_string(local_port_) }));
		out_socket_.async_connect(*iterator,
			[this](const boost::system::error_code &ec)
		{
			if (!ec)
			{
				//std::cout << "connect localhost OK!" << std::endl;
				std::make_shared<MySession>(std::move(in_socket_), std::move(out_socket_))->start();
				do_resolve();
			}
			else
			{
				std::cout << "Error: do_connect_socks5! :" << ec.message() << std::endl;
			}
		});
	}

	boost::asio::deadline_timer timer;
	tcp::socket in_socket_;
	tcp::socket out_socket_;
	std::string ctrl_ip_;
	WORD ctrl_port_;
	std::string local_ip_;
	WORD local_port_;
	tcp::resolver resolver_;
	std::array<char,4096> buf_;
};
/***********************************************************/

//链接服务器 得到服务器分配的端口
void resolve_handler(tcp::socket& sock, uint16_t& ser_prot,boost::asio::ip::tcp::resolver::iterator& it)
{
	sock.async_connect(*it,
		[&](const boost::system::error_code &ec)
	{
		if (!ec)
		{
			std::array<char, 4096> buffer;
			sock.async_receive(boost::asio::buffer(buffer),
				[&](const boost::system::error_code &ec, std::size_t bytes)
			{
				if (!ec)
				{
					ser_prot = std::atoi(buffer.data());
					sock.close();
				}
				else
				{
					std::cout << "Error: sock.async_read_some! -->" << ec.message() <<std::endl;
					sock.close();
					resolve_handler(sock, ser_prot,it);
				}
			});
		}
		else
		{
			std::cout << "Error: sock.async_connect! -->" << ec.message() << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(5));
			resolve_handler(sock, ser_prot, it);
		}
	});
}

DWORD WINAPI PortTransfer(LPVOID lParam)
{
	char* remot_ip = (char*)lParam;

	try
	{
		while (1)
		{
			uint16_t ser_prot = 0;
			while (!ser_prot)
			{
				boost::asio::io_service io_service;
				tcp::resolver resolver(io_service);
				tcp::socket sock(io_service);
				tcp::resolver::iterator iterator = resolver.resolve(tcp::resolver::query({ remot_ip, "30080" }));
				resolve_handler(sock, ser_prot,iterator);
				io_service.run();
			}

			const char* local_ip = "127.0.0.1";
			std::cout << "连接中...Server IP:" << remot_ip << " port:" << ser_prot << std::endl;

			boost::asio::io_service io_service2;
			MyServer server(io_service2, remot_ip, ser_prot, (char*)local_ip, 31080);
			//boost::asio::io_service::work io_work(io_service);
			io_service2.run();
		}
	}
	catch (...)
	{
		std::cout << "连接异常..." << std::endl;
	}
	return 0;
}
