#include "srcon.h"

#include <mh/memory/unique_object.hpp>

#include <iostream>
#include <string.h>
#include <fcntl.h>
#include <chrono>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <WinSock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket(sock) close(sock)
#define SOCKET_ERROR (-1)
#endif

static std::error_code GetSocketError()
{
#ifdef _WIN32
	return std::error_code(WSAGetLastError(), std::system_category());
#else
	return std::error_code(errno, std::generic_category());
#endif
}

#ifdef _WIN32
static const std::error_code SRCON_EWOULDBLOCK(WSAEWOULDBLOCK, std::system_category());
static const std::error_code SRCON_EINPROGRESS(WSAEINPROGRESS, std::system_category());
#else
static const std::error_code SRCON_EWOULDBLOCK(EWOULDBLOCK, std::generic_category());
static const std::error_code SRCON_EINPROGRESS(EINPROGRESS, std::generic_category());
#endif

static void DefaultLogFunc(std::string&& str)
{
	std::clog << str << std::endl;
}

static srcon::LogFunc_t s_LogFunc = &DefaultLogFunc;
void srcon::SetLogFunc(LogFunc_t func)
{
	s_LogFunc = func ? func : &DefaultLogFunc;
}

#define LOG(msg) \
	do \
	{ \
		std::stringstream ss; \
		ss << msg; \
		s_LogFunc(ss.str()); \
	} while (0)

struct SocketTraits
{
	void delete_obj(SOCKET& socket) const
	{
		if (auto result = closesocket(socket); result != 0)
		{
			auto err = GetSocketError();
			std::stringstream ss;
			ss << __FUNCTION__ << "(): Failed to closesocket(): " << err.message();
		}

		socket = INVALID_SOCKET;
	}
	int release_obj(SOCKET& socket) const
	{
		int temp = socket;
		socket = 0;
		return temp;
	}
	bool is_obj_valid(SOCKET socket) const
	{
		return socket != INVALID_SOCKET;
	}
};

struct srcon::client::SocketData
{
	unsigned int id = 0;

	~SocketData()
	{
		if (m_Socket != INVALID_SOCKET)
			closesocket(m_Socket);
	}

	SOCKET m_Socket = INVALID_SOCKET;

	std::string send(const std::string_view& data, PacketType type = PacketType::SERVERDATA_EXECCOMMAND)
	{
		//LOG("Sending: \"" << data << '"');

		int packet_len = data.length() + SRCON_HEADER_SIZE;

		auto packet = std::make_unique<char[]>(packet_len);
		pack(packet.get(), data, packet_len, id++, type);
		if (::send(m_Socket, packet.get(), packet_len, 0) < 0)
		{
			std::stringstream ss;
			ss << "Sending failed! " << GetSocketError().message();
			throw srcon_error(ss.str());
		}

		if (type != PacketType::SERVERDATA_EXECCOMMAND)
			return "";

		unsigned long halt_id = id;
		send("", PacketType::SERVERDATA_RESPONSE_VALUE);
		return recv(halt_id);
	}

	void pack(char packet[], const std::string_view& data, int packet_len, int id, PacketType type) const
	{
		int data_len = packet_len - SRCON_HEADER_SIZE;
		std::memset(packet, 0, packet_len);
		packet[0] = data_len + 10;
		packet[4] = id;
		packet[8] = int(type);
		for (int i = 0; i < data_len; i++)
			packet[12 + i] = data[i];
	}

	size_t read_packet_len() const
	{
		char buffer[4]{};
		::recv(m_Socket, buffer, 4, 0);
		const size_t len = byte32_to_int(buffer);
		return len;
	}

	std::unique_ptr<char[]> read_packet(unsigned int& size, bool& can_sleep) const
	{
		size_t len = read_packet_len();
		if (can_sleep && len > SRCON_SLEEP_THRESHOLD)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(SRCON_SLEEP_MILLISECONDS));
			can_sleep = false;
		}

		auto buffer = std::make_unique<char[]>(len);
		unsigned int bytes = 0;
		do
		{
			auto recvResult = ::recv(m_Socket, buffer.get(), len - bytes, 0);
			if (recvResult < 0)
			{
				const auto err = GetSocketError();
				std::stringstream ss;
				ss << __FUNCTION__ << "(): Error while receiving data: " << err.message();
				throw srcon_error(ss.str());
			}

			bytes += recvResult;

		} while (bytes < len);

		size = len;
		return buffer;
	}

	std::string recv(unsigned long halt_id) const
	{
		unsigned int bytes = 0;
		std::unique_ptr<char[]> buffer;
		std::string response;
		bool can_sleep = false;//true;
		while (1)
		{
			buffer = read_packet(bytes, can_sleep);
			if (byte32_to_int(buffer.get()) == halt_id)
				break;

			int offset = bytes - SRCON_HEADER_SIZE + 3;
			if (offset == -1)
				continue;
			else if (offset < 0)
			{
				std::stringstream ss;
				ss << "Invalid offset " << offset;
				throw srcon_error(ss.str());
			}

			std::string_view part(&buffer[8], offset);
			response += part;
		}

		buffer = read_packet(bytes, can_sleep);
		return response;
	}
};

void srcon::client::SocketDataDeleter::operator()(SocketData* data) const
{
	delete data;
}

srcon::client::~client()
{
	m_Socket.reset();
}

static bool SetNonBlocking(SOCKET s, bool isNonBlocking)
{
#ifdef _WIN32
	u_long value = isNonBlocking ? 1 : 0;
	if (auto ret = ioctlsocket(s, FIONBIO, &value); ret == SOCKET_ERROR)
	{
		LOG("Failed to change socket's non-blocking mode");
		return false;
	}
#else
	auto existing = fcntl(sockfd, F_GETFL, 0);

	if (isNonBlocking)
		existing |= O_NONBLOCK;
	else
		existing &= ~(O_NONBLOCK);

	fcntl(sockfd, F_SETFL, existing);
#endif

	return true;
}

static void SetSocketTimeout(SOCKET s, srcon::timeout_t time)
{
#ifdef _WIN32
	DWORD timeoutVal = std::chrono::duration_cast<std::chrono::milliseconds>(time).count();
#else
	timeval timeoutVal{};
	timeoutVal.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(time).count();
	timeoutVal.tv_usec = std::chrono::duration_cast<std::chrono::microseconds>(time - std::chrono::seconds(timeoutVal.tv_sec)).count();
#endif

	if (auto result = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutVal), sizeof(timeoutVal));
		result != 0)
	{
		throw srcon::srcon_error("Failed to set socket receive timeout");
	}

	if (auto result = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeoutVal), sizeof(timeoutVal));
		result != 0)
	{
		throw srcon::srcon_error("Failed to set socket send timeout");
	}
}

auto srcon::client::ConnectImpl(const srcon_addr& addr, const timeout_t& timeout) -> SocketDataPtr
{
#ifdef _WIN32
	WSADATA wsaData{};
	if (auto result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		result != 0)
	{
		std::stringstream ss;
		ss << "Failed to initialize Winsock 2.2: " << std::error_code(result, std::system_category()).message();
		LOG(ss.str());
		throw srcon_error(ss.str());
	}
#endif

	auto retVal = SocketDataPtr(new SocketData());

	retVal->m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (retVal->m_Socket == INVALID_SOCKET)
		throw srcon_error("Error opening socket");

	LOG("Socket (" << retVal->m_Socket << ") opened, connecting...");
	SetSocketTimeout(retVal->m_Socket, timeout);

	SetNonBlocking(retVal->m_Socket, true);
	{
		sockaddr_in server{};
		server.sin_family = AF_INET;
		server.sin_addr.s_addr = inet_addr(addr.addr.c_str());
		server.sin_port = htons(addr.port);


		int status = SOCKET_ERROR;
		if ((status = ::connect(retVal->m_Socket, (struct sockaddr*)&server, sizeof(server))) == SOCKET_ERROR)
		{
			auto error = GetSocketError();
			const auto msg = error.message();
			if (error != SRCON_EWOULDBLOCK)
			{
				std::stringstream ss;
				ss << "Error during connection: " << error.message();
				throw srcon_error(ss.str());
			}
		}
	}
	SetNonBlocking(retVal->m_Socket, false);

	retVal->send(addr.pass, PacketType::SERVERDATA_AUTH);
	char buffer[SRCON_HEADER_SIZE];
	::recv(retVal->m_Socket, buffer, SRCON_HEADER_SIZE, (int)PacketType::SERVERDATA_RESPONSE_VALUE);
	::recv(retVal->m_Socket, buffer, SRCON_HEADER_SIZE, (int)PacketType::SERVERDATA_RESPONSE_VALUE);

	LOG("Connection established!");
	return retVal;
}

void srcon::client::connect(srcon_addr addr, timeout_t timeout)
{
	m_Socket.reset();

	m_Address = std::move(addr);
	m_Timeout = std::move(timeout);
	m_Socket = ConnectImpl(m_Address, m_Timeout);

	if (!m_Socket)
		throw srcon_error("Unknown error when connecting");
}

void srcon::client::connect(std::string address, std::string password, int port, timeout_t timeout)
{
	srcon_addr addr;
	addr.addr = std::move(address);
	addr.pass = std::move(password);
	addr.port = port;
	connect(std::move(addr), timeout);
}

void srcon::client::reconnect()
{
	if (m_Address.addr.empty() || m_Address.port <= 0)
		throw srcon_error("reconnect() failed: No preexisting connection");

	disconnect();
	return connect(m_Address, m_Timeout);
}

void srcon::client::disconnect()
{
	m_Socket.reset();
}

std::string srcon::client::send(const std::string_view& data, PacketType type)
{
	if (!is_connected())
		throw srcon_error("Connection has not been established.");

	return m_Socket->send(data, type);
}

size_t srcon::client::byte32_to_int(const char* buffer)
{
	return	static_cast<size_t>(
		static_cast<unsigned char>(buffer[0]) |
		static_cast<unsigned char>(buffer[1]) << 8 |
		static_cast<unsigned char>(buffer[2]) << 16 |
		static_cast<unsigned char>(buffer[3]) << 24);
}
