#include "..\include\srcon.h"
#include "..\include\srcon.h"
#include "..\include\srcon.h"
#include "srcon.h"

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

bool srcon::client::connect(srcon_addr addr, timeout_t timeout)
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

	m_Socket.reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

	if (m_Socket.value() == -1)
	{
		LOG("Error opening socket.");
		return false;
	}

	m_Address = std::move(addr);
	m_Timeout = timeout;

	LOG("Socket (" << m_Socket << ") opened, connecting...");
	if (!connect(timeout))
	{
		LOG("Connection not established.");
		m_Socket.reset();
		return false;
	}

	LOG("Connection established!");
	connected = true;

	send(m_Address.pass, PacketType::SERVERDATA_AUTH);
	char buffer[SRCON_HEADER_SIZE];
	::recv(m_Socket.value(), buffer, SRCON_HEADER_SIZE, (int)PacketType::SERVERDATA_RESPONSE_VALUE);
	::recv(m_Socket.value(), buffer, SRCON_HEADER_SIZE, (int)PacketType::SERVERDATA_RESPONSE_VALUE);

	return true;
}

bool srcon::client::connect(std::string address, std::string password, int port, timeout_t timeout)
{
	srcon_addr addr;
	addr.addr = std::move(address);
	addr.pass = std::move(password);
	addr.port = port;
	return connect(std::move(addr), timeout);
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

static bool SetSocketTimeout(SOCKET s, srcon::timeout_t time)
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
		LOG("Failed to set socket timeout");
		return false;
	}

	return true;
}

bool srcon::client::connect(const timeout_t timeout) const
{
	sockaddr_in server{};
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(m_Address.addr.c_str());
	server.sin_port = htons(m_Address.port);

	SetNonBlocking(m_Socket.value(), true);

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(m_Socket.value(), &fds);

	int status = SOCKET_ERROR;
	if ((status = ::connect(m_Socket.value(), (struct sockaddr*)&server, sizeof(server))) == SOCKET_ERROR)
	{
		auto error = GetSocketError();
		const auto msg = error.message();
		if (error != SRCON_EWOULDBLOCK)
			return false;
	}

	//status = select(sockfd + 1, NULL, &fds, NULL, &tv);
	SetSocketTimeout(m_Socket.value(), timeout);
	SetNonBlocking(m_Socket.value(), false);
	return status != 0;
}

bool srcon::client::reconnect()
{
	disconnect();
	return connect(m_Address, m_Timeout);
}

void srcon::client::disconnect()
{
	m_Socket.reset();
}

std::string srcon::client::send(const std::string_view& data, const PacketType type)
{
	//LOG("Sending: \"" << data << '"');
	if (!is_connected())
		throw srcon_error("Connection has not been established.");

	int packet_len = data.length() + SRCON_HEADER_SIZE;

	auto packet = std::make_unique<char[]>(packet_len);
	pack(packet.get(), data, packet_len, id++, type);
	if (::send(m_Socket.value(), packet.get(), packet_len, 0) < 0)
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

std::string srcon::client::recv(unsigned long halt_id) const
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
			LOG("Invalid offset " << offset);

		std::string_view part(&buffer[8], offset);
		response += part;
	}

	buffer = read_packet(bytes, can_sleep);
	return response;
}

std::unique_ptr<char[]> srcon::client::read_packet(unsigned int& size, bool& can_sleep) const
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
		auto recvResult = ::recv(m_Socket.value(), buffer.get(), len - bytes, 0);
		if (recvResult < 0)
		{
			const auto err = GetSocketError();
			std::stringstream ss;
			ss << __FUNCTION__ << "(): Error while receiving data: " << err.message();
			throw std::runtime_error(ss.str());
		}

		bytes += recvResult;

	} while (bytes < len);

	size = len;
	return buffer;
}

size_t srcon::client::read_packet_len() const
{
	char buffer[4]{};
	::recv(m_Socket.value(), buffer, 4, 0);
	const size_t len = byte32_to_int(buffer);
	return len;
}

void srcon::client::pack(char packet[], const std::string_view& data, int packet_len, int id, PacketType type) const
{
	int data_len = packet_len - SRCON_HEADER_SIZE;
	std::memset(packet, 0, packet_len);
	packet[0] = data_len + 10;
	packet[4] = id;
	packet[8] = int(type);
	for (int i = 0; i < data_len; i++)
		packet[12 + i] = data[i];
}

size_t srcon::client::byte32_to_int(const char* buffer) const
{
	return	static_cast<size_t>(
		static_cast<unsigned char>(buffer[0]) |
		static_cast<unsigned char>(buffer[1]) << 8 |
		static_cast<unsigned char>(buffer[2]) << 16 |
		static_cast<unsigned char>(buffer[3]) << 24);
}

void srcon::client::SocketTraits::delete_obj(int& socket) const
{
	if (auto result = closesocket(socket); result != 0)
	{
		auto err = GetSocketError();
		std::stringstream ss;
		ss << __FUNCTION__ << "(): Failed to closesocket(): " << err.message();
	}

	socket = 0;
}

int srcon::client::SocketTraits::release_obj(int& socket) const
{
	int temp = socket;
	socket = 0;
	return temp;
}

bool srcon::client::SocketTraits::is_obj_valid(int socket) const
{
	return socket > 0;
}
