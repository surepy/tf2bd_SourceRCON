#include "../include/srcon.h"

#include <iostream>
#include <string.h>
#include <fcntl.h>
#include <cassert>
#include <chrono>
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

//#define DEBUG 1
#ifdef _DEBUG
#define LOG(str) std::clog << str << std::endl;
#else
#define LOG(str)
#endif

srcon::client::client(const std::string address, const int port, const std::string pass, const int timeout)
	: client(srcon_addr{ address, port, pass }, timeout)
{
}

srcon::client::client(const srcon_addr addr, const int timeout) :
	addr(addr),
	sockfd(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)),
	id(0),
	connected(false)
{
	if (sockfd == -1)
	{
		LOG("Error opening socket.");
		return;
	}

	LOG("Socket (" << sockfd << ") opened, connecting...");
	if (!connect(timeout))
	{
		LOG("Connection not established.");
		closesocket(sockfd);
		return;
	}

	LOG("Connection established!");
	connected = true;

	send(addr.pass, SERVERDATA_AUTH);
	char buffer[SRCON_HEADER_SIZE];
	::recv(sockfd, buffer, SRCON_HEADER_SIZE, SERVERDATA_RESPONSE_VALUE);
	::recv(sockfd, buffer, SRCON_HEADER_SIZE, SERVERDATA_RESPONSE_VALUE);
}

srcon::client::~client()
{
	if (get_connected())
		closesocket(sockfd);
}

static bool SetNonBlocking(SOCKET s, bool isNonBlocking)
{
#ifdef _WIN32
	u_long value = isNonBlocking ? 1 : 0;
	if (auto ret = ioctlsocket(s, FIONBIO, &value); ret == SOCKET_ERROR)
	{
		assert(!"Failed to change socket's non-blocking mode");
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

bool srcon::client::connect(const int timeout) const
{
	sockaddr_in server{};
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(addr.addr.c_str());
	server.sin_port = htons(addr.port);

	SetNonBlocking(sockfd, true);

	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);

	int status = SOCKET_ERROR;
	if ((status = ::connect(sockfd, (struct sockaddr*)&server, sizeof(server))) == SOCKET_ERROR)
	{
		auto error = GetSocketError();
		const auto msg = error.message();
		if (error != SRCON_EWOULDBLOCK)
			return false;
	}

	status = select(sockfd + 1, NULL, &fds, NULL, &tv);
	SetNonBlocking(sockfd, false);
	return status != 0;
}

std::string srcon::client::send(const std::string_view& data, const int type)
{
	LOG("Sending: " << data);
	if (!get_connected())
		return "Connection has not been established.";

	int packet_len = data.length() + SRCON_HEADER_SIZE;

	auto packet = std::make_unique<char[]>(packet_len);
	pack(packet.get(), data, packet_len, id++, type);
	if (::send(sockfd, packet.get(), packet_len, 0) < 0)
		return "Sending failed!";

	if (type != SERVERDATA_EXECCOMMAND)
		return "";

	unsigned long halt_id = id;
	send("", SERVERDATA_RESPONSE_VALUE);
	return recv(halt_id);
}

std::string srcon::client::recv(unsigned long halt_id) const
{
	unsigned int bytes = 0;
	std::unique_ptr<char[]> buffer;
	std::string response;
	bool can_sleep = true;
	while (1)
	{
		buffer = read_packet(bytes, can_sleep);
		if (byte32_to_int(buffer.get()) == halt_id)
			break;

		int offset = bytes - SRCON_HEADER_SIZE + 3;
		if (offset == -1)
			continue;

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
		bytes += ::recv(sockfd, buffer.get(), len - bytes, 0);

	} while (bytes < len);

	size = len;
	return buffer;
}

size_t srcon::client::read_packet_len() const
{
	char buffer[4]{};
	::recv(sockfd, buffer, 4, 0);
	const size_t len = byte32_to_int(buffer);
	return len;
}

void srcon::client::pack(char packet[], const std::string_view& data, int packet_len, int id, int type) const
{
	int data_len = packet_len - SRCON_HEADER_SIZE;
	std::memset(packet, 0, packet_len);
	packet[0] = data_len + 10;
	packet[4] = id;
	packet[8] = type;
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
