#include "srcon.h"

#include <mh/memory/unique_object.hpp>

#include <cassert>
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <sstream>
#include <thread>
#include <vector>

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

static constexpr bool SRCON_LOG_TX = false;
static constexpr bool SRCON_LOG_RX = false;

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

namespace srcon
{
	template<typename PacketType>
	struct PacketHeader
	{
		static_assert(std::is_same_v<std::underlying_type_t<PacketType>, int32_t>);
		int32_t m_Size{};
		int32_t m_ID{};
		PacketType m_Type{};
	};

	template<typename PacketType>
	struct Packet
	{
		using header_type = srcon::PacketHeader<PacketType>;

		static_assert(std::is_same_v<std::underlying_type_t<PacketType>, int32_t>);
		int32_t m_ID{};
		PacketType m_Type{};

		std::string m_Body1;
		std::string m_Body2;

		std::vector<char> pack() const
		{
			//using PacketHeader = RequestPacketHeader<true>;
			const auto packetSizeActual = sizeof(header_type) + m_Body1.size() + 1 + m_Body2.size() + 1;
			assert(packetSizeActual >= sizeof(header_type));

			std::vector<char> packet(packetSizeActual);
			header_type& header = *reinterpret_cast<header_type*>(packet.data());
			header.m_Size = packetSizeActual - sizeof(header_type::m_Size);
			header.m_ID = m_ID;
			header.m_Type = m_Type;

			char* destPtr = packet.data() + sizeof(header_type);
			std::memcpy(destPtr, m_Body1.data(), m_Body1.size());
			destPtr += m_Body1.size();
			*(destPtr++) = '\0';

			std::memcpy(destPtr, m_Body2.data(), m_Body2.size());
			destPtr += m_Body2.size();
			*(destPtr++) = '\0';

			assert(destPtr == (packet.data() + packet.size()));
			return packet;
		}
	};

	using RequestPacket = Packet<RequestPacketType>;
	using ResponsePacket = Packet<ResponsePacketType>;
	using RequestPacketHeader = PacketHeader<RequestPacketType>;
	using ResponsePacketHeader = PacketHeader<ResponsePacketType>;

	//static_assert(sizeof(PacketHeader) == 12);
	static constexpr int32_t SRCON_MIN_ACTUAL_PACKET_SIZE = sizeof(PacketHeader<RequestPacketType>) + 1 + 1;

#if 0
#pragma pack(push)
#pragma pack(1)
	template<typename PacketType, size_t bodySize1, size_t bodySize2 = 0>
	struct Packet : PacketHeader<true, PacketType>
	{
		char m_Body1[bodySize1 + 1]{};
		char m_Body2[bodySize2 + 1]{};
	};
#pragma pack(pop)

	static_assert(sizeof(Packet<RequestPacketType, 0, 0>) == 14);
#endif
}

struct srcon::client::SocketData
{
	uint32_t m_NextID = 1;

	~SocketData()
	{
		if (m_Socket != INVALID_SOCKET)
			closesocket(m_Socket);
	}

	SOCKET m_Socket = INVALID_SOCKET;

	std::vector<ResponsePacket> send(const std::string_view& data,
		RequestPacketType type = RequestPacketType::SERVERDATA_EXECCOMMAND, bool reliable = true)
	{
		RequestPacket packetTemp;
		packetTemp.m_Type = type;
		packetTemp.m_ID = m_NextID++;
		packetTemp.m_Body1 = data;

		auto packet = packetTemp.pack();

		if constexpr (SRCON_LOG_TX)
			LOG('[' << packetTemp.m_ID << "] Sending: \"" << data << '"');

		const auto sendResult = ::send(m_Socket, reinterpret_cast<const char*>(packet.data()), packet.size(), 0);
		if (sendResult < 0)
		{
			const auto error = GetSocketError();
			std::stringstream ss;
			ss << "Sending failed! " << error.message();
			throw srcon_error(ss.str());
		}
		else if (sendResult != packet.size())
		{
			std::stringstream ss;
			ss << "Sending failed! Sent " << sendResult << " bytes instead of " << packet.size() << " expected.";
			throw srcon_error(ss.str());
		}

		if (type == RequestPacketType::SERVERDATA_AUTH)
		{
			std::vector<ResponsePacket> responses;
			do
			{
				responses.push_back(read_packet());

			} while (responses.back().m_Type != ResponsePacketType::SERVERDATA_AUTH_RESPONSE);

			return responses;
		}

		//if (type != PacketType::SERVERDATA_EXECCOMMAND)
		//	return "";

		if (!reliable)
			return {};

		unsigned long halt_id = m_NextID;
		send("", RequestPacketType::SERVERDATA_EXECCOMMAND, false);
		return recv(halt_id);
	}

	size_t read_packet_len() const
	{
		//char buffer[4]{};
		char buffer[64]{};
		::recv(m_Socket, buffer, 4, 0);
		const size_t len = byte32_to_int(buffer);
		return len;
	}

	ResponsePacket read_packet() const
	{
		ResponsePacket packet;
		size_t len = read_packet_len();

		auto buffer = std::make_unique<char[]>(len);
		unsigned int bytes = 0;
		do
		{
			auto recvResult = ::recv(m_Socket, buffer.get() + bytes, len - bytes, 0);
			if (recvResult < 0)
			{
				const auto err = GetSocketError();
				std::stringstream ss;
				ss << __FUNCTION__ << "(): Error while receiving data: " << err.message();
				throw srcon_error(ss.str());
			}

			bytes += recvResult;

		} while (bytes < len);

		struct PacketHeaderNoSize
		{
			int32_t m_ID;
			ResponsePacketType m_Type;
		};

		const auto& header = *reinterpret_cast<const PacketHeaderNoSize*>(buffer.get());

		packet.m_ID = header.m_ID;
		packet.m_Type = header.m_Type;

		auto body = std::string_view(&buffer.get()[sizeof(PacketHeaderNoSize)],
			len - sizeof(PacketHeaderNoSize));

		auto firstNullTerm = body.find('\0');
		packet.m_Body1 = body.substr(0, firstNullTerm);

		auto secondNullTerm = body.rfind('\0');
		packet.m_Body2 = body.substr(firstNullTerm + 1, secondNullTerm - (firstNullTerm + 1));

		if constexpr (SRCON_LOG_RX)
			LOG('[' << packet.m_ID << "] Receiving: " << packet.m_Body1);

		return packet;
	}

	std::vector<ResponsePacket> recv(unsigned long halt_id) const
	{
		std::vector<ResponsePacket> responses;
		while (1)
		{
			auto packet = read_packet();
			if (packet.m_ID == halt_id)
				break;

			responses.push_back(std::move(packet));
		}

		//auto packet2 = read_packet();
		return responses;
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
	LOG("Connecting to " << addr.addr << ':' << addr.port << "...");

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

	auto authResponses = retVal->send(addr.pass, RequestPacketType::SERVERDATA_AUTH);

	for (auto& response : authResponses)
	{
		if (response.m_Type != ResponsePacketType::SERVERDATA_AUTH_RESPONSE)
			continue;

		if (response.m_ID == -1)
		{
			std::stringstream ss;
			ss << "Bad RCON password when connecting to " << addr.addr << ':' << addr.port;
			throw srcon_error(ss.str());
		}
	}

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

std::string srcon::client::send_command(const std::string_view& data)
{
	if (!is_connected())
		throw srcon_error("Connection has not been established.");

	auto responses = m_Socket->send(data);
	if (responses.size() == 1)
		return responses[0].m_Body1;

	std::string retVal;

	for (auto& response : responses)
	{
		retVal += response.m_Body1;
	}

	return retVal;
}

int srcon::client::byte32_to_int(const char* buffer)
{
	return	static_cast<int>(
		static_cast<unsigned char>(buffer[0]) |
		static_cast<unsigned char>(buffer[1]) << 8 |
		static_cast<unsigned char>(buffer[2]) << 16 |
		static_cast<unsigned char>(buffer[3]) << 24);
}
