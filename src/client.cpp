#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include "srcon/srcon.h"
#include "srcon/client.h"
#include "srcon_internal.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <string.h>
#include <sstream>
#include <thread>
#include <vector>

#ifdef _WIN32
	#include <WinSock2.h>
	using socklen_t = int;
#else
	#include <netinet/in.h>
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <unistd.h>
	using SOCKET = int;
	static auto closesocket(SOCKET sock) { return close(sock); }
	static constexpr int SOCKET_ERROR = -1;
	static constexpr int INVALID_SOCKET = -1;
#endif

static std::error_code MakeSocketError(int errc)
{
#ifdef _WIN32
	return std::error_code(errc, std::system_category());
#else
	return std::error_code(errc, std::generic_category());
#endif
}

static std::error_code GetSocketError()
{
#ifdef _WIN32
	return MakeSocketError(WSAGetLastError());
#else
	return MakeSocketError(errno);
#endif
}

#ifdef _WIN32
static const std::error_code SRCON_EWOULDBLOCK = MakeSocketError(WSAEWOULDBLOCK);
static const std::error_code SRCON_EINPROGRESS = MakeSocketError(WSAEINPROGRESS);
#else
static const std::error_code SRCON_EWOULDBLOCK = MakeSocketError(EWOULDBLOCK);
static const std::error_code SRCON_EINPROGRESS = MakeSocketError(EINPROGRESS);
#endif

namespace srcon
{
	using PacketID_t = int32_t;
	using PacketSize_t = int32_t;

	template<typename PacketType>
	struct PacketHeader
	{
		static_assert(std::is_same_v<std::underlying_type_t<PacketType>, int32_t>);
		PacketSize_t m_Size{};
		PacketID_t m_ID{};
		PacketType m_Type{};
	};

	template<typename PacketType>
	struct Packet
	{
		using header_type = srcon::PacketHeader<PacketType>;

		static_assert(std::is_same_v<std::underlying_type_t<PacketType>, int32_t>);
		PacketID_t m_ID{};
		PacketType m_Type{};

		std::string m_Body1;
		std::string m_Body2;

		std::vector<char> pack() const try
		{
			//using PacketHeader = RequestPacketHeader<true>;
			const auto packetSizeActual = sizeof(header_type) + m_Body1.size() + 1 + m_Body2.size() + 1;
			assert(packetSizeActual >= sizeof(header_type));

			std::vector<char> packet(packetSizeActual);
			header_type& header = *reinterpret_cast<header_type*>(packet.data());
			header.m_Size = PacketSize_t(packetSizeActual - sizeof(header_type::m_Size));
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
		catch (const std::exception& e)
		{
			SRCON_STACK_TRACE(e);
			throw;
		}
	};

	using RequestPacket = Packet<RequestPacketType>;
	using ResponsePacket = Packet<ResponsePacketType>;
	using RequestPacketHeader = PacketHeader<RequestPacketType>;
	using ResponsePacketHeader = PacketHeader<ResponsePacketType>;

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
	std::shared_ptr<LogSettings> m_LogSettings;

	SocketData(srcon_addr addr, timeout_t timeout, const std::shared_ptr<LogSettings>& logSettings);
	~SocketData()
	{
		if (m_Socket != INVALID_SOCKET)
			closesocket(m_Socket);
	}

	SOCKET m_Socket = INVALID_SOCKET;

	std::vector<ResponsePacket> send(const std::string_view& data,
		RequestPacketType type = RequestPacketType::SERVERDATA_EXECCOMMAND, bool reliable = true) try
	{
		RequestPacket packetTemp;
		packetTemp.m_Type = type;
		packetTemp.m_ID = m_NextID++;
		try
		{
			packetTemp.m_Body1 = data;
		}
		catch (const std::exception& e)
		{
			SRCON_STACK_TRACE(e);
			throw;
		}

		auto packet = packetTemp.pack();

		if (m_LogSettings->m_IsLoggingTX)
			SRCON_LOG('[' << packetTemp.m_ID << "] Sending: " << std::quoted(data));

		const auto sendResult = ::send(m_Socket, reinterpret_cast<const char*>(packet.data()), int(packet.size()), 0);
		if (sendResult < 0)
		{
			auto error = GetSocketError();
			throw srcon_error(srcon_errc::socket_send_failed, error, __FUNCTION__);
		}
		else if (sendResult != int(packet.size()))
		{
			std::stringstream ss;
			ss << "Sent " << sendResult << " bytes instead of " << packet.size() << " expected.";
			throw srcon_error(srcon_errc::socket_send_failed, {}, ss.str());
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
	catch (const std::exception& e)
	{
		SRCON_STACK_TRACE(e);
		throw;
	}

	PacketSize_t read_packet_len() const try
	{
		char buffer[4]{};
		if (auto result = ::recv(m_Socket, buffer, 4, 0); result != 4)
		{
			std::stringstream ss;
			ss << "actual received size was " << result;
			throw srcon_error(srcon_errc::socket_recv_failed, GetSocketError(), ss.str());
		}

		return byte32_to_int(buffer);
	}
	catch (const std::exception& e)
	{
		SRCON_STACK_TRACE(e);
		throw;
	}

	ResponsePacket read_packet() const try
	{
		ResponsePacket packet;
		const auto len = read_packet_len();

		auto buffer = std::make_unique<char[]>(len);
		int bytes = 0;
		do
		{
			auto recvResult = ::recv(m_Socket, buffer.get() + bytes, len - bytes, 0);
			if (recvResult < 0)
				throw srcon_error(srcon_errc::socket_recv_failed, GetSocketError(), __FUNCTION__);

			bytes += recvResult;

		} while (bytes < len);

		struct PacketHeaderNoSize
		{
			PacketID_t m_ID;
			ResponsePacketType m_Type;
		};

		const auto& header = *reinterpret_cast<const PacketHeaderNoSize*>(buffer.get());

		packet.m_ID = header.m_ID;
		packet.m_Type = header.m_Type;

		if (len < PacketSize_t(sizeof(PacketHeaderNoSize)))
		{
			std::stringstream ss;
			ss << "Reported packet length was " << len;
			throw std::length_error(ss.str());
		}

		auto body = std::string_view(&buffer.get()[sizeof(PacketHeaderNoSize)],
			len - sizeof(PacketHeaderNoSize));

		auto firstNullTerm = body.find('\0');
		packet.m_Body1 = body.substr(0, firstNullTerm);

		auto secondNullTerm = body.rfind('\0');
		packet.m_Body2 = body.substr(firstNullTerm + 1, secondNullTerm - (firstNullTerm + 1));

		if (m_LogSettings->m_IsLoggingRX)
			SRCON_LOG('[' << packet.m_ID << "] Receiving: " << std::quoted(packet.m_Body1) << ", " << std::quoted(packet.m_Body2));

		return packet;
	}
	catch (const std::exception& e)
	{
		SRCON_STACK_TRACE(e);
		throw;
	}

	std::vector<ResponsePacket> recv(PacketID_t halt_id) const try
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
	catch (const std::exception& e)
	{
		SRCON_STACK_TRACE(e);
		throw;
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
		SRCON_LOG("Failed to change socket's non-blocking mode");
		return false;
	}
#else
	auto existing = fcntl(s, F_GETFL, 0);

	if (isNonBlocking)
		existing |= O_NONBLOCK;
	else
		existing &= ~(O_NONBLOCK);

	fcntl(s, F_SETFL, existing);
#endif

	return true;
}

static timeval ToTimeval(srcon::timeout_t dur)
{
	using namespace std::chrono;

	timeval timeoutVal{};
	auto seconds = duration_cast<duration<decltype(timeval::tv_sec)>>(dur);
	timeoutVal.tv_sec = seconds.count();
	timeoutVal.tv_usec = duration_cast<duration<decltype(timeval::tv_usec), std::micro>>(dur - seconds).count();
	return timeoutVal;
}

static void SetSocketTimeout(SOCKET s, srcon::timeout_t time) try
{
#ifdef _WIN32
	using namespace std::chrono;
	DWORD timeoutVal = duration_cast<duration<DWORD, std::milli>>(time).count();
#else
	timeval timeoutVal = ToTimeval(time);
#endif

	if (auto result = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutVal), sizeof(timeoutVal));
		result != 0)
	{
		throw srcon::srcon_error(srcon::srcon_errc::rcon_connect_failed, GetSocketError(), "SO_RCVTIMEO");
	}

	if (auto result = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeoutVal), sizeof(timeoutVal));
		result != 0)
	{
		throw srcon::srcon_error(srcon::srcon_errc::rcon_connect_failed, GetSocketError(), "SO_SNDTIMEO");
	}
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

static void WaitForSocketConnection(SOCKET s, srcon::timeout_t timeout) try
{
	using namespace srcon;

	timeval timeoutVal = ToTimeval(timeout);

	fd_set writeSet;
	FD_ZERO(&writeSet);
	FD_SET(s, &writeSet);
	{
		const auto result = select(int(s + 1), nullptr, &writeSet, nullptr, &timeoutVal);
		if (result == SOCKET_ERROR)
			throw srcon_error(srcon_errc::rcon_connect_failed, GetSocketError(), "WaitForSocketConnection(): select()");
	}

	if (FD_ISSET(s, &writeSet))
		return; // Success

	{
		int error;
		socklen_t errorSize = sizeof(error);
		const auto result = getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &errorSize);
		if (result == SOCKET_ERROR)
			throw srcon_error(srcon_errc::rcon_connect_failed, GetSocketError(), "WaitForSocketConnection(): getsockopt()");

		if (errorSize != sizeof(error))
		{
			std::stringstream ss;
			ss << __FUNCTION__ << "(): After getsockopt(), errorSize == " << errorSize;
			throw std::runtime_error(ss.str());
		}

		throw srcon_error(srcon_errc::rcon_connect_failed, MakeSocketError(error), "WaitForSocketConnection(): socket error");
	}
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

srcon::client::SocketData::SocketData(const srcon_addr addr, const timeout_t timeout, const std::shared_ptr<LogSettings>& logSettings) try
{
	m_LogSettings = logSettings;

	SRCON_LOG("Password length: " << addr.pass.size());
	SRCON_LOG("Connecting to " << addr.addr << ':' << addr.port << " with password " << std::quoted(addr.pass) << "...");

#ifdef _WIN32
	WSADATA wsaData{};
	if (auto result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		result != 0)
	{
		throw srcon_error(srcon_errc::rcon_connect_failed, std::error_code(result, std::system_category()), "WSAStartup()");
	}
#endif

	m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_Socket == INVALID_SOCKET)
		throw srcon_error(srcon_errc::rcon_connect_failed, GetSocketError(), "socket()");

	SRCON_LOG("Socket (" << m_Socket << ") opened, connecting...");
	SetSocketTimeout(m_Socket, timeout);

	SetNonBlocking(m_Socket, true);
	{
		sockaddr_in server{};
		server.sin_family = AF_INET;
		server.sin_addr.s_addr = inet_addr(addr.addr.c_str());
		server.sin_port = htons(addr.port);

		int status = SOCKET_ERROR;
		if ((status = ::connect(m_Socket, (struct sockaddr*)&server, sizeof(server))) == SOCKET_ERROR)
		{
			auto error = GetSocketError();
			const auto msg = error.message();
			if (error != SRCON_EWOULDBLOCK)
				throw srcon_error(srcon_errc::rcon_connect_failed, error, "connect()");
		}
	}
	SetNonBlocking(m_Socket, false);

	WaitForSocketConnection(m_Socket, timeout);

	auto authResponses = send(addr.pass, RequestPacketType::SERVERDATA_AUTH);

	for (auto& response : authResponses)
	{
		if (response.m_Type != ResponsePacketType::SERVERDATA_AUTH_RESPONSE)
			continue;

		if (response.m_ID == -1)
			throw srcon_error(srcon_errc::bad_rcon_password);
	}

	SRCON_LOG("Connection established!");
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

void srcon::client::connect(srcon_addr addr, timeout_t timeout) try
{
	disconnect();

	m_Address = std::move(addr);
	m_Timeout = std::move(timeout);
	m_Socket = SocketDataPtr(new SocketData(m_Address, m_Timeout, m_LogSettings));
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

void srcon::client::connect(std::string address, std::string password, int port, timeout_t timeout)
{
	srcon_addr addr;
	addr.addr = std::move(address);
	addr.pass = std::move(password);
	addr.port = port;
	connect(std::move(addr), timeout);
}

void srcon::client::reconnect() try
{
	if (m_Address.addr.empty() || m_Address.port <= 0)
		throw srcon_error(srcon_errc::no_preexisting_connection, {}, __FUNCTION__);

	disconnect();
	return connect(m_Address, m_Timeout);
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

void srcon::client::disconnect()
{
	m_Socket.reset();
}

std::string srcon::client::send_command(const std::string_view& data) try
{
	if (!is_connected())
		throw srcon_error(srcon_errc::no_preexisting_connection, {}, __FUNCTION__);

	auto responses = m_Socket->send(data);
	if (responses.size() == 1)
		return responses[0].m_Body1;

	std::string retVal;

	for (auto& response : responses)
		retVal += response.m_Body1;

	return retVal;
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

int srcon::client::byte32_to_int(const char* buffer)
{
	return	static_cast<int>(
		static_cast<unsigned char>(buffer[0]) |
		static_cast<unsigned char>(buffer[1]) << 8 |
		static_cast<unsigned char>(buffer[2]) << 16 |
		static_cast<unsigned char>(buffer[3]) << 24);
}

void srcon::client::set_logging(bool txEnabled, bool rxEnabled)
{
	m_LogSettings->m_IsLoggingTX = txEnabled;
	m_LogSettings->m_IsLoggingRX = rxEnabled;
}
