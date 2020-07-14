#pragma once

#include <chrono>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>

namespace srcon
{
	enum class RequestPacketType : int32_t
	{
		SERVERDATA_REQUESTVALUE = 0,
		SERVERDATA_SETVALUE = 1,
		SERVERDATA_EXECCOMMAND = 2,
		SERVERDATA_AUTH = 3,
		SERVERDATA_VPROF = 4,
		SERVERDATA_REMOVE_VPROF = 5,
		SERVERDATA_TAKE_SCREENSHOT = 6,
		SERVERDATA_SEND_CONSOLE_LOG = 7,
	};

	enum class ResponsePacketType : int32_t
	{
		SERVERDATA_RESPONSE_VALUE = 0,
		SERVERDATA_UPDATE = 1,
		SERVERDATA_AUTH_RESPONSE = 2,
		SERVERDATA_VPROF_DATA = 3,
		SERVERDATA_VPROF_GROUPS = 4,
		SERVERDATA_SCREENSHOT_RESPONSE = 5,
		SERVERDATA_CONSOLE_LOG_RESPONSE = 6,
		SERVERDATA_RESPONSE_STRING = 7,
	};

	using timeout_t = std::chrono::steady_clock::duration;
	static constexpr timeout_t SRCON_DEFAULT_TIMEOUT = std::chrono::seconds(4);
	static constexpr int SRCON_SLEEP_THRESHOLD = 1024;
	static constexpr int SRCON_SLEEP_MILLISECONDS = 500;

	using LogFunc_t = void(*)(std::string&& msg);
	void SetLogFunc(LogFunc_t func);

	struct srcon_addr
	{
		std::string addr;
		std::string pass;
		int port = -1;
	};

	class client final
	{
		srcon_addr m_Address;
		timeout_t m_Timeout{};

	public:
		~client();

		void connect(srcon_addr addr, timeout_t timeout = SRCON_DEFAULT_TIMEOUT);
		void connect(std::string address, std::string password, int port = 27015, timeout_t timeout = SRCON_DEFAULT_TIMEOUT);
		void reconnect();
		void disconnect();
		std::string send_command(const std::string_view& message);

		bool is_connected() const { return !!m_Socket; }
		const srcon_addr& get_addr() const { return m_Address; }

		void set_logging(bool txEnabled, bool rxEnabled);
		bool is_logging_tx() const { return m_LogSettings->m_IsLoggingTX; }
		bool is_logging_rx() const { return m_LogSettings->m_IsLoggingRX; }

	private:
		struct SocketData;
		struct SocketDataDeleter
		{
			void operator()(SocketData* data) const;
		};

		using SocketDataPtr = std::unique_ptr<SocketData, SocketDataDeleter>;
		SocketDataPtr m_Socket;

		struct LogSettings
		{
			bool m_IsLoggingTX = false;
			bool m_IsLoggingRX = false;
		};
		std::shared_ptr<LogSettings> m_LogSettings = std::make_shared<LogSettings>();

		static int byte32_to_int(const char*);
	};
}

template<typename CharT, typename Traits>
std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const srcon::RequestPacketType& type)
{
#undef OS_CASE
#define OS_CASE(v) case v : return os << #v
	switch (type)
	{
		OS_CASE(srcon::RequestPacketType::SERVERDATA_REQUESTVALUE);
		OS_CASE(srcon::RequestPacketType::SERVERDATA_SETVALUE);
		OS_CASE(srcon::RequestPacketType::SERVERDATA_EXECCOMMAND);
		OS_CASE(srcon::RequestPacketType::SERVERDATA_AUTH);
		OS_CASE(srcon::RequestPacketType::SERVERDATA_VPROF);
		OS_CASE(srcon::RequestPacketType::SERVERDATA_REMOVE_VPROF);
		OS_CASE(srcon::RequestPacketType::SERVERDATA_TAKE_SCREENSHOT);
		OS_CASE(srcon::RequestPacketType::SERVERDATA_SEND_CONSOLE_LOG);

	default:
		return os << "srcon::RequestPacketType(" << +std::underlying_type_t<srcon::RequestPacketType>(type) << ')';
	}
#undef OS_CASE
}

template<typename CharT, typename Traits>
std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const srcon::ResponsePacketType& type)
{
#undef OS_CASE
#define OS_CASE(v) case v : return os << #v
	switch (type)
	{
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_RESPONSE_VALUE);
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_UPDATE);
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_AUTH_RESPONSE);
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_VPROF_DATA);
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_VPROF_GROUPS);
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_SCREENSHOT_RESPONSE);
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_CONSOLE_LOG_RESPONSE);
		OS_CASE(srcon::ResponsePacketType::SERVERDATA_RESPONSE_STRING);

	default:
		return os << "srcon::ResponsePacketType(" << +std::underlying_type_t<srcon::ResponsePacketType>(type) << ')';
	}
#undef OS_CASE
}
