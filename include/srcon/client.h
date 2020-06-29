#pragma once

#include <chrono>
#include <memory>
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

	private:
		struct SocketData;
		struct SocketDataDeleter
		{
			void operator()(SocketData* data) const;
		};

		using SocketDataPtr = std::unique_ptr<SocketData, SocketDataDeleter>;

		static SocketDataPtr ConnectImpl(const srcon_addr& addr, const timeout_t& timeout);
		SocketDataPtr m_Socket;

		static int byte32_to_int(const char*);
	};
}
