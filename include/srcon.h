#pragma once

#include <mh/memory/unique_object.hpp>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace srcon
{
	class srcon_error final : public std::runtime_error
	{
	public:
		srcon_error(std::string msg) : std::runtime_error(std::move(msg)) {}
	};

	enum class PacketType
	{
		SERVERDATA_AUTH = 3,
		SERVERDATA_EXECCOMMAND = 2,
		SERVERDATA_AUTH_RESPONSE = 2,
		SERVERDATA_RESPONSE_VALUE = 0,
	};

	using timeout_t = std::chrono::steady_clock::duration;
	static constexpr timeout_t SRCON_DEFAULT_TIMEOUT = std::chrono::seconds(4);
	static constexpr int SRCON_HEADER_SIZE = 14;
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
		unsigned int id = 0;
		bool connected = false;
		timeout_t m_Timeout{};

	public:
		bool connect(srcon_addr addr, timeout_t timeout = SRCON_DEFAULT_TIMEOUT);
		bool connect(std::string address, std::string password, int port = 27015, timeout_t timeout = SRCON_DEFAULT_TIMEOUT);
		bool reconnect();
		void disconnect();
		std::string send(const std::string_view& message, PacketType type = PacketType::SERVERDATA_EXECCOMMAND);

		inline bool is_connected() const { return connected; }
		inline const srcon_addr& get_addr() const { return m_Address; }

	private:
		struct SocketTraits
		{
			void delete_obj(int& socket) const;
			int release_obj(int& socket) const;
			bool is_obj_valid(int socket) const;
		};
		mh::unique_object<int, SocketTraits> m_Socket;

		bool connect(timeout_t timeout = SRCON_DEFAULT_TIMEOUT) const;
		std::string recv(unsigned long) const;
		size_t read_packet_len() const;
		void pack(char packet[], const std::string_view& data, int packet_len, int id, PacketType type) const;
		std::unique_ptr<char[]> read_packet(unsigned int&, bool&) const;
		size_t byte32_to_int(const char*) const;
	};
}
