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
		int port;
		std::string pass;
	};

	class client final
	{
		const srcon_addr addr;
		unsigned int id;
		bool connected;

	public:
		client(const srcon_addr addr, const timeout_t timeout = SRCON_DEFAULT_TIMEOUT);
		client(const std::string address, const int port, const std::string password,
			const timeout_t timeout = SRCON_DEFAULT_TIMEOUT);

		std::string send(const std::string_view& message, PacketType type = PacketType::SERVERDATA_EXECCOMMAND);

		inline bool get_connected() const
		{
			return connected;
		}

		inline bool is_connected() const
		{
			return get_connected();
		}

		inline srcon_addr get_addr() const
		{
			return addr;
		}

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
