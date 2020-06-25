#pragma once

#include <memory>
#include <string>
#include <string_view>

namespace srcon
{
	static constexpr int SERVERDATA_AUTH = 3;
	static constexpr int SERVERDATA_EXECCOMMAND = 2;
	static constexpr int SERVERDATA_AUTH_RESPONSE = 2;
	static constexpr int SERVERDATA_RESPONSE_VALUE = 0;

	static constexpr int SRCON_DEFAULT_TIMEOUT = 4;
	static constexpr int SRCON_HEADER_SIZE = 14;
	static constexpr int SRCON_SLEEP_THRESHOLD = 1024;
	static constexpr int SRCON_SLEEP_MILLISECONDS = 500;

	struct srcon_addr
	{
		std::string addr;
		int port;
		std::string pass;
	};

	class client
	{
		const srcon_addr addr;
		const int sockfd;
		unsigned int id;
		bool connected;

	public:
		client(const srcon_addr addr, const int timeout = SRCON_DEFAULT_TIMEOUT);
		client(const std::string address, const int port, const std::string password, const int timeout = SRCON_DEFAULT_TIMEOUT);
		virtual ~client();

		std::string send(const std::string_view& message, int type = SERVERDATA_EXECCOMMAND);

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
		bool connect(int timeout = SRCON_DEFAULT_TIMEOUT) const;
		std::string recv(unsigned long) const;
		size_t read_packet_len() const;
		void pack(char packet[], const std::string_view& data, int packet_len, int id, int type) const;
		std::unique_ptr<char[]> read_packet(unsigned int&, bool&) const;
		size_t byte32_to_int(const char*) const;
	};
}
