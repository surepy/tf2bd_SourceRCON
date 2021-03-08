#pragma once

#include "client.h"

#include <future>
#include <memory>
#include <string_view>

namespace srcon
{
	class async_client
	{
	public:
		async_client();
		~async_client();

		async_client(const async_client&) = delete;
		async_client& operator=(const async_client&) = delete;

		srcon_addr get_addr() const;
		void set_addr(srcon_addr addr);

		std::string send_command(const std::string_view& command);
		std::shared_future<std::string> send_command_async(std::string command, bool reliable = true);

		void set_logging(bool enabled);
		void set_logging(bool txEnabled, bool rxEnabled);
		bool is_logging_tx() const;
		bool is_logging_rx() const;

		// Minimum delay between issuing commands to server.
		void set_min_delay(const std::chrono::steady_clock::duration& duration);
		std::chrono::steady_clock::duration get_min_delay() const;

	private:
		struct RCONCommand;
		struct ClientThreadData;

#ifdef _WIN32
		struct ThreadLangData;
#endif

		std::shared_ptr<ClientThreadData> m_ClientThreadData;
		std::thread m_ClientThread;

		static void ClientThreadFunc(std::shared_ptr<ClientThreadData> data);
	};
}
