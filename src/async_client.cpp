#include "srcon/async_client.h"
#include "srcon_internal.h"

#include <mh/concurrency/locked_value.hpp>

#include <cassert>
#include <condition_variable>
#include <iomanip>
#include <mutex>
#include <optional>
#include <queue>

using namespace srcon;
using namespace std::chrono_literals;

struct async_client::ClientThreadData
{
	std::string send_command(const std::string_view& command);

	client m_Client;
	mutable std::mutex m_ClientMutex;

	std::queue<std::shared_ptr<RCONCommand>> m_Commands;
	mutable std::mutex m_CommandsMutex;
	std::condition_variable m_CommandsCV;

	mh::locked_value<srcon_addr> m_Address;

	std::chrono::steady_clock::duration m_MinDelay = std::chrono::milliseconds(150);

#ifdef _WIN32
	std::unique_ptr<ThreadLangData> m_SpawningThreadLanguage = std::make_unique<ThreadLangData>();
#endif
};

struct async_client::RCONCommand
{
	explicit RCONCommand(std::string cmd, bool reliable);

	bool operator==(const RCONCommand& other) const { return m_Command == other.m_Command; }

	std::string m_Command;
	bool m_Reliable = true;
	std::promise<std::string> m_Promise;
	std::shared_future<std::string> m_Future{ m_Promise.get_future().share() };
};

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
struct async_client::ThreadLangData
{
	ThreadLangData()
	{
		m_LangID = GetThreadUILanguage();
	}

	void Apply() const
	{
		if (auto result = SetThreadUILanguage(m_LangID); result != m_LangID)
			SRCON_LOG("Failed to propagate thread LANGID " << m_LangID << " to child thread");
	}

	LANGID m_LangID;
};
#endif

async_client::async_client() :
	m_ClientThreadData(std::make_shared<ClientThreadData>()),
	m_ClientThread(&ClientThreadFunc, m_ClientThreadData)
{
}

async_client::~async_client()
{
	m_ClientThread.detach();
}

srcon_addr async_client::get_addr() const
{
	return m_ClientThreadData->m_Address;
}

void async_client::set_addr(srcon_addr addr)
{
	m_ClientThreadData->m_Address = std::move(addr);
}

std::string async_client::ClientThreadData::send_command(const std::string_view& command) try
{
	std::lock_guard lock(m_ClientMutex);

	if (!m_Client.is_connected())
	{
		SRCON_LOG("client not connected, reconnecting for command " << std::quoted(command));
		m_Client.connect(m_Address);
	}

	return m_Client.send_command(command);
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

std::string async_client::send_command(const std::string_view& command) try
{
	return m_ClientThreadData->send_command(command);
}
catch (const std::exception& e)
{
	SRCON_STACK_TRACE(e);
	throw;
}

std::shared_future<std::string> async_client::send_command_async(std::string command, bool reliable)
{
	std::lock_guard lock(m_ClientThreadData->m_CommandsMutex);
	auto retVal = m_ClientThreadData->m_Commands.emplace(std::make_shared<RCONCommand>(std::move(command), reliable))->m_Future;
	m_ClientThreadData->m_CommandsCV.notify_one();
	return retVal;
}

void async_client::ClientThreadFunc(std::shared_ptr<ClientThreadData> data)
{
#ifdef _WIN32
	data->m_SpawningThreadLanguage->Apply();
#endif

	while (data.use_count() > 1)
	{
		{
			std::unique_lock lock(data->m_CommandsMutex);
			data->m_CommandsCV.wait_for(lock, 1s);
		}

		while (!data->m_Commands.empty() && data.use_count() > 1)
		{
			std::shared_ptr<RCONCommand> cmd;
			{
				std::lock_guard lock(data->m_CommandsMutex);
				if (data->m_Commands.empty())
					break;

				cmd = data->m_Commands.front();
				if (!cmd->m_Reliable)
					data->m_Commands.pop();
			}

			try
			{
				if (cmd->m_Command.size() > 4096)
					SRCON_LOG("Sending a command that is " << cmd->m_Command.size() << " chars long, was this really intended?");

				auto resultStr = data->send_command(cmd->m_Command);
				//DebugLog("Setting promise for "s << std::quoted(cmd->m_Command) << " to " << std::quoted(resultStr));
				cmd->m_Promise.set_value(resultStr);

				if (cmd->m_Reliable)
				{
					std::lock_guard lock(data->m_CommandsMutex);
					assert(!data->m_Commands.empty());
					if (!data->m_Commands.empty())
					{
						assert(data->m_Commands.front() == cmd);
						data->m_Commands.pop();
					}
				}
			}
			catch (const std::exception& e)
			{
				SRCON_LOG("Unhandled exception: " << e.what() << ", disconnecting");
				if (!cmd->m_Reliable)
					cmd->m_Promise.set_exception(std::current_exception());

				{
					std::lock_guard lock(data->m_ClientMutex);
					data->m_Client.disconnect();
				}

				std::this_thread::sleep_for(1s);
			}

			std::this_thread::sleep_for(data->m_MinDelay);
		}
	}
}

async_client::RCONCommand::RCONCommand(std::string cmd, bool reliable) :
	m_Command(std::move(cmd)), m_Reliable(reliable)
{
}

void async_client::set_logging(bool enabled)
{
	set_logging(enabled, enabled);
}

void async_client::set_logging(bool txEnabled, bool rxEnabled)
{
	m_ClientThreadData->m_Client.set_logging(txEnabled, rxEnabled);
}

bool async_client::is_logging_tx() const
{
	return m_ClientThreadData->m_Client.is_logging_tx();
}

bool async_client::is_logging_rx() const
{
	return m_ClientThreadData->m_Client.is_logging_rx();
}

void async_client::set_min_delay(const std::chrono::steady_clock::duration& duration)
{
	m_ClientThreadData->m_MinDelay = duration;
}

std::chrono::steady_clock::duration async_client::get_min_delay() const
{
	return m_ClientThreadData->m_MinDelay;
}
