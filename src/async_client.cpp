#include "srcon/async_client.h"
#include "srcon_internal.h"

#include <cassert>
#include <iomanip>
#include <optional>

using namespace srcon;
using namespace std::chrono_literals;

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

async_client::async_client()
{
#ifdef _WIN32
	m_ClientThreadData->m_SpawningThreadLanguage = std::make_unique<ThreadLangData>();
#endif
}

async_client::~async_client()
{
	m_ClientThreadData->m_IsCancelled = true;
	m_ClientThread.detach();
}

srcon_addr async_client::get_addr() const
{
	std::lock_guard lock(m_ClientThreadData->m_AddressMutex);
	return m_ClientThreadData->m_Address;
}

void async_client::set_addr(srcon_addr addr)
{
	std::lock_guard lock(m_ClientThreadData->m_AddressMutex);
	m_ClientThreadData->m_Address = std::move(addr);
}

std::string async_client::ClientThreadData::send_command(const std::string_view& command) try
{
	std::lock_guard lock(m_ClientMutex);

	if (!m_Client.is_connected())
	{
		SRCON_LOG("client not connected, reconnecting for command " << std::quoted(command));
		std::lock_guard lock2(m_AddressMutex);
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

	while (!data->m_IsCancelled)
	{
		{
			std::unique_lock lock(data->m_CommandsMutex);
			data->m_CommandsCV.wait_for(lock, 1s);
		}

		while (!data->m_Commands.empty() && !data->m_IsCancelled)
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
		}
	}
}

async_client::RCONCommand::RCONCommand(std::string cmd, bool reliable) :
	m_Command(std::move(cmd)), m_Reliable(reliable)
{
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
