#include "srcon/async_client.h"
#include "srcon_internal.h"

#include <cassert>
#include <iomanip>
#include <optional>

using namespace srcon;
using namespace std::chrono_literals;

async_client::async_client()
{
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
		LOG("client not connected, reconnecting for command " << std::quoted(command));
		std::lock_guard lock2(m_AddressMutex);
		m_Client.connect(m_Address);
	}

	return m_Client.send_command(command);
}
catch (const std::exception& e)
{
	LOG(__FUNCTION__ << "(): " << e.what());
	throw;
}

std::string async_client::send_command(const std::string_view& command)
{
	return m_ClientThreadData->send_command(command);
}

std::shared_future<std::string> async_client::send_command_async(std::string command, bool reliable)
{
	std::lock_guard lock(m_ClientThreadData->m_CommandsMutex);
	return m_ClientThreadData->m_Commands.emplace(std::move(command), reliable).m_Future;
}

void async_client::ClientThreadFunc(std::shared_ptr<ClientThreadData> data)
{
	while (!data->m_IsCancelled)
	{
		std::this_thread::sleep_for(250ms);

		while (!data->m_Commands.empty() && !data->m_IsCancelled)
		{
			std::optional<RCONCommand> cmd;
			{
				std::lock_guard lock(data->m_CommandsMutex);
				if (data->m_Commands.empty())
					break;

				auto& front = data->m_Commands.front();
				if (!front.m_Reliable)
				{
					cmd = std::move(front);
					data->m_Commands.pop();
				}
				else
				{
					cmd = front;
				}
			}

			try
			{
				auto resultStr = data->send_command(cmd->m_Command);
				//DebugLog("Setting promise for "s << std::quoted(cmd->m_Command) << " to " << std::quoted(resultStr));
				cmd->m_Promise->set_value(resultStr);

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
				LOG(__FUNCTION__ << "(): Unhandled exception: " << e.what());
				if (!cmd->m_Reliable)
					cmd->m_Promise->set_exception(std::current_exception());

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
