#pragma once

#include "srcon/srcon.h"

#include <sstream>

namespace srcon
{
#define SRCON_LOG_INTERNAL(msg) \
	do \
	{ \
		std::stringstream ss; \
		ss << msg; \
		srcon::GetLogFunc()(ss.str()); \
	} while (0)

#define SRCON_LOG(msg) SRCON_LOG_INTERNAL(__func__ << "(): " << msg)

#define SRCON_STACK_TRACE(exception) \
	SRCON_LOG_INTERNAL(typeid(exception).name() << " @ " << __FILE__ << ':' << __LINE__ << " in " << __func__ << "(): " << exception.what())

	LogFunc_t GetLogFunc();
}
