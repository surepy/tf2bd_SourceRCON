#pragma once

#include "srcon/srcon.h"

#include <sstream>

namespace srcon
{
#define LOG(msg) \
	do \
	{ \
		std::stringstream ss; \
		ss << msg; \
		srcon::GetLogFunc()(ss.str()); \
	} while (0)

	LogFunc_t GetLogFunc();
}
