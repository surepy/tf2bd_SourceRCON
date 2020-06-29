cmake_minimum_required(VERSION 3.10)

project(SourceRCON)

add_library(SourceRCON
	"include/srcon/client.h"
	"src/client.cpp"
	"include/srcon/async_client.h"
	"src/async_client.cpp"
	"src/srcon_internal.h"
	"include/srcon/srcon.h"
	"src/srcon.cpp"
)

set_property(TARGET SourceRCON PROPERTY CXX_STANDARD 17)

target_include_directories(SourceRCON PUBLIC include)

option(SourceRCON_WARNINGS_AS_ERRORS "Treat compile warnings as errors." off)
if (SourceRCON_WARNINGS_AS_ERRORS)
	if (MSVC)
		target_compile_options(SourceRCON PRIVATE /WX)
	else()
		target_compile_options(SourceRCON PRIVATE -Werror)
	endif()
endif()
