cmake_minimum_required(VERSION 3.10)

project(SourceRCON)

add_library(SourceRCON STATIC
	"include/srcon/client.h"
	"src/client.cpp"
	"include/srcon/async_client.h"
	"src/async_client.cpp"
	"src/srcon_internal.h"
	"include/srcon/srcon.h"
	"src/srcon.cpp"
)

target_include_directories(SourceRCON PUBLIC "include")

target_compile_features(SourceRCON PUBLIC cxx_std_17)

if (NOT TARGET mh::stuff)
	find_package(mh-stuff CONFIG REQUIRED)
endif()

target_link_libraries(SourceRCON
	PRIVATE
		mh::stuff
)

if (WIN32)
	target_link_libraries(SourceRCON PRIVATE ws2_32)
endif()

option(SourceRCON_WARNINGS_AS_ERRORS "Treat compile warnings as errors." off)
if (SourceRCON_WARNINGS_AS_ERRORS)
	if (MSVC)
		target_compile_options(SourceRCON PRIVATE /WX)
	else()
		target_compile_options(SourceRCON PRIVATE -Werror)
	endif()
endif()
