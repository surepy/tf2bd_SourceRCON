cmake_minimum_required(VERSION 3.10)

project(source-rcon
	VERSION 1.0
	DESCRIPTION "C++ Source RCON implementation "
	HOMEPAGE_URL "https://github.com/PazerOP/SourceRCON"
)

add_library(${PROJECT_NAME} STATIC
	"include/srcon/client.h"
	"src/client.cpp"
	"include/srcon/async_client.h"
	"src/async_client.cpp"
	"src/srcon_internal.h"
	"include/srcon/srcon.h"
	"src/srcon.cpp"
)

target_include_directories(${PROJECT_NAME}
	PUBLIC
		"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
		"$<INSTALL_INTERFACE:include>"
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

find_package(mh-stuff CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME}
	PRIVATE
		mh::mh-stuff
)

if (WIN32)
	target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()

option(SourceRCON_WARNINGS_AS_ERRORS "Treat compile warnings as errors." off)
if (SourceRCON_WARNINGS_AS_ERRORS)
	if (MSVC)
		target_compile_options(${PROJECT_NAME} PRIVATE /WX)
	else()
		target_compile_options(${PROJECT_NAME} PRIVATE -Werror)
	endif()
endif()

find_package(mh-cmake-common CONFIG REQUIRED)
mh_basic_install(
	PROJ_INCLUDE_DIRS
		"include/"
)
