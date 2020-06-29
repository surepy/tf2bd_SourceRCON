cmake_minimum_required(VERSION 3.17)

project(SourceRCON)

include(FetchContent)

FetchContent_Declare(
	mh_stuff
	GIT_REPOSITORY https://github.com/PazerOP/stuff.git
)
if (NOT mh_stuff_POPULATED)
	FetchContent_MakeAvailable(mh_stuff)
endif()

add_library(SourceRCON
	"include/srcon/client.h"
	"src/client.cpp"
	"include/srcon/async_client.h"
	"src/async_client.cpp"
	"src/srcon_internal.h"
	"include/srcon/srcon.h"
	"src/srcon.cpp"
)

target_link_libraries(SourceRCON PRIVATE mh_stuff)

set_property(TARGET SourceRCON PROPERTY CXX_STANDARD 17)

target_include_directories(SourceRCON PUBLIC include)
