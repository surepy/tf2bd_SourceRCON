project(SourceRCON)

add_library(SourceRCON
	"src/srcon.cpp"
)

set_property(TARGET SourceRCON PROPERTY CXX_STANDARD 17)

target_include_directories(SourceRCON PUBLIC include)
