# CMakeList.txt : CMake project for PreludePlus, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("PreludePlus")

# Add source to this project's executable.
add_executable (PreludePlus 
	"PreludePlus.cpp"
	"util/fixes.cpp")

target_include_directories(PreludePlus 
	PRIVATE "${CMAKE_SOURCE_DIR}/PTD/include"
	PRIVATE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/PTD"
	PRIVATE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/Infrastructure"
	 )
#target_link_libraries(PreludePlus)

TARGET_LINK_LIBRARIES(PreludePlus Shlwapi.dll dbghelp.lib PTD)

# TODO: Add tests and install targets if needed.
