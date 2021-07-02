# CMakeList.txt : CMake project for PreludePlus, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("PreludePlus")

# Add source to this project's executable.
add_executable (PreludePlus 
	"PreludePlus.cpp"
	"util/fixes.cpp" "gfx.cpp" "include/gfx.h" "engine.cpp" "include/engine.h" "include/sound_engine.h" "sound_engine.cpp" "include/input_system.h" "include/meshes.h" "input_system.cpp")


target_include_directories(PreludePlus 
	PRIVATE "${CMAKE_SOURCE_DIR}/infrastructure/include"
	PRIVATE "${CMAKE_SOURCE_DIR}/PTD/include"
	PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include"

	PRIVATE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/PTD"
	PRIVATE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/Infrastructure"
	 )
#target_link_libraries(PreludePlus)

target_link_libraries(PreludePlus Shlwapi.dll dbghelp.lib PTD minhook)

# TODO: Add tests and install targets if needed.
