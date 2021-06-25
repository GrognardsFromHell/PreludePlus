
cmake_minimum_required (VERSION 3.8)

project ("PTD")

add_library(PTD "src/dll.cpp")


message(STATUS "CMAKE_SOURCE_DIR: ${CMAKE_SOURCE_DIR}")

target_include_directories(PTD PRIVATE "include/ptd"
	PRIVATE "${CMAKE_SOURCE_DIR}/infrastructure/include"
	PRIVATE "${CMAKE_SOURCE_DIR}/dependencies/minhook/include"
	
	#PRIVATE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/Infrastructure"
	)

target_link_directories(PTD
	PUBLIC "${CMAKE_SOURCE_DIR}/dependencies/lib"
	)

target_link_libraries(PTD 
	Shlwapi.dll dbghelp.lib Psapi.lib 
	Infrastructure minhook
)

install(TARGETS PTD 
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
#set(HEADER_FILES "${INCLUDES}/ptd/dll.h")

# Add source to this project's executable.

