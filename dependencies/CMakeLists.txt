cmake_minimum_required (VERSION 3.8)

project ("dependencies")

install(TARGETS dependencies 
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
