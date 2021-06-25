# CMakeList.txt : Top-level CMake project file, do global configuration
cmake_minimum_required (VERSION 3.8)

project ("PreludePlus")


# Include sub-projects.
add_subdirectory ("PreludePlus")
add_subdirectory ("PTD")
add_subdirectory ("Infrastructure")
#add_subdirectory ("dependencies")