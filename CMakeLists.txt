cmake_minimum_required(VERSION 3.20) # CMake 3.20 or higher for C++23 support

project(Parasyte VERSION 1.0 DESCRIPTION "A simple C++23 project")


set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(${PROJECT_SOURCE_DIR}/src/network)

# Find Boost, specifying the components you need
find_package(Boost 1.83.0 REQUIRED COMPONENTS filesystem system)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    # For executables
    add_executable(Parasyte src/main.cpp)
    # For linking Boost libraries with the executable
    target_link_libraries(Parasyte ${Boost_LIBRARIES})
endif()
