cmake_minimum_required(VERSION 3.20) # CMake 3.20 or higher for C++23 support
project(Parasyte VERSION 1.0 DESCRIPTION "A simple C++23 project")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Boost, specifying the components you need
find_package(Boost 1.83.0 REQUIRED COMPONENTS filesystem system)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

# List of all source files
set(SOURCE_FILES
    src/main.cpp
    src/controller/Parasyte.cpp
    src/exploits/ExploitBase.cpp
    src/network/NetScanner.cpp
    src/network/NetUtils.cpp
    src/payload/PayloadBase.cpp
    src/utils/Logger.cpp
)

# Add executable based on source files
add_executable(Parasyte ${SOURCE_FILES})

# Include directories for the Parasyte target
target_include_directories(Parasyte PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
)

# Link Boost libraries with the Parasyte executable
target_link_libraries(Parasyte PRIVATE
    ${Boost_LIBRARIES}
)
