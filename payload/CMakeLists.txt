cmake_minimum_required(VERSION 3.20) # CMake 3.20 or higher for C++23 support
project(Parasyte-Payload VERSION 1.0 DESCRIPTION "A simple C++23 project")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # Generate compile_commands.json for clangd
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wpedantic -Wconversion")

# Find Boost, specifying the components you need
find_package(Boost 1.83.0 REQUIRED COMPONENTS filesystem system)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -g")
endif()

# List of all source files
set(SOURCE_FILES
    src/main.cpp
    src/controller/Controller.cpp
    src/encryption/Encryptor.cpp
    src/network/Connection.cpp
)

# Add executable based on source files
add_executable(Parasyte-Payload ${SOURCE_FILES})

# Include directories for the Parasyte-Payload target
target_include_directories(Parasyte-Payload PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Link Boost and OpenSSL libraries with the Parasyte-Payload executable
target_link_libraries(Parasyte-Payload PRIVATE
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)
