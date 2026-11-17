cmake_minimum_required(VERSION 3.16)
project(psi_he CXX)
set(CMAKE_CXX_STANDARD 17)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenFHE 1.6 REQUIRED CONFIG)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(OpenMP REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")
include_directories(${OpenFHE_INCLUDE} ${OpenFHE_INCLUDE}/third-party/include ${OpenFHE_INCLUDE}/core
                    ${OpenFHE_INCLUDE}/pke ${OpenFHE_INCLUDE}/binfhe ${OpenFHE_INCLUDE}/cereal src)
link_directories(${OpenFHE_LIBDIR})

add_library(psi STATIC src/oprf.cpp src/hashing.cpp src/he.cpp src/protocol.cpp)
target_link_libraries(psi PUBLIC ${OpenFHE_SHARED_LIBRARIES} PkgConfig::SODIUM OpenMP::OpenMP_CXX)

add_executable(psi_bench apps/psi_bench.cpp)
target_link_libraries(psi_bench psi)
add_executable(psi_demo apps/psi_demo.cpp)
target_link_libraries(psi_demo psi)
add_executable(psi_tests tests/psi_tests.cpp)
target_link_libraries(psi_tests psi)
