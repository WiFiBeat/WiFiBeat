cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(WiFiBeat
        VERSION 0.1
        DESCRIPTION "Store 802.11 frames in Elasticsearch. Visualize with Kibana"
        HOMEPAGE_URL "https://wifibeat.org/"
        LANGUAGES CXX)

include(GNUInstallDirs)

configure_file(version.h.in version.h)

# C++11 would be good if we didn't need [[fallthrough]]
# If C++11 is necessary, add -Wimplicit-fallthrough=0 to add_compile_options below
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Release mode for now
set(NBDEBUG 1)

## Force clang for now
set(CMAKE_CXX_COMPILER clang++)

file(GLOB source_files CONFIGURE_DEPENDS
            "config/*.cpp"
            "config/*.h"
            "threads/*.cpp"
            "threads/*.h"
            "utils/*.cpp"
            "utils/*.h"
            "*.h"
            "*.cpp"
        )

add_compile_options(-Wall -Wextra -O3 -DNDEBUG)

add_executable(wifibeat ${source_files})

# Link libraries statically
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -static")

find_package(libtins REQUIRED)
target_link_libraries(wifibeat libtins::libtins)

find_package(RapidJSON REQUIRED)
target_link_libraries(wifibeat rapidjson)

find_package(yaml-cpp REQUIRED)
target_link_libraries(wifibeat yaml-cpp::yaml-cpp)

find_package(libpcap REQUIRED)
target_link_libraries(wifibeat libpcap::libpcap)

find_package(Boost REQUIRED)
target_link_libraries(wifibeat -static -lboost_system)
target_link_libraries(wifibeat -static -lboost_program_options)

target_link_libraries(wifibeat -static -lpthread)

find_package(libnl REQUIRED)
target_link_libraries(wifibeat libnl::libnl)

find_package(Poco REQUIRED)
target_link_libraries(wifibeat Poco::Poco)

target_include_directories(wifibeat
        PUBLIC
        . .. ${CMAKE_CURRENT_BINARY_DIR})
