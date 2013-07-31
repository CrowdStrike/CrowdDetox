cmake_minimum_required(VERSION 2.8)
project(CrowdDetox)

cmake_policy(SET CMP0015 NEW)

set(CMAKE_BUILD_TYPE Release)

if (WIN32)

    add_definitions(-D__NT__=1
                    -DUNICODE
                    -DWIN32
                    -D__IDP__)

    find_library(IDA_LIB
                 NAMES "ida"
                 PATHS "${IDA_SDK}/lib/x86_win_vc_32")

    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zi")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Zi")

elseif (APPLE)

    add_definitions(-D__MAC__=1)

    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32 -Wno-deprecated-writable-strings")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -Wno-deprecated-writable-strings")

    find_library (IDA_LIB
                  NAMES "ida"
                  PATHS "${IDA_DIR}")

elseif (UNIX)

    add_definitions(-D__LINUX__=1)
	
    set (CMAKE_CXX_FLAGS "-m32 -std=c++0x -pipe -O2")

    set (CMAKE_FIND_LIBRARY_SUFFIXES ".a;.so")

endif ( )

set (SOURCES
     CrowdDetox.cpp)

include_directories(${IDA_SDK}/include
                    ${IDA_DIR}/plugins/hexrays_sdk/include)

message (STATUS "IDA_DIR: " ${IDA_DIR})
message (STATUS "IDA_SDK: " ${IDA_SDK})
message (STATUS "IDA_LIB: " ${IDA_LIB})

add_library(CrowdDetox MODULE ${SOURCES})

if (WIN32)
    set (IDA_SUFFIX ".plw")
elseif (APPLE)
    set (IDA_SUFFIX ".pmc")
elseif (UNIX)
    set (IDA_SUFFIX ".plx")
endif ()

set_target_properties (CrowdDetox
                       PROPERTIES
                       PREFIX "hexrays_"
                       SUFFIX ${IDA_SUFFIX}
                       OUTPUT_NAME CrowdDetox)
                       
target_link_libraries (CrowdDetox ${IDA_LIB})
