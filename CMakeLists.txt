cmake_minimum_required(VERSION 3.20)

project(PacketAnalyzer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# include headers
include_directories(include)

add_executable(PacketAnalyzer
    src/main.cpp
    src/core/PacketAnalyzer.cpp
    src/parser/PcapParser.cpp
    src/parser/IPv4Parser.cpp
    src/parser/IPv6Parser.cpp
    src/parser/EthernetParser.cpp
    src/util/MapUtils.cpp
    src/util/ByteUtils.cpp
)

set_target_properties(PacketAnalyzer PROPERTIES
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)