#pragma once
#include <string>
#include <cstdint>

struct IPv6Packet
{
    std::string srcIP;
    std::string dstIP;
    uint8_t nextHeader;
    uint8_t hopLimit;
};