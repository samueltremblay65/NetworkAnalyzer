#pragma once
#include <string>
#include <cstdint>

struct IPv4Packet
{
    std::string srcIP;
    std::string dstIP;
    uint8_t protocol;   // TCP = 6, UDP = 17
    uint8_t ttl;
};