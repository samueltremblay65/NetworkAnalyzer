#pragma once
#include <string>
#include <cstdint>

struct EthernetFrame
{
    std::string destMac;
    std::string srcMac;
    uint16_t etherType;
};