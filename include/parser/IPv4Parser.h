#pragma once
#include <vector>
#include "model/IPv4Packet.h"

class IPv4Parser
{
public:
    static IPv4Packet parse(const std::vector<uint8_t>& data, size_t offset);
};