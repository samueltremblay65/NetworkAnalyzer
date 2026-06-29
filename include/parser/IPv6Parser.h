#pragma once
#include <vector>
#include "model/IPv6Packet.h"

class IPv6Parser
{
public:
    static IPv6Packet parse(const std::vector<uint8_t>& data, size_t offset);
};