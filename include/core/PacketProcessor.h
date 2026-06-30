#pragma once

#include <cstdint>
#include <cstddef>

#include "stats/TrafficStats.h"

class PacketProcessor
{
public:
    void processPacket(const uint8_t* data,
                       size_t length,
                       TrafficStats& stats);
};