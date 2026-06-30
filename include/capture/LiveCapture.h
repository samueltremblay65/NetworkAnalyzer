#pragma once

#include <pcap.h>
#include "stats/TrafficStats.h"
#include "core/PacketProcessor.h"

class LiveCapture
{
public:
    bool start(PacketProcessor& processor, TrafficStats& stats, int packetLimit);
};