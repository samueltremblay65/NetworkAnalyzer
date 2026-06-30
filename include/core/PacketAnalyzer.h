#pragma once
#include <string>

#include "stats/TrafficStats.h"

class PacketAnalyzer
{
    public:
        void run(const std::string& file);
        void runLive(int packets);

        const TrafficStats& getTrafficStats();
};