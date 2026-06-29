#include "core/PacketAnalyzer.h"
#include "parser/PcapParser.h"
#include "stats/TrafficStats.h"
#include <iostream>

TrafficStats trafficStats;

void PacketAnalyzer::run(const std::string& file)
{
    PcapParser parser;

    parser.open(file);

    if (!parser.readGlobalHeader())
    {
        std::cerr << "Failed to read PCAP header\n";
        return;
    }

    parser.readPackets(trafficStats);
}

const TrafficStats &PacketAnalyzer::getTrafficStats()
{
    return trafficStats;
}