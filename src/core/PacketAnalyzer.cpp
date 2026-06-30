#include "core/PacketAnalyzer.h"
#include "parser/PcapParser.h"
#include "stats/TrafficStats.h"
#include "core/PacketProcessor.h"
#include "capture/LiveCapture.h"
#include <iostream>

TrafficStats trafficStats;

void PacketAnalyzer::run(const std::string& file)
{
    PcapParser parser;
    PacketProcessor processor;
    TrafficStats stats;

    parser.open(file);

    if (!parser.readGlobalHeader())
    {
        std::cerr << "Failed to read PCAP header\n";
        return;
    }

    parser.readPackets(processor, stats);

    trafficStats = stats; // store result in class member
}

void PacketAnalyzer::runLive(int packetLimit) {
    PacketProcessor processor;
    LiveCapture capture;

    capture.start(processor, trafficStats, packetLimit);
}

const TrafficStats &PacketAnalyzer::getTrafficStats()
{
    return trafficStats;
}