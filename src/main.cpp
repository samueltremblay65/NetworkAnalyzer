#include "core/PacketAnalyzer.h"
#include "stats/TrafficStats.h"
#include "util/MapUtils.h"
#include <iostream>

void printReport(const TrafficStats& trafficStats);

int main()
{
    PacketAnalyzer analyzer;

    analyzer.run("data/2026-02-28-traffic-analysis-exercise.pcap");
    const TrafficStats& trafficStats = analyzer.getTrafficStats();

    printReport(trafficStats);

    return 0;
}

void printReport(const TrafficStats& trafficStats) {
    std::cout << "Total packets: " << trafficStats.totalPackets << "\n";

    std::cout << "\nProtocol breakdown:\n";
    std::cout << "IPv4: " << trafficStats.ipv4 << "\n";
    std::cout << "IPv6: " << trafficStats.ipv6 << "\n";
    std::cout << "TCP: " << trafficStats.tcp << "\n";
    std::cout << "UDP: " << trafficStats.udp << "\n";
    std::cout << "Others: " << trafficStats.otherIPProtocols << "\n";

    std::cout << "Top destination IPs" << "\n";
    std::vector<std::pair<std::string, int>> entries = getTopEntries(trafficStats.ipCounts, 5);

    for(int i = 0; i < entries.size(); i++) {
        std::cout << entries[i].first << ": " << entries[i].second << " Packets" << "\n";
    }
}


