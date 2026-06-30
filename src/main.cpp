#include <iostream>

#include "core/PacketAnalyzer.h"
#include "stats/TrafficStats.h"
#include "util/MapUtils.h"


void printReport(const TrafficStats& trafficStats);

int main()
{
    PacketAnalyzer analyzer;

    // From file
    analyzer.run("data/2026-02-28-traffic-analysis-exercise.pcap");

    // Live
    // analyzer.runLive(100);
    
    printReport(analyzer.getTrafficStats());

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

    std::cout << "\nTop Destination IPs\n";
    std::vector<std::pair<std::string, int>> topIPs = getTopEntries(trafficStats.ipCounts, 5);
    if (topIPs.empty())
    {
        std::cout << "No IPs recorded\n";
    }
    else
    {
        for (const auto& entry : topIPs)
        {
            std::cout << entry.first << ": " << entry.second << " packets\n";
        }
    }

    std::cout << "\nTop TCP Ports\n";

    std::vector<std::pair<int, int>> tcpPortCounts = getTopEntries(trafficStats.tcpPortCounts, 5);

    if (tcpPortCounts.empty())
    {
        std::cout << "No UDP ports recorded\n";
    }
    else
    {
        for (const auto& entry : tcpPortCounts)
        {
            std::cout << entry.first << ": " << entry.second << " packets\n";
        }
    }

    std::cout << "\nTop UDP Ports\n";
    std::vector<std::pair<int, int>> udpPortCounts = getTopEntries(trafficStats.udpPortCounts, 5);
    if (udpPortCounts.empty())
    {
        std::cout << "No UDP ports recorded\n";
    }
    else
    {
        for (const auto& entry : udpPortCounts)
        {
            std::cout << entry.first << ": " << entry.second << " packets\n";
        }
    }

    std::cout << "\nTop DNS Queries\n";

    std::vector<std::pair<std::string, int>> topQueries = getTopEntries(trafficStats.dnsQueries, 10);
    if (topQueries.empty())
    {
        std::cout << "No DNS queries detected\n";
    }
    else {
        for (const auto& query : topQueries)
        {
            std::cout << query.first << ": "
                    << query.second
                    << " queries\n";
        }
    }

}
