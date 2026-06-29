#pragma once
#include <string>
#include <cstdint>
#include <unordered_map>


struct TrafficStats
{
    int totalPackets = 0;

    std::unordered_map<std::string, int> ipCounts;
    std::unordered_map<int, int> portCounts;

    int ipv4 = 0;
    int ipv6 = 0;
    int tcp = 0;
    int udp = 0;
    int otherIPProtocols = 0;
};