#include <fstream>
#include <iostream>
#include <vector>

#include "parser/PcapParser.h"
#include "model/EthernetFrame.h"
#include "parser/EthernetParser.h"
#include "parser/IPv4Parser.h"
#include "parser/IPv6Parser.h"
#include "stats/TrafficStats.h"
#include "util/MapUtils.h"


bool PcapParser::open(const std::string& filename)
{
    filePath = filename;
    return true;
}

bool PcapParser::readGlobalHeader()
{
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open())
    {
        std::cerr << "Failed to open file\n";
        return false;
    }

    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (!file)
    {
        std::cerr << "Failed to read PCAP header\n";
        return false;
    }

    std::cout << "PCAP GLOBAL HEADER\n";
    std::cout << "Magic: " << std::hex << header.magicNumber << std::dec << "\n";
    std::cout << "Version: " << header.versionMajor << "." << header.versionMinor << "\n";
    std::cout << "SnapLen: " << header.snaplen << "\n";
    std::cout << "Network: " << header.network << "\n";

    return true;
}

bool PcapParser::readPackets(TrafficStats& trafficStats)
{
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open())
    {
        std::cerr << "Failed to open file\n";
        return false;
    }

    // Skip global header (24 bytes)
    file.seekg(24, std::ios::beg);

    while (file)
    {
        PacketHeader ph;

        file.read(reinterpret_cast<char*>(&ph), sizeof(ph));

        if (!file)
            break;

        std::vector<uint8_t> data(ph.incl_len);
        file.read(reinterpret_cast<char*>(data.data()), ph.incl_len);

        if (!file)
            break;

        trafficStats.totalPackets++;

        EthernetFrame frame = EthernetParser::parse(data);

        // Determine if it is IPv4 or IPv6
        if (frame.etherType == 0x0800)
        {
            IPv4Packet ip = IPv4Parser::parse(data, 14);
            trafficStats.ipv4++;
            // Could move to map to contain all IP protocols
            if(ip.protocol == 6) trafficStats.tcp++;
            else if(ip.protocol == 17)  trafficStats.udp++; 
            else trafficStats.otherIPProtocols++;

            // Add
            if(mapContainsKey(trafficStats.ipCounts, ip.dstIP)) trafficStats.ipCounts[ip.dstIP]++;
            else trafficStats.ipCounts.insert({ip.dstIP, 1});
        }
        else if (frame.etherType == 0x86DD)
        {
            IPv6Packet ip = IPv6Parser::parse(data, 14);
            trafficStats.ipv6++;
            // nextHeader of IPv6 contains  the IP protocol used
            if(ip.nextHeader == 6) trafficStats.tcp++;
            else if(ip.nextHeader == 17)  trafficStats.udp++;
            else trafficStats.otherIPProtocols++;

            if(mapContainsKey(trafficStats.ipCounts, ip.dstIP)) trafficStats.ipCounts[ip.dstIP]++;
            else trafficStats.ipCounts.insert({ip.dstIP, 1});
        }
    }

    return true;
}