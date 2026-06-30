#include "core/PacketProcessor.h"

#include "parser/EthernetParser.h"
#include "parser/IPv4Parser.h"
#include "parser/IPv6Parser.h"
#include "util/MapUtils.h"

#include <cstdint>

void PacketProcessor::processPacket(const uint8_t* data,
                                    size_t length,
                                    TrafficStats& trafficStats)
{
    if (length < 14)
        return; // invalid Ethernet frame

    trafficStats.totalPackets++;

    EthernetFrame frame = EthernetParser::parse(data);

    const uint8_t* ipData = data + 14;
    size_t ipLength = length - 14;

    // IPv4
    if (frame.etherType == 0x0800)
    {
        if (ipLength < 20)
            return;

        IPv4Packet ip = IPv4Parser::parse(data + 14, length - 14);

        trafficStats.ipv4++;

        if (ip.protocol == 6)
            trafficStats.tcp++;
        else if (ip.protocol == 17)
            trafficStats.udp++;
        else
            trafficStats.otherIPProtocols++;

        trafficStats.ipCounts[ip.dstIP]++;
    }

    // IPv6
    else if (frame.etherType == 0x86DD)
    {
        // IPv6 header is immediately after Ethernet header (14 bytes)
        const uint8_t* ipv6Data = data + 14;
        size_t ipv6Length = length - 14;

        if (ipv6Length < 40) // minimum IPv6 header size
            return;

        IPv6Packet ip = IPv6Parser::parse(ipv6Data, ipv6Length);

        trafficStats.ipv6++;

        if (ip.nextHeader == 6)
            trafficStats.tcp++;
        else if (ip.nextHeader == 17)
            trafficStats.udp++;
        else
            trafficStats.otherIPProtocols++;

        trafficStats.ipCounts[ip.dstIP]++;
    }
}