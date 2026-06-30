#include "core/PacketProcessor.h"

#include "parser/EthernetParser.h"
#include "parser/IPv4Parser.h"
#include "parser/IPv6Parser.h"
#include "parser/DNSParser.h"
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
        int ipHeaderLength = (data[14] & 0x0F) * 4;

        trafficStats.ipv4++;

        if (ip.protocol == 6) {
            trafficStats.tcp++;
            const uint8_t* tcp = data + 14 + (ipHeaderLength);

            uint16_t srcPort = (tcp[0] << 8) | tcp[1];
            uint16_t dstPort = (tcp[2] << 8) | tcp[3];

            trafficStats.tcpPortCounts[srcPort]++;
            trafficStats.tcpPortCounts[dstPort]++;

        }

        else if (ip.protocol == 17) {
            trafficStats.udp++;
            const uint8_t* udp = data + 14 + (ipHeaderLength);

            uint16_t srcPort = (udp[0] << 8) | udp[1];
            uint16_t dstPort = (udp[2] << 8) | udp[3];

            trafficStats.udpPortCounts[srcPort]++;
            trafficStats.udpPortCounts[dstPort]++;
            
            if (srcPort == 53 || dstPort == 53)
            {
                // If DNS Packet
                const uint8_t* dnsData = udp + 8;
                size_t dnsLength = length - (dnsData - data);

                DNSQuery query = DNSParser::parse(dnsData, dnsLength);

                if (query.valid)
                {
                    trafficStats.dnsQueries[query.domainName]++;
                }
            }
        }
        else trafficStats.otherIPProtocols++;

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

        const int ethernetHeader = 14;
        const int ipv6Header = 40;

        if (ip.nextHeader == 6) {
            trafficStats.tcp++;
            const uint8_t* tcp = data + ethernetHeader + ipv6Header;
            uint16_t srcPort = (tcp[0] << 8) | tcp[1];
            uint16_t dstPort = (tcp[2] << 8) | tcp[3];
        }
        else if (ip.nextHeader == 17) {
            trafficStats.udp++;
            const uint8_t* udp = data + ethernetHeader + ipv6Header;

            uint16_t srcPort = (udp[0] << 8) | udp[1];
            uint16_t dstPort = (udp[2] << 8) | udp[3];

            trafficStats.udpPortCounts[srcPort]++;
            trafficStats.udpPortCounts[dstPort]++;

            if (srcPort == 53 || dstPort == 53)
            {
                // If DNS Packet
                const uint8_t* dnsData = udp + 8;
                size_t dnsLength = length - (dnsData - data);

                DNSQuery query = DNSParser::parse(dnsData, dnsLength);

                if (query.valid)
                {
                    trafficStats.dnsQueries[query.domainName]++;
                }
            }
        }
        else trafficStats.otherIPProtocols++;

        trafficStats.ipCounts[ip.dstIP]++;
    }
}