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
        trafficStats.ipv4++;

        if (ipLength < 20)
            return;

        IPv4Packet ip = IPv4Parser::parse(data + 14, length - 14);
        int ipHeaderLength = (data[14] & 0x0F) * 4;

        const uint8_t* transport = data + 14 + ipHeaderLength;

        processTransportPacket(transport, length - (transport - data), ip.protocol, trafficStats);

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
        trafficStats.ipv6++;
        // IPv6 header is immediately after Ethernet header (14 bytes)
        const uint8_t* ipv6Data = data + 14;
        size_t ipv6Length = length - 14;

        if (ipv6Length < 40) // minimum IPv6 header size
            return;

        IPv6Packet ip = IPv6Parser::parse(ipv6Data, ipv6Length);

        const int ethernetHeader = 14;
        const int ipv6Header = 40;

        const uint8_t* transport = data + ethernetHeader + ipv6Header;

        processTransportPacket(transport,length - (transport - data), ip.nextHeader, trafficStats);
    }
}

void PacketProcessor::processTransportPacket(
    const uint8_t* transport,
    size_t transportLength,
    uint8_t protocol,
    TrafficStats& trafficStats)
{
    // Need at least the source and destination ports
    if (transportLength < 4)
        return;

    if (protocol == 6) // TCP
    {
        trafficStats.tcp++;

        uint16_t srcPort = (transport[0] << 8) | transport[1];
        uint16_t dstPort = (transport[2] << 8) | transport[3];

        trafficStats.tcpPortCounts[srcPort]++;
        trafficStats.tcpPortCounts[dstPort]++;

        // TCP header must be at least 20 bytes
        if (transportLength < 20)
            return;

        int tcpHeaderLength = ((transport[12] >> 4) & 0x0F) * 4;

        if (transportLength < static_cast<size_t>(tcpHeaderLength))
            return;

        const uint8_t* payload = transport + tcpHeaderLength;
        size_t payloadLength = transportLength - tcpHeaderLength;

        if (srcPort == 443 || dstPort == 443)
        {
            // TLS parsing goes here next
            // TLSHello hello = TLSParser::parse(payload, payloadLength);
        }
    }
    else if (protocol == 17) // UDP
    {
        trafficStats.udp++;

        uint16_t srcPort = (transport[0] << 8) | transport[1];
        uint16_t dstPort = (transport[2] << 8) | transport[3];

        trafficStats.udpPortCounts[srcPort]++;
        trafficStats.udpPortCounts[dstPort]++;

        // UDP header is always 8 bytes
        if (transportLength < 8)
            return;

        const uint8_t* payload = transport + 8;
        size_t payloadLength = transportLength - 8;

        if (srcPort == 53 || dstPort == 53)
        {
            DNSQuery query = DNSParser::parse(payload, payloadLength);

            if (query.valid)
            {
                trafficStats.dnsQueries[query.domainName]++;
            }
        }
    }
    else
    {
        trafficStats.otherIPProtocols++;
    }
}
