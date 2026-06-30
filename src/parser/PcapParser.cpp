#include <fstream>
#include <iostream>
#include <vector>

#include "parser/PcapParser.h"
#include "core/PacketProcessor.h"
#include "model/EthernetFrame.h"
#include "parser/EthernetParser.h"
#include "parser/IPv4Parser.h"
#include "parser/IPv6Parser.h"
#include "stats/TrafficStats.h"
#include "util/MapUtils.h"

PcapParser::PcapParser() : handle(nullptr) {}

PcapParser::~PcapParser()
{
    close();
}

bool PcapParser::open(const std::string& filePath)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(filePath.c_str(), errbuf);

    if (!handle)
    {
        std::cerr << "pcap_open_offline failed: "
                  << errbuf << "\n";
        close();
        return false;
    }

    return true;
}

bool PcapParser::readGlobalHeader()
{
    if (!handle)
    {
        std::cerr << "PCAP handle is null\n";
        return false;
    }

    int linkType = pcap_datalink(handle);

    std::cout << "PCAP GLOBAL HEADER INFO\n";
    std::cout << "Link-layer type: " << linkType << "\n";

    if (linkType != 1)
    {
        std::cerr << "Unsupported link type (not Ethernet)\n";
        return false;
    }

    return true;
}

bool PcapParser::readPackets(PacketProcessor& processor, TrafficStats& stats)
{
    if (!handle)
    {
        std::cerr << "Cannot read packets: handle is null\n";
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true)
    {
        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 1)
        {
            if (!packet || !header)
                continue;

            processor.processPacket(
                reinterpret_cast<const uint8_t*>(packet),
                header->caplen,
                stats
            );
        }
        else if (result == 0)
        {
            continue; // timeout (rare for offline)
        }
        else if (result == -2)
        {
            break; // EOF
        }
        else
        {
            std::cerr << "pcap_next_ex error: "
                      << pcap_geterr(handle) << "\n";
            break;
        }
    }

    return true;
}

void PcapParser::close()
{
    if (handle)
    {
        pcap_close(handle);
        handle = nullptr;
    }
}