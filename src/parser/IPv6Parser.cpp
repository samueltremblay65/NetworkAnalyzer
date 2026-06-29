#include "parser/IPv6Parser.h"

#include <vector>
#include <sstream>
#include <iomanip>

static std::string formatIPv6(const uint8_t* p)
{
    std::ostringstream ss;

    for (int i = 0; i < 16; i += 2)
    {
        uint16_t block = (p[i] << 8) | p[i + 1];

        ss << std::hex << block;

        if (i < 14)
            ss << ":";
    }

    return ss.str();
}

IPv6Packet IPv6Parser::parse(const std::vector<uint8_t>& data, size_t offset)
{
    IPv6Packet pkt;

    const uint8_t* p = data.data() + offset;

    // IPv6 header is fixed 40 bytes
    // -------------------------------
    // Byte 6: Next Header (protocol)
    // Byte 7: Hop Limit (TTL equivalent)
    // Byte 8: Source IP (16 bytes)
    // Byte 24: Destination IP (16 bytes)
    // -------------------------------

    pkt.nextHeader = p[6];
    pkt.hopLimit = p[7];

    pkt.srcIP = formatIPv6(p + 8);
    pkt.dstIP = formatIPv6(p + 24);

    return pkt;
}