#include "parser/IPv4Parser.h"
#include <sstream>

static std::string formatIP(uint32_t ip)
{
    std::ostringstream ss;
    ss
        << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);

    return ss.str();
}

IPv4Packet IPv4Parser::parse(const std::vector<uint8_t>& data, size_t offset)
{
    IPv4Packet pkt;

    const uint8_t* p = data.data() + offset;

    // IPv4 header layout (minimum 20 bytes)
    // -------------------------------
    // Byte 0: Version + IHL
    // Byte 8: TTL
    // Byte 9: Protocol
    // Byte 12: Source IP (4 bytes)
    // Byte 16: Destination IP (4 bytes)
    // -------------------------------

    pkt.ttl = p[8];
    pkt.protocol = p[9];

    uint32_t src =
        (p[12] << 24) |
        (p[13] << 16) |
        (p[14] << 8)  |
        (p[15]);

    uint32_t dst =
        (p[16] << 24) |
        (p[17] << 16) |
        (p[18] << 8)  |
        (p[19]);

    pkt.srcIP = formatIP(src);
    pkt.dstIP = formatIP(dst);

    return pkt;
}