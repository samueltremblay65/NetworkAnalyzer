#include "parser/EthernetParser.h"
#include "util/ByteUtils.h"
#include "parser/IPv4Parser.h"
#include "parser/IPv6Parser.h"

#include <iostream>

EthernetFrame EthernetParser::parse(const std::vector<uint8_t>& data)
{
    EthernetFrame frame;

    const uint8_t* ptr = data.data();

    // Ethernet header layout (standard IEEE 802.3 frame)

    // Byte offset | Field
    // ---------------------------------------
    // 0-5         | Destination MAC (6 bytes)
    // 6-11        | Source MAC (6 bytes)
    // 12-13       | EtherType (2 bytes)
    // 14+         | Payload (rest of bytes)

    frame.destMac = formatMac(ptr);        // reads bytes 0–5
    frame.srcMac  = formatMac(ptr + 6);    // reads bytes 6–11

    // EtherType, 2 bytes (big-endian)
    // ptr[12] = high byte, ptr[13] = low byte
    frame.etherType = (ptr[12] << 8) | ptr[13];

    return frame;
}