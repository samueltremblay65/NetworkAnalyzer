#pragma once
#include <string>
#include <cstdint>
#include <unordered_map>

#include "stats/TrafficStats.h"

class PcapParser
{
    public:
        bool open(const std::string& filename);
        bool readGlobalHeader();
        bool readPackets(TrafficStats& trafficStats);

    private:
        std::string filePath;

    struct GlobalHeader
    {
        // Identifies the file format and byte ordering.
        // Common values:
        // 0xa1b2c3d4: standard PCAP (native endian)
        // 0xd4c3b2a1: swapped endian version
        uint32_t magicNumber;

        // PCAP format version major number, 2 bytes
        // Almost always 2.
        uint16_t versionMajor;

        // PCAP format version minor number, 2 bytes
        // Almost always 4 (i.e., version 2.4).
        uint16_t versionMinor;

        // Timezone correction (deprecated in modern usage).
        // Typically set to 0.
        int32_t thiszone;

        // Rarely used, usually 0
        uint32_t sigfigs;

        uint32_t snaplen;

        // Common values:
        // 1: Ethernet
        // 105: IEEE 802.11 (Wi-Fi)
        uint32_t network;
    } header;

    struct PacketHeader
    {
        // Timestamp of packet capture, in seconds since epoch
        uint32_t ts_sec;

        // Microseconds part of timestamp
        uint32_t ts_usec;

        // Number of bytes actually stored in the file for this packet, may be truncated for performance reasons
        uint32_t incl_len;

        // Original size of the packet on the wire, useful for detecting truncation)
        uint32_t orig_len;
    };
};