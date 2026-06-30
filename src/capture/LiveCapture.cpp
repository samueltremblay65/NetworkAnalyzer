#include "capture/LiveCapture.h"

#include <iostream>
#include <vector>

#include <pcap.h>

bool LiveCapture::start(PacketProcessor& processor, TrafficStats& stats, int packetLimit)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find all network adapters
    pcap_if_t* devices = nullptr;

    if (pcap_findalldevs(&devices, errbuf) == -1)
    {
        std::cerr << "Failed to enumerate network adapters:\n"
                  << errbuf << '\n';
        return false;
    }

    if (devices == nullptr)
    {
        std::cerr << "No capture devices found.\n";
        return false;
    }

    // Display adapters
    std::vector<pcap_if_t*> adapterList;

    std::cout << "\nAvailable network adapters:\n\n";

    int index = 0;

    for (pcap_if_t* d = devices; d != nullptr; d = d->next)
    {
        adapterList.push_back(d);

        std::cout << index << ": ";

        if (d->description)
            std::cout << d->description;
        else
            std::cout << d->name;

        std::cout << '\n';

        index++;
    }

    // Let the user choose one
    int choice;

    std::cout << "\nSelect adapter: ";
    std::cin >> choice;

    if (choice < 0 || choice >= adapterList.size())
    {
        std::cerr << "Invalid adapter selection.\n";
        pcap_freealldevs(devices);
        return false;
    }

    pcap_if_t* adapter = adapterList[choice];

    // Open adapter for live capture
    pcap_t* handle = pcap_open_live(
        adapter->name,
        65536,     // Capture the entire packet
        1,         // Promiscuous mode
        1000,      // Read timeout (milliseconds)
        errbuf);

    if (handle == nullptr)
    {
        std::cerr << "Failed to open adapter:\n"
                  << errbuf << '\n';

        pcap_freealldevs(devices);
        return false;
    }

    if (!handle)
    {
        std::cerr << "pcap_open_live failed: "
                << errbuf << "\n";
        return false;
    }
    

    std::cout << "\nListening for packets...\n";
    std::cout << "Press Ctrl+C to stop.\n\n";

    int packetsCaptured = 0;

    // Capture packets forever
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int result = pcap_next_ex(handle, &header, &packet);

        if(packetsCaptured > packetLimit) {
            // We found enough packets, stop capture
            break;
        }

        if (result == 0)
        {
            // No packet arrived
            continue;
        }

        if (result == -1)
        {
            std::cerr << "Capture error: "
                      << pcap_geterr(handle)
                      << '\n';
            break;
        }

        if (result == -2)
        {
            // Capture finished (offline files only)
            break;
        }

        if(result == 1) // Packet captured, now process it
        {
            processor.processPacket(
                reinterpret_cast<const uint8_t*>(packet),
                header->caplen,
                stats
            );

            packetsCaptured++;
        }
    }

    pcap_close(handle);
    pcap_freealldevs(devices);

    return true;
}