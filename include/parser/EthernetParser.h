#pragma once
#include <vector>
#include "model/EthernetFrame.h"

class EthernetParser
{
    public:
        static EthernetFrame parse(const std::vector<uint8_t>& data);
};