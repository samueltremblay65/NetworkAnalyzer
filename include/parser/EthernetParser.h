#pragma once
#include <vector>
#include "model/EthernetFrame.h"

class EthernetParser
{
    public:
        static EthernetFrame parse(const uint8_t* data);
};