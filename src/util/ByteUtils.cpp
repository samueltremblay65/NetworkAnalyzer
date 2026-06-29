#include "util/ByteUtils.h"
#include <sstream>
#include <iomanip>

// Formats MAC adress
std::string formatMac(const uint8_t* data)
{
    std::stringstream ss;

    // MAC address has 6 bytes
    for (int i = 0; i < 6; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(data[i]);

        // If not at the end
        if (i != 5)
            ss << ":";
    }

    return ss.str();
}