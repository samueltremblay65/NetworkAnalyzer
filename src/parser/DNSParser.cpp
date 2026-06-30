#include "parser/DNSParser.h"

DNSQuery DNSParser::parse(const uint8_t* dnsData, size_t length)
{
    DNSQuery result;

    // DNS header is 12 bytes
    if (length < 12)
        return result;

    size_t offset = 12;

    while (offset < length)
    {
        uint8_t labelLength = dnsData[offset];

        // End of domain name
        if (labelLength == 0)
        {
            result.valid = !result.domainName.empty();
            return result;
        }

        offset++;

        // Prevent malformed packets from reading past the buffer
        if (offset + labelLength > length)
            return DNSQuery();

        if (!result.domainName.empty())
            result.domainName += '.';

        result.domainName.append(
            reinterpret_cast<const char*>(dnsData + offset),
            labelLength);

        offset += labelLength;
    }

    return DNSQuery();
}