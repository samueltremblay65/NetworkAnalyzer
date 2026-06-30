#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

struct DNSQuery
{
    std::string domainName;
    bool valid = false;
};

class DNSParser
{
public:
    static DNSQuery parse(const uint8_t* dnsData, size_t length);
};