#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <utility>
#include <vector>

// TODO: Apply templates instead of having overloads by type
bool mapContainsKey(std::unordered_map<int, int>& map, int key) {
  if (map.find(key) == map.end()) return false;
  return true;
}

bool mapContainsKey(std::unordered_map<std::string, int>& map, std::string key) {
  if (map.find(key) == map.end()) return false;
  return true;
}

std::vector<std::pair<int, int>> getTopEntries(const std::unordered_map<int, int>& map, std::size_t n)
{
    std::vector<std::pair<int, int>> entries(map.begin(), map.end());

    // Sort by value
    std::sort(entries.begin(), entries.end(),
        [](const auto& a, const auto& b)
        {
            return a.second > b.second;
        });

    // Keep only n items if there are more
    if (entries.size() > n)
    {
        entries.resize(n);
    }

    return entries;
}

std::vector<std::pair<std::string, int>> getTopEntries(const std::unordered_map<std::string, int>& map, std::size_t n)
{
    std::vector<std::pair<std::string, int>> entries(map.begin(), map.end());

    // Sort by value
    std::sort(entries.begin(), entries.end(),
        [](const auto& a, const auto& b)
        {
            return a.second > b.second;
        });

    // Keep only n items if there are more
    if (entries.size() > n)
    {
        entries.resize(n);
    }

    return entries;
}