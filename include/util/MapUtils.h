#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

bool mapContainsKey(std::unordered_map<int, int>& map, int key);

bool mapContainsKey(std::unordered_map<std::string, int>& map, std::string key);

std::vector<std::pair<std::string, int>> getTopEntries(const std::unordered_map<std::string, int>& map, std::size_t n);