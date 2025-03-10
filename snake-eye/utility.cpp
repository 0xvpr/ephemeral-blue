#include "utility.hpp"

#include <algorithm>

std::string utility::to_lower(std::string s) {
    std::ranges::transform( s,
                            s.begin(),
                            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
