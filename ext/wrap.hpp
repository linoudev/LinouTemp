#pragma once
#include <Windows.h>
#include <vector>
#include <cstdint>

namespace mod::wrap {
    bool init();
    bool map(const std::vector<uint8_t>& drv, bool needGuid = true);
    bool cleanup();
}
