#include "wrap.hpp"
#include <iostream>
#include <vector>
#include <Windows.h>

namespace term {
    enum class L { I = 0, G = 1, E = 2 };
    extern void log(const char* tag, const char* msg, L lv);
}

namespace ctx {
    extern std::string guid;
    extern GUID guidStruct;
}

#define DISABLE_OUTPUT
#include "ldr.hpp"
#include "drv.hpp"

namespace mod::wrap {

bool init() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        term::log("sys", "admin rights required", term::L::E);
        return false;
    }

    NTSTATUS status = mod::drv::Load();
    if (!NT_SUCCESS(status)) {
        char buf[32];
        sprintf_s(buf, "0x%X", status);
        std::string m = "load failed\nNTSTATUS: " + std::string(buf) + "\n\n";

        if (status == 0xC0000428) {
            m += "driver blocklist active";
            term::log("sys", "blocklist - check reg", term::L::E);
        }
        else if (status == 0xC0000022) {
            m += "access denied - run as admin";
            term::log("sys", "access denied", term::L::E);
        }
        else if (status == 0xC000010E) {
            m += "driver already loaded - restart PC";
            term::log("sys", "already loaded - restart", term::L::E);
        }
        else if (status == 0xC0000718) {
            m += "blocked by security software";
            term::log("sys", "security block", term::L::E);
        }
        else {
            m += "check log";
            term::log("sys", ("init failed (" + std::string(buf) + ")").c_str(), term::L::E);
        }

        MessageBoxA(NULL, m.c_str(), "init error", MB_ICONERROR);
        return false;
    }

    return true;
}

bool map(const std::vector<uint8_t>& drv, bool needGuid) {
    if (drv.empty()) {
        term::log("sys", "empty driver", term::L::E);
        return false;
    }

    std::vector<uint8_t> data(drv.size());
    data.assign(drv.begin(), drv.end());

    const uint8_t placeholder[16] = {
        0xEF, 0xBE, 0xAD, 0xDE, 0xAD, 0xDE, 0xEF, 0xBE,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };

    bool patched = false;
    size_t off = 0;

    if (needGuid) {
        for (size_t i = 0; i <= data.size() - 16; i++) {
            if (memcmp(&data[i], placeholder, 16) == 0) {
                if (i >= 0x1000) {
                    uint8_t gb[16];
                    memcpy(gb, &ctx::guidStruct, sizeof(GUID));
                    if (i + 16 <= data.size()) {
                        memcpy(&data[i], gb, 16);
                        patched = true;
                        off = i;
                        if (memcmp(&data[i], gb, 16) == 0) {
                            char msg[128];
                            sprintf_s(msg, "guid at 0x%zX", off);
                            term::log("sys", msg, term::L::G);
                        } else {
                            term::log("sys", "guid write fail", term::L::E);
                            return false;
                        }
                        break;
                    }
                }
            }
        }

        if (!patched) {
            term::log("sys", "guid not found - bad compile", term::L::E);
            return false;
        }
    } else {
        term::log("sys", "guid bypass", term::L::I);
    }

    term::log("sys", "mapping driver..", term::L::I);
    Sleep(100);

    NTSTATUS ec = 0;
    ULONG64 res = mod::ldr::MapDriver(
        data.data(), 0, 0, false, true,
        mod::ldr::AllocationMode::AllocateIndependentPages,
        false, nullptr, &ec
    );

    if (res == 0) {
        term::log("sys", "map failed", term::L::E);
        return false;
    }

    if (!NT_SUCCESS(ec)) {
        char buf[32];
        sprintf_s(buf, "0x%X", ec);
        term::log("sys", ("init failed (" + std::string(buf) + ")").c_str(), term::L::E);
        return false;
    }

    return true;
}

bool cleanup() {
    mod::drv::Unload();
    return true;
}

}
