#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <conio.h>
#include <windows.h>

namespace term {
    inline HANDLE _h = GetStdHandle(STD_OUTPUT_HANDLE);

    inline void init() {
        DWORD m = 0;
        GetConsoleMode(_h, &m);
        SetConsoleMode(_h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleOutputCP(CP_UTF8);
    }

    inline void title(const char* t) { SetConsoleTitleA(t); }

    inline void cursor(bool v) {
        CONSOLE_CURSOR_INFO ci;
        GetConsoleCursorInfo(_h, &ci);
        ci.bVisible = v;
        SetConsoleCursorInfo(_h, &ci);
    }

    inline void cls() { system("cls"); }

    enum class L { I, G, W, E };

    inline void log(const char* tag, const char* msg, L lv = L::I) {
        const char* c = "\x1b[37m";
        switch (lv) {
        case L::I: c = "\x1b[36m"; break;
        case L::G: c = "\x1b[32m"; break;
        case L::W: c = "\x1b[33m"; break;
        case L::E: c = "\x1b[31m"; break;
        }
        printf("%s[%s] %s\x1b[0m\n", c, tag, msg);
    }

    inline void bar(const char* label, int ms) {
        printf("\n%s [", label);
        for (int i = 0; i < 30; i++) {
            printf("\x1b[32m=\x1b[0m");
            fflush(stdout);
            Sleep(ms / 30);
        }
        printf("] \x1b[32mOK\x1b[0m\n");
    }

    inline int menu(const std::vector<const char*>& opts) {
        cursor(false);
        int sel = 0;
        while (true) {
            cls();
            printf("welcome to linou free woofer!\n\n");
            for (size_t i = 0; i < opts.size(); i++) {
                if (i == sel) printf("  \x1b[36m> %s\x1b[0m\n", opts[i]);
                else printf("    %s\n", opts[i]);
            }
            printf("\n  \x1b[90m[arrows/ws] enter\x1b[0m");
            int k = _getch();
            if (k == 224 || k == 0) k = _getch();
            if (k == 72 || k == 'w' || k == 'W') sel = (sel - 1 + (int)opts.size()) % opts.size();
            else if (k == 80 || k == 's' || k == 'S') sel = (sel + 1) % opts.size();
            else if (k == 13 || k == ' ') break;
        }
        cursor(true);
        return sel;
    }
}
