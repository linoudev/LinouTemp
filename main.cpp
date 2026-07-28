#include <iostream>
#include <vector>
#include <conio.h>
#include "term.hpp"
#include "run.hpp"
// welcome to this horrible temp woofer, semi pasted and detected asf.
// made by https://github.com/linoudev
// consider joining https://discord.gg/linouservices
// i hope you enjoy this terrible temp source <3
int main() {
    term::init();
    term::title("svc");
    term::cursor(false);

    while (true) {
        printf("welcome to linou free woofer!");
        std::vector<const char*> opts = { "clean", "spoof", "exit" };
        int ch = term::menu(opts);
        switch (ch) {
        case 0:
            run::run_clean();
            printf("\npress any key..");
            _getch();
            break;
        case 1:
            run::run_spoof();
            printf("\npress any key..");
            _getch();
            break;
        case 2:
            term::cursor(true);
            return 0;
        }
    }
}
