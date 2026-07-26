# linoutemp
## extremly shitcoded, good luck trying to do anything with this :D
a kernel temporary spoofer and cleaner tool for fortnite. maps unsigned drivers using a vulnerable intel driver exploit (iqvw64e.sys) and provides hardware trace cleaning utilities. made by [linoucat](https://github.com/linoucat)

## features

- **driver mapper** - full kdmapper implementation that maps the spoofer driver file into kernel memory via intel driver vulnerability, supports independent page allocation, import resolving, section protection, and driver trace cleanup (piddb cache, kernel hash bucket, mmunloadeddrivers, wdfilter)
- **spoofer** - loads a custom spoofing driver that spoofs all required hwid identifiers for fortnite bans
- **cleaner** - loads a cleaning driver, removes epic games registry keys, deletes fortnite crash logs and saved data, clears browser cache, flushes dns, removes recent documents, downloads and executes an additional cleanup utility

## how it works

the tool uses the known intel driver vulnerability (iqvw64e.sys) to gain kernel level access. it extracts the vulnerable driver from embedded resources, writes it to disk with a random name, registers it as a windows service and starts it. once the driver is loaded it provides ioctl based primitives for reading/writing physical memory, allocating kernel pool pages and calling kernel functions

the actual spoofer and cleaner drivers are embedded as xor encrypted byte arrays and decrypted at runtime before mapping. the mapper parses the pe headers, allocates kernel memory, copies sections, resolves imports against ntoskrnl.exe and other kernel modules, fixes relocations, sets memory protection per section and calls the driver entry point

after the kernel driver does its job, the user-mode tool also runs registry cleanup, file deletion, and system utility calls to remove leftover traces.

## project structure

```
linoutemp.sln              - visual studio 2022 solution
linoutemp.vcxproj          - project file (x64 release/debug)
main.cpp                   - entry point, menu loop
term.hpp                   - minimal console ui (3 buttons clean/spoof/exit)
run.hpp                    - feature execution (spoofer + cleaner logic)
blob.hpp                   - xor-encrypted driver binaries (spoof driver + clean driver)
ext/
  ldr.cpp/.hpp             - kdmapper core (pe loader, memory allocation, import resolving)
  wrap.cpp/.hpp            - mapper wrapper (admin check, vulnerable driver init, guid patching)
  drv.cpp/.hpp             - intel driver interface (ioctl, memory r/w, pool management)
  drv_res.hpp              - embedded vulnerable intel driver (iqvw64e.sys)
  svc.cpp/.hpp             - windows service management (register, start, stop, remove)
  pe.cpp/.hpp              - portable executable parser (pe headers, sections, relocs, imports)
  utl.cpp/.hpp             - utilities (pattern scanning, kernel module lookup, temp path)
  ctx.cpp/.hpp             - driver session context (guid tracking)
  nt.hpp                   - nt kernel structures (piddbcacheentry, rtl_avl_table, etc.)
  sym.h                    - optional pdb symbol handler
```

## building

open the solution in visual studio 2022, select release|x64, and build. you'll need the windows sdk and the c++ desktop workload installed. the project statically links the crt (multithreaded) to avoid external dependencies.

## usage

1. build the project
2. run the executable as administrator (required for the vulnerable driver)
3. select an option from the menu:
   - **clean** - loads the cleaner driver, removes game traces, registry keys, cache, downloads cleanup tool
   - **spoof** - loads the spoofer driver to spoof hardware identifiers
   - **exit** - quit

## notes

- this requires administrator privileges to load the vulnerable intel driver
- vulnerable driver list must be disabled or the driver will be blocked
- some antivirus software may flag the vulnerable driver or the mapping technique
- the spoofer and cleaner drivers are embedded xor-obfuscated (so no you won't get the source :3)
- you need to restart your pc after running the cleaner for full effect, after you re spoof OBVIOUSLY

## credits

- intel driver exploit widely known in the cheat com, no need to credit someone
- kdmapper (https://github.com/z175/kdmapper) for the original driver mapping implementation

## license

you can use this code for your own purposes, but please don't claim it as your own work.
