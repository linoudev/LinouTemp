#define DISABLE_OUTPUT
#include "svc.hpp"
#include <Windows.h>
#include <string>
#include <iostream>

#include "utl.hpp"
#include "nt.hpp"
// main shi that will execute everything
NTSTATUS mod::svc::RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); 
	if (status != ERROR_SUCCESS) {
		LOG("[-] Can't create service key" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size()*sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		LOG("[-] Can't create 'ImagePath' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		LOG("[-] Can't create 'Type' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return STATUS_UNSUCCESSFUL;
	}

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS ntStatus = nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(ntStatus)) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		LOG("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return ntStatus;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	ntStatus = nt::NtLoadDriver(&serviceStr);

	LOG("[+] NtLoadDriver Status 0x" << std::hex << ntStatus << std::endl); // DO NOT BSOD DO NOT BSOD DO NOT BSOD DO NOT BSOD

	if (ntStatus == STATUS_IMAGE_CERT_REVOKED) {
		LOG("[-] driver blocked by policy" << std::endl);
		LOG("[-] Registry path to disable vulnerable driver list: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config" << std::endl);
		LOG("[-] Set 'VulnerableDriverBlocklistEnable' as dword to 0" << std::endl);
	}
	else if (ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_INSUFFICIENT_RESOURCES) {
		LOG("[-] Access Denied or Insufficient Resources (0x" << std::hex << ntStatus << "), Probably some anticheat or antivirus running blocking the load of vulnerable driver" << std::endl);
	}

	if (!NT_SUCCESS(ntStatus)) {

		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		if (status != ERROR_SUCCESS) {
			LOG("[-] Can't delete service registry key after NtLoadDriver failure" << std::endl);
		}
	}

	return ntStatus;
}

NTSTATUS mod::svc::StopAndRemove(const std::wstring& serviceName) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return STATUS_UNSUCCESSFUL;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return STATUS_SUCCESS; 
		}
		return STATUS_REGISTRY_IO_FAILED;
	}
	RegCloseKey(driver_service);

	NTSTATUS st = nt::NtUnloadDriver(&serviceStr);
	LOG("[+] NtUnloadDriver Status 0x" << std::hex << st << std::endl);// gg u didnt bsod :D
	if (st != ERROR_SUCCESS) {
		LOG("[-] Driver Unload Failed!!" << std::endl);
		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return st; 
	}

	status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return STATUS_REGISTRY_IO_FAILED;
	}
	return st;
}