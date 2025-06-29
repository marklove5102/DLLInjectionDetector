#include <string>
#include "InjectionMonitor.h"
#include "..\InjectionDetector\InjectionDetector.h"
#include "..\LogService\ILogService.h"

namespace InjectionDetector
{
  InjectionMonitor::InjectionMonitor(ILogService* logService)
  {
    _logService = logService;
    _dllCreationThreadDetected = false;
  }

  InjectionMonitor::~InjectionMonitor()
  {
  }

  NTSTATUS InjectionMonitor::HandleLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
  {
    if (_dllCreationThreadDetected)
    {
      _dllCreationThreadDetected = false;

      std::wstring output(L"LdrLoadDll: Detected dll ");
      output.append(DllName->Buffer);
      _logService->Log(output.c_str());
    }
    return InjectionDetector::Instance()->CallLdrLoadDllStub(DllPath, DllCharacteristics, DllName, DllHandle);
  }

  ULONG __stdcall InjectionMonitor::HandleRtlGetFullPathName_U(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart)
  {
    if (FileName != nullptr)
    {
      auto moduleHandle = GetModuleHandleW(FileName); // Checking if the filename belongs to a module. When injected, it is already available using GetModuleHandleW at this point.
      if (moduleHandle != nullptr)
      {
        std::wstring output(L"RtlGetFullPathName_U: Detected dll ");
        output.append(FileName);
        _logService->Log(output.c_str());
      }
    }
    return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(FileName, BufferLength, Buffer, FilePart);
  }

  void __fastcall InjectionMonitor::HandleBaseThreadInitThunk(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter)
  {
    if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"))
    {
      _dllCreationThreadDetected = true;
      _logService->Log(L"BaseThreadInitThunk: Detected thread creation on LoadLibraryA");
    }
    else if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"))
    {
      _dllCreationThreadDetected = true;
      _logService->Log(L"BaseThreadInitThunk: Detected thread creation on LoadLibraryW");
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllOriginal((DWORD)lpStartAddress))
    {
      _dllCreationThreadDetected = true;
      _logService->Log(L"BaseThreadInitThunk: Detected thread creation on LdrLoadDll");
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllHook((DWORD)lpStartAddress))
    {
      _dllCreationThreadDetected = true;
      _logService->Log(L"BaseThreadInitThunk: Detected thread creation on LdrLoadDllHook");
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllStub((DWORD)lpStartAddress))
    {
      _dllCreationThreadDetected = true;
      _logService->Log(L"BaseThreadInitThunk: Detected thread creation on LdrLoadDllStub");
    }
    else
    {
      DWORD startAddress = (DWORD)lpStartAddress;
      if (!InjectionDetector::Instance()->IsModuleAddress(startAddress))
      {
        _logService->Log(L"BaseThreadInitThunk: Detected creation of suspicious thread");
      }
    }
    InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, lpStartAddress, lpParameter);
  }
}
