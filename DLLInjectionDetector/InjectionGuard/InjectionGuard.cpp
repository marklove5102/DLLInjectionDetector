#include <string>
#include "InjectionGuard.h"
#include "..\InjectionDetector\InjectionDetector.h"
#include "..\LogService\ILogService.h"

namespace InjectionDetector
{
  InjectionGuard::InjectionGuard(ILogService* logService)
  {
    _logService = logService;
  }

  InjectionGuard::~InjectionGuard()
  {
  }

  NTSTATUS InjectionGuard::HandleLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
  {
    // This hook is not required for InjectionGuard, as thread creation for DLL loading is already blocked in BaseThreadInitThunk,
    // and DLL loading itself is handled in HandleRtlGetFullPathName_U.
    return InjectionDetector::Instance()->CallLdrLoadDllStub(DllPath, DllCharacteristics, DllName, DllHandle);
  }

  ULONG __stdcall InjectionGuard::HandleRtlGetFullPathName_U(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart)
  {
    if (FileName != nullptr)
    {
      auto moduleHandle = GetModuleHandleW(FileName); // Checking if the filename belongs to a module. When injected, it is already available using GetModuleHandleW at this point.
      if (moduleHandle != nullptr)
      {
        std::wstring output(L"RtlGetFullPathName_U: Blocked attempt to inject ");
        output.append(FileName);
        _logService->Log(output.c_str());

        memset(Buffer, 0, BufferLength);
        return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(NULL, BufferLength, Buffer, FilePart);
      }
    }
    return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(FileName, BufferLength, Buffer, FilePart);
  }

  void __fastcall InjectionGuard::HandleBaseThreadInitThunk(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter)
  {
    bool threadBlocked = false;
    if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"))
    {
      threadBlocked = true;
      _logService->Log(L"BaseThreadInitThunk: Blocked thread creation on LoadLibraryA");
    }
    else if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"))
    {
      threadBlocked = true;
      _logService->Log(L"BaseThreadInitThunk: Blocked thread creation on LoadLibraryW");
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllOriginal((DWORD)lpStartAddress))
    {
      threadBlocked = true;
      _logService->Log(L"BaseThreadInitThunk: Blocked thread creation on LdrLoadDll");
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllHook((DWORD)lpStartAddress))
    {
      threadBlocked = true;
      _logService->Log(L"BaseThreadInitThunk: Blocked thread creation on LdrLoadDllHook");
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllStub((DWORD)lpStartAddress))
    {
      threadBlocked = true;
      _logService->Log(L"BaseThreadInitThunk: Blocked thread creation on LdrLoadDllStub");
    }
    else
    {
      DWORD startAddress = (DWORD)lpStartAddress;
      if (!InjectionDetector::Instance()->IsModuleAddress(startAddress))
      {
        threadBlocked = true;
        _logService->Log(L"BaseThreadInitThunk: Blocked creation of suspicious thread");
      }
    }

    if (threadBlocked)
    {
      InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, (LPTHREAD_START_ROUTINE)Sleep, 0);
    }
    else
    {
      InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, lpStartAddress, lpParameter);
    }
  }
}
