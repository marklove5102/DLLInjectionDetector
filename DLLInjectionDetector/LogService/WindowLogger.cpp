#include <Windows.h>
#include "WindowLogger.h"
#include <string>

namespace InjectionDetector
{
  WindowLogger::WindowLogger(HWND windowHandle, int dialogItem)
  {
    _windowHandle = windowHandle;
    _dialogItem = dialogItem;
  }

  WindowLogger::~WindowLogger()
  {
  }

  void WindowLogger::Log(LPCWSTR text)
  {
    GetDlgItemText(_windowHandle, _dialogItem, _buffer, sizeof(_buffer) / 2);

    std::wstring output(_buffer);
    output += L"\r\n";
    output += text;
    output += L"\r\n";

    SetDlgItemText(_windowHandle, _dialogItem, output.c_str());
  }
}