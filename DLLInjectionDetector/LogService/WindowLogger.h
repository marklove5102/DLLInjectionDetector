#pragma once
#include "ILogService.h"

namespace InjectionDetector
{
  class WindowLogger : public ILogService
  {
  public:
    WindowLogger(HWND windowHandle, int dialogItem);
    ~WindowLogger();

    virtual void Log(LPCWSTR text);

  private:
    HWND _windowHandle;
    int _dialogItem;
    wchar_t _buffer[10240] = { 0 };
  };
}