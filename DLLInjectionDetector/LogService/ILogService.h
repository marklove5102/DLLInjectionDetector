#pragma once
#include <Windows.h>

namespace InjectionDetector
{
  class ILogService
  {
  public:
    virtual void Log(LPCWSTR text) = 0;
  };
}