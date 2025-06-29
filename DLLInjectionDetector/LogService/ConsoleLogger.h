#pragma once
#include "ILogService.h"

namespace InjectionDetector
{
  class ConsoleLogger : public ILogService
  {
  public:
    ConsoleLogger();
    ~ConsoleLogger();

    virtual void Log(LPCWSTR text);

  };
}