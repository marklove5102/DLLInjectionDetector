#include <Windows.h>
#include "ConsoleLogger.h"
#include <iostream>
#include <string>

namespace InjectionDetector
{
  ConsoleLogger::ConsoleLogger()
  {
  }

  ConsoleLogger::~ConsoleLogger()
  {
  }

  void ConsoleLogger::Log(LPCWSTR text)
  {
    std::wcout << std::endl << text << std::endl;
  }
}