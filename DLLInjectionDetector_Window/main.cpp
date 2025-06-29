#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string>
#include "Resources\resource1.h"
#include "..\DLLInjectionDetector\InjectionDetector\InjectionDetector.h"
#include "..\DLLInjectionDetector\InjectionMonitor\InjectionMonitor.h"
#include "..\DLLInjectionDetector\InjectionGuard\InjectionGuard.h"
#include "..\DLLInjectionDetector\LogService\WindowLogger.h"

LRESULT CALLBACK DlgProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
void Start(HWND hWnd);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{
  DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, reinterpret_cast<DLGPROC>(DlgProc));
}

LRESULT CALLBACK DlgProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  switch (Msg)
  {
    case WM_INITDIALOG:
    {
      //SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
      break;
    }
    case WM_COMMAND:
    {
      switch (wParam)
      {
        case IDC_START:
        {
          auto startButton = GetDlgItem(hWnd, IDC_START);
          EnableWindow(startButton, FALSE);
          Start(hWnd);
          break;
        }
      }
      break;
    }
    case WM_CLOSE:
    {
      EndDialog(hWnd, TRUE);
      break;
    }
  }

  return FALSE;
}

void Start(HWND hWnd)
{
  SetDlgItemText(hWnd, IDC_LOG, L"Starting in guard mode.");
  InjectionDetector::InjectionDetector::Instance()->Initialze(new InjectionDetector::InjectionGuard(new InjectionDetector::WindowLogger(hWnd, IDC_LOG)));
}