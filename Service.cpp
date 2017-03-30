// DriverInstallService.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#define		MAX_NUM_OF_PROCESS		4
#include "Userenv.h"
#include"tlhelp32.h"



VOID ServiceMainProc();
VOID Install(TCHAR* pPath, TCHAR* pName);
VOID WriteLog(TCHAR* pFile, TCHAR* pMsg);
VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);
VOID WINAPI ServiceHandler(DWORD fdwControl);
VOID AttachProcessNames();
VOID ProcMonitorThread(VOID *);
VOID EndProcess(int ProcessIndex);
BOOL StartProcess(int ProcessIndex);
BOOL RunService(TCHAR* pName);
VOID ExecuteSubProcess();
BOOL KillService(TCHAR* pName);
VOID UnInstall(TCHAR* pName);
BOOL CREATEPROCESS(TCHAR* process_name,int processIndex);
BOOL Is64BitOS();
DWORD GetProcessIDFromName(TCHAR *name);
HANDLE GetProcessHandle(TCHAR *processname);




/** Window Service **/
const int nBufferSize = 500;
TCHAR pServiceName[nBufferSize + 1];
TCHAR pExeFile[nBufferSize + 1];
TCHAR lpCmdLineData[nBufferSize + 1];
TCHAR pLogFile[nBufferSize + 1];
BOOL  ProcessStarted = TRUE;
BOOL  bWin64 = FALSE;

CRITICAL_SECTION		myCS;
SERVICE_TABLE_ENTRY		lpServiceStartTable[] =
{
	{ pServiceName, ServiceMain },
	{ NULL, NULL }
};

LPTSTR ProcessNames[MAX_NUM_OF_PROCESS];

SERVICE_STATUS_HANDLE   hServiceStatusHandle;
SERVICE_STATUS          ServiceStatus;
PROCESS_INFORMATION	pProcInfo[MAX_NUM_OF_PROCESS];




int _tmain(int argc, _TCHAR* argv[])
{
	bWin64 = Is64BitOS();
	if (argc >= 2)
		_tcscpy(lpCmdLineData, argv[1]);
	ServiceMainProc();
	return 0;
}



VOID ServiceMainProc()
{
	::InitializeCriticalSection(&myCS);
	// initialize variables for .exe and .log file names
	TCHAR pModuleFile[nBufferSize + 1];
	DWORD dwSize = GetModuleFileName(NULL, pModuleFile, nBufferSize);
	pModuleFile[dwSize] = 0;
	if (dwSize > 4 && pModuleFile[dwSize - 4] == '.')
	{
		swprintf(pExeFile, _T("%s"), pModuleFile);
		pModuleFile[dwSize - 4] = 0;
		swprintf(pLogFile, _T("%s.log"), pModuleFile);
	}
	_tcscpy(pServiceName, _T("DriverInstallService"));

	if (_tcsicmp(_T("-i"), lpCmdLineData) == 0 || _tcsicmp(_T("-I"), lpCmdLineData) == 0)
		Install(pExeFile, pServiceName);
	else if (_tcsicmp(_T("-k"), lpCmdLineData) == 0 || _tcsicmp(_T("-K"), lpCmdLineData) == 0)
		KillService(pServiceName);
	else if (_tcsicmp(_T("-u"), lpCmdLineData) == 0 || _tcsicmp(_T("-U"), lpCmdLineData) == 0)
		UnInstall(pServiceName);
	else if (_tcsicmp(_T("-s"), lpCmdLineData) == 0 || _tcsicmp(_T("-S"), lpCmdLineData) == 0)
		RunService(pServiceName);
	else if (_tcsicmp(_T("-r"), lpCmdLineData) == 0 || _tcsicmp(_T("-R"), lpCmdLineData) == 0)
	{
		Install(pExeFile, pServiceName);
		RunService(pServiceName);
	}
	else if (_tcsicmp(_T("-t"), lpCmdLineData) == 0 || _tcsicmp(_T("-T"), lpCmdLineData) == 0)
	{
		KillService(pServiceName);
		UnInstall(pServiceName);
	}
	else
		ExecuteSubProcess();
}


VOID Install(TCHAR* pPath, TCHAR* pName)
{
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (schSCManager == 0)
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("OpenSCManager failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
	else
	{
		SC_HANDLE schService = CreateService
			(
			schSCManager,	/* SCManager database      */
			pName,			/* name of service         */
			pName,			/* service name to display */
			SERVICE_ALL_ACCESS,        /* desired access          */
			SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, /* service type            */
			SERVICE_AUTO_START,      /* start type              */
			SERVICE_ERROR_NORMAL,      /* error control type      */
			pPath,			/* service's binary        */
			NULL,                      /* no load ordering group  */
			NULL,                      /* no tag identifier       */
			NULL,                      /* no dependencies         */
			NULL,                      /* LocalSystem account     */
			NULL
			);                     /* no password             */
		if (schService == 0)
		{
			/*long nError = GetLastError();
			TCHAR pTemp[121];
			swprintf(pTemp, _T("Failed to create service %s, error code = %d\n"), pName, nError);
			WriteLog(pLogFile, pTemp);*/
		}
		else
		{
			/*TCHAR pTemp[121];
			swprintf(pTemp, _T("Service %s installed\n"), pName);
			WriteLog(pLogFile, pTemp);*/
			CloseServiceHandle(schService);
		}
		CloseServiceHandle(schSCManager);
	}
}



VOID WriteLog(TCHAR* pFile, TCHAR* pMsg)
{
	// write error or other information into log file
	::EnterCriticalSection(&myCS);
	try
	{
		SYSTEMTIME oT;
		::GetLocalTime(&oT);
		FILE* pLog = _tfopen(pFile, _T("a"));
		fprintf(pLog, "%02d/%02d/%04d, %02d:%02d:%02d\n    %s", oT.wMonth, oT.wDay, oT.wYear, oT.wHour, oT.wMinute, oT.wSecond, pMsg);
		fclose(pLog);
	}
	catch (...) {}
	::LeaveCriticalSection(&myCS);
}


VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	DWORD   status = 0;
	DWORD   specificError = 0xfffffff;

	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;
    for (int iLoop = 0; iLoop < MAX_NUM_OF_PROCESS; iLoop++)
    {
        pProcInfo[iLoop].hProcess = 0;
        StartProcess(iLoop);
    }

	hServiceStatusHandle = RegisterServiceCtrlHandler(pServiceName, ServiceHandler);
   

	if (hServiceStatusHandle == 0)
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("RegisterServiceCtrlHandler failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
		return;
	}

	// Initialization complete - report running status 
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;
	if (!SetServiceStatus(hServiceStatusHandle, &ServiceStatus))
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("SetServiceStatus failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
}



VOID WINAPI ServiceHandler(DWORD fdwControl)
{
	switch (fdwControl)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		ProcessStarted = FALSE;
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwCheckPoint = 0;
		ServiceStatus.dwWaitHint = 0;
		// terminate all processes started by this service before shutdown
		{
			for (int i = MAX_NUM_OF_PROCESS - 1; i >= 0; i--)
			{
				EndProcess(i);
				delete ProcessNames[i];
			}
		}
		break;
	case SERVICE_CONTROL_PAUSE:
		ServiceStatus.dwCurrentState = SERVICE_PAUSED;
		break;
	case SERVICE_CONTROL_CONTINUE:
		ServiceStatus.dwCurrentState = SERVICE_RUNNING;
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		if (fdwControl >= 128 && fdwControl < 256)
		{
			int nIndex = fdwControl & 0x7F;
			// bounce a single process
			if (nIndex >= 0 && nIndex < MAX_NUM_OF_PROCESS)
			{
				EndProcess(nIndex);
				StartProcess(nIndex);
			}
			// bounce all processes
			else if (nIndex == 127)
			{
				for (int i = MAX_NUM_OF_PROCESS - 1; i >= 0; i--)
				{
					EndProcess(i);
				}
				for (int i = 0; i < MAX_NUM_OF_PROCESS; i++)
				{
					StartProcess(i);
				}
			}
		}
		else
		{
			/*TCHAR pTemp[121];
			swprintf(pTemp, _T("Unrecognized opcode %d\n"), fdwControl);
			WriteLog(pLogFile, pTemp);*/
		}
	}
	if (!SetServiceStatus(hServiceStatusHandle, &ServiceStatus))
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("SetServiceStatus failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
}




BOOL StartProcess(int ProcessIndex)
{

	

	STARTUPINFO startUpInfo = { sizeof(STARTUPINFO), NULL, _T(""), NULL, 0, 0, 0, 0, 0, 0, 0, STARTF_USESHOWWINDOW, 0, 0, NULL, 0, 0, 0 };
	startUpInfo.wShowWindow = SW_SHOW;
	startUpInfo.lpDesktop = NULL;
	/*if (CreateProcess(NULL, ProcessNames[ProcessIndex], NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, \
		NULL, NULL, &startUpInfo, &pProcInfo[ProcessIndex]))
	{
		
	}*/
	if (CREATEPROCESS(ProcessNames[ProcessIndex],ProcessIndex))
	{
		Sleep(1000);
		return TRUE;
	}
	else
	{
		/*long nError = GetLastError();
		TCHAR pTemp[256];
		swprintf(pTemp, _T("Failed to start program '%s', error code = %d\n"), ProcessNames[ProcessIndex], nError);
		WriteLog(pLogFile, pTemp);*/
		return FALSE;
	}
}


VOID EndProcess(int ProcessIndex)
{
	if (ProcessIndex >= 0 && ProcessIndex <= MAX_NUM_OF_PROCESS)
	{
		if (pProcInfo[ProcessIndex].hProcess)
		{
			// post a WM_QUIT message first
			PostThreadMessage(pProcInfo[ProcessIndex].dwThreadId, WM_QUIT, 0, 0);
			Sleep(1000);
			// terminate the process by force
			TerminateProcess(pProcInfo[ProcessIndex].hProcess, 0);
		}
	}
}
VOID ProcMonitorThread(VOID *)
{
	while (ProcessStarted == TRUE)
	{
		DWORD dwCode;
		for (int iLoop = 0; iLoop < MAX_NUM_OF_PROCESS; iLoop++)
		{
			if (::GetExitCodeProcess(pProcInfo[iLoop].hProcess, &dwCode) && pProcInfo[iLoop].hProcess != NULL)
			{
				if (dwCode != STILL_ACTIVE)
				{
					if (StartProcess(iLoop))
					{
						/*TCHAR pTemp[121];
						swprintf(pTemp, _T("Restarted process %d\n"), iLoop);
						WriteLog(pLogFile, pTemp);*/
					}
				}
			}
			Sleep(1);
		}
	}
}


BOOL RunService(TCHAR* pName)
{
	// run service with given name
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == 0)
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("OpenSCManager failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
	else
	{
		// open the service
		SC_HANDLE schService = OpenService(schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService == 0)
		{
			/*long nError = GetLastError();
			TCHAR pTemp[121];
			swprintf(pTemp, _T("OpenService failed, error code = %d\n"), nError);
			WriteLog(pLogFile, pTemp);*/
		}
		else
		{
			// call StartService to run the service
			if (StartService(schService, 0, (const TCHAR**)NULL))
			{
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return TRUE;
			}
			else
			{
				/*long nError = GetLastError();
				TCHAR pTemp[121];
				swprintf(pTemp, _T("StartService failed, error code = %d\n"), nError);
				WriteLog(pLogFile, pTemp);*/
			}
			CloseServiceHandle(schService);
		}
		CloseServiceHandle(schSCManager);
	}
	return FALSE;
}


VOID ExecuteSubProcess()
{
	if (_beginthread(ProcMonitorThread, 0, NULL) == -1)
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("StartService failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
	if (!StartServiceCtrlDispatcher(lpServiceStartTable))
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("StartServiceCtrlDispatcher failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
	::DeleteCriticalSection(&myCS);
}



BOOL KillService(TCHAR* pName)
{
	// kill service with given name
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == 0)
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("OpewnSCManager failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
	else
	{
		// open the service
		SC_HANDLE schService = OpenService(schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService == 0)
		{
			/*long nError = GetLastError();
			TCHAR pTemp[121];
			swprintf(pTemp, _T("OpenService failed, error code = %d\n"), nError);
			WriteLog(pLogFile, pTemp);*/
		}
		else
		{
			// call ControlService to kill the given service
			SERVICE_STATUS status;
			if (ControlService(schService, SERVICE_CONTROL_STOP, &status))
			{
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return TRUE;
			}
			else
			{
				/*long nError = GetLastError();
				TCHAR pTemp[121];
				swprintf(pTemp, _T("ControlService failed, error code = %d\n"), nError);
				WriteLog(pLogFile, pTemp);*/
			}
			CloseServiceHandle(schService);
		}
		CloseServiceHandle(schSCManager);
	}
	return FALSE;
}


VOID UnInstall(TCHAR* pName)
{
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == 0)
	{
		/*long nError = GetLastError();
		TCHAR pTemp[121];
		swprintf(pTemp, _T("OpenSCManager failed, error code = %d\n"), nError);
		WriteLog(pLogFile, pTemp);*/
	}
	else
	{
		SC_HANDLE schService = OpenService(schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService == 0)
		{
			/*long nError = GetLastError();
			TCHAR pTemp[121];
			swprintf(pTemp, _T("OpenService failed, error code = %d\n"), nError);
			WriteLog(pLogFile, pTemp);*/
		}
		else
		{
			if (!DeleteService(schService))
			{
				/*TCHAR pTemp[121];
				swprintf(pTemp, _T("Failed to delete service %s\n"), pName);
				WriteLog(pLogFile, pTemp);*/
			}
			else
			{
				/*TCHAR pTemp[121];
				swprintf(pTemp, _T("Service %s removed\n"), pName);
				WriteLog(pLogFile, pTemp);*/
			}
			CloseServiceHandle(schService);
		}
		CloseServiceHandle(schSCManager);
	}
	DeleteFile(pLogFile);
}





BOOL Is64BitOS()
{
	typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(__out LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandleW(L"kernel32"), "GetNativeSystemInfo");
	if (fnGetNativeSystemInfo)
	{
		SYSTEM_INFO stInfo = { 0 };
		fnGetNativeSystemInfo(&stInfo);
		if (stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
			|| stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			return TRUE;
		}
	}
	return FALSE;
}



/**
*  创建进程
*  @param process_name 进程名
*/
//int create_process(TCHAR* process_name, LPPROCESS_INFORMATION process, int is_run_with_create)
BOOL CREATEPROCESS(TCHAR* process_name,int processIndex)
{



	HANDLE hToken = NULL;
	HANDLE hTokenDup = NULL;
	BOOL errRet = TRUE;
	//TCHAR expName[20] = _T("explorer.exe");

	if (_tcscmp(process_name, _T("")) == 0)
    {
		return FALSE;
	}

	do
	{   
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
		{
			if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &hTokenDup))
			{
				STARTUPINFO si;

				PROCESS_INFORMATION pi;
				ZeroMemory(&pi, sizeof(pi));
				LPVOID pEnv = NULL;
				DWORD dwSessionId = WTSGetActiveConsoleSessionId();

				ZeroMemory(&si, sizeof(STARTUPINFO));



				if (!SetTokenInformation(hTokenDup, TokenSessionId, &dwSessionId, sizeof(DWORD)))
				{
                    errRet = FALSE;
					break;
				}


				si.cb = sizeof(STARTUPINFO);
				si.lpDesktop = _T("WinSta0\\Default");
				si.wShowWindow = SW_SHOW;
				si.dwFlags = STARTF_USESHOWWINDOW /*|STARTF_USESTDHANDLES*/;


				if (!CreateEnvironmentBlock(&pEnv, hTokenDup, FALSE))
				{
                    errRet = FALSE;
					break;
				}
				
				if (!CreateProcessAsUser(hTokenDup, process_name, NULL, NULL, NULL, FALSE,
					NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                    pEnv, NULL, &si,&pProcInfo[processIndex]))
				{

                    errRet = FALSE;
					break;
				}

				if (pEnv)
				{
					DestroyEnvironmentBlock(pEnv);
				}
                
			}
			else
			{
				break;
			}


		}
		else
		{

			errRet = TRUE;
			break;
		}
	} while (0);

	if (hTokenDup != NULL && hTokenDup != INVALID_HANDLE_VALUE)
		CloseHandle(hTokenDup);
	if (hToken != NULL && hToken != INVALID_HANDLE_VALUE)
		CloseHandle(hToken);


	return errRet;
}



DWORD GetProcessIDFromName(TCHAR *name)
{
	HANDLE snapshot;
	PROCESSENTRY32   processinfo;
	processinfo.dwSize = sizeof(processinfo);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == NULL)
		return FALSE;

	BOOL status = Process32First(snapshot, &processinfo);
	while (status)
	{
		if (_tcsicmp(name, processinfo.szExeFile) == 0)
			return processinfo.th32ProcessID;
		status = Process32Next(snapshot, &processinfo);
	}
	return -1;
}


HANDLE GetProcessHandle(TCHAR *processname)
{
	if (processname == NULL)
	{
		return NULL;
	}

	HANDLE proc = NULL;
	PROCESSENTRY32 pe;
	DWORD id = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapshot, &pe))
		return NULL;
	while (1)
	{
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32Next(hSnapshot, &pe) == FALSE)
			break;
		if (lstrcmpi(pe.szExeFile, processname) == 0)
		{
			id = pe.th32ProcessID;
			break;
		}
	}
	CloseHandle(hSnapshot);
	if (id != 0)
	{
		proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
	}

	return proc;
}
