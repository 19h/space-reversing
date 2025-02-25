#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>

void printUsage(const char* programName) {
    printf("Usage: %s -l <comma_separated_dll_list> -- <executable> [arguments]\n", programName);
}

BOOL injectDLL(HANDLE hProcess, const char* dllPath) {
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory) return FALSE;

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
    if (!hRemoteThread) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    return TRUE;
}

int main(int argc, char* argv[]) {
    // Debug output
    printf("argc: %d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i] ? argv[i] : "NULL");
    }

    if (argc < 5 || strcmp(argv[1], "-l") != 0 || strcmp(argv[3], "--") != 0) {
        printUsage(argv[0]);
        return 1;
    }

    char* dllList = argv[2];
    char* dlls[64];
    int dllCount = 0;
    char* token = strtok(dllList, ",");
    while (token && dllCount < 64) {
        dlls[dllCount++] = token;
        token = strtok(NULL, ",");
    }

    char commandLine[1024] = {0};
    strncpy(commandLine, argv[4], sizeof(commandLine) - 1);
    for (int i = 5; i < argc; i++) {
        strncat(commandLine, " ", sizeof(commandLine) - strlen(commandLine) - 1);
        strncat(commandLine, argv[i], sizeof(commandLine) - strlen(commandLine) - 1);
    }

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Create new environment block with additional variable
    char* currentEnv = GetEnvironmentStrings();
    size_t envSize = 0;
    char* envPtr = currentEnv;
    while (*envPtr) {
        envSize += strlen(envPtr) + 1;
        envPtr += strlen(envPtr) + 1;
    }
    
    // Allocate new environment block with extra space
    char* newEnv = (char*)malloc(envSize + 32); // Extra space for new variable
    if (!newEnv) {
        FreeEnvironmentStrings(currentEnv);
        return 1;
    }
    
    // Copy existing environment and add new variable
    memcpy(newEnv, currentEnv, envSize);
    strcpy(newEnv + envSize, "EOS_USE_ANTICHEATCLIENTNULL=1");
    envSize += strlen("EOS_USE_ANTICHEATCLIENTNULL=1") + 1;
    newEnv[envSize] = '\0'; // Double null termination required
    
    if (!CreateProcess(NULL, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, 
                      newEnv,  // Use new environment block
                      NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        free(newEnv);
        FreeEnvironmentStrings(currentEnv);
        return 1;
    }
    
    free(newEnv);
    FreeEnvironmentStrings(currentEnv);

    for (int i = 0; i < dllCount; i++) {
        if (!injectDLL(pi.hProcess, dlls[i])) {
            printf("Failed to inject %s\n", dlls[i]);
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 1;
        }
        printf("Injected %s\n", dlls[i]);
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("Process started.\n");
    return 0;
}