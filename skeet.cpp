#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <fstream>
#include <filesystem>
#include <regex>

namespace {
    std::string StartSteam() {
        HKEY hKey;
        char steamPath[MAX_PATH];
        DWORD steamPathSize = sizeof(steamPath);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
                return "";
            }
        }
        
        if (RegQueryValueExA(hKey, "InstallPath", nullptr, nullptr, reinterpret_cast<LPBYTE>(steamPath), &steamPathSize) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return "";
        }
        RegCloseKey(hKey);
        
        return steamPath;
    }

    std::string StartCSGO() {
        HKEY hKey;
        char steamPath[MAX_PATH];
        DWORD steamPathSize = sizeof(steamPath);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
                return "";
            }
        }
        
        if (RegQueryValueExA(hKey, "InstallPath", nullptr, nullptr, reinterpret_cast<LPBYTE>(steamPath), &steamPathSize) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return "";
        }
        RegCloseKey(hKey);

        std::filesystem::path vdfPath = std::filesystem::path(steamPath) / "steamapps" / "libraryfolders.vdf";
        std::ifstream vdfFile(vdfPath);
        if (!vdfFile.is_open()) {
            return "";
        }

        std::string line;
        std::vector<std::string> libraryPaths;
        libraryPaths.push_back(steamPath);

        while (std::getline(vdfFile, line)) {
            if (line.find("\"path\"") != std::string::npos) {
                std::regex pathRegex("\"path\"\\s+\"([^\"]+)\"");
                std::smatch match;
                if (std::regex_search(line, match, pathRegex)) {
                    libraryPaths.push_back(match[1].str());
                }
            }
        }

        for (const auto& libraryPath : libraryPaths) {
            std::filesystem::path csgoPath = std::filesystem::path(libraryPath) / "steamapps" / "common" / "Counter-Strike Global Offensive";
            if (std::filesystem::exists(csgoPath)) {
                return csgoPath.string();
            }
        }

        return "";
    }

    constexpr DWORD INVALID_PROCESS_ID = static_cast<DWORD>(-1);
    
    void SetConsoleColor(int color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }

    DWORD GetProcessByName(const char* processName) {
        PROCESSENTRY32 procEntry{};
        procEntry.dwSize = sizeof(procEntry);

        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return INVALID_PROCESS_ID;
        }

        if (Process32First(snapshot, &procEntry)) {
            do {
                if (lstrcmpA(procEntry.szExeFile, processName) == 0) {
                    CloseHandle(snapshot);
                    return procEntry.th32ProcessID;
                }
            } while (Process32Next(snapshot, &procEntry));
        }

        CloseHandle(snapshot);
        return INVALID_PROCESS_ID;
    }

    bool WaitForModules(DWORD processId) {
        while (true) {
            const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
            if (snapshot != INVALID_HANDLE_VALUE) {
                MODULEENTRY32 moduleEntry{};
                moduleEntry.dwSize = sizeof(moduleEntry);
                bool clientFound = false;
                bool engineFound = false;

                if (Module32First(snapshot, &moduleEntry)) {
                    do {
                        if (_stricmp(moduleEntry.szModule, "client.dll") == 0) clientFound = true;
                        if (_stricmp(moduleEntry.szModule, "engine.dll") == 0) engineFound = true;
                    } while (Module32Next(snapshot, &moduleEntry) && !(clientFound && engineFound));
                }
                CloseHandle(snapshot);
                
                if (clientFound && engineFound) {
                    return true;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

int main(const int argc, char* argv[]) {
    constexpr const char* DLL_NAME = "skeet.dll";
    constexpr const char* PROCESS_NAME = "csgo.exe";
    constexpr const char* STEAM_PROCESS = "steam.exe";
    char dllPath[MAX_PATH];

    SetConsoleColor(15);
    DWORD steamPid = GetProcessByName(STEAM_PROCESS);
    if (steamPid == INVALID_PROCESS_ID) {
        std::string steamPath = StartSteam();
        if (!steamPath.empty()) {
            std::string steamExePath = steamPath + "\\" + STEAM_PROCESS;
            
            if (GetFileAttributesA(steamExePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                STARTUPINFOA si = { sizeof(STARTUPINFOA) };
                PROCESS_INFORMATION pi;
                
                if (CreateProcessA(nullptr, const_cast<LPSTR>(steamExePath.c_str()), 
                    nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);

                    std::cout << "Waiting 15s for Steam to initialize...\n";
                    std::this_thread::sleep_for(std::chrono::seconds(15));
                }
            }
        } else {
            std::cout << "Failed to start Steam. Please start it manually.\n";
            return 1;
        }
    }

    std::string csgoPath = StartCSGO();
    if (!csgoPath.empty()) {
        std::string csgoExePath = csgoPath + "\\" + PROCESS_NAME;
        
        if (GetFileAttributesA(csgoExePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            STARTUPINFOA si = { sizeof(STARTUPINFOA) };
            PROCESS_INFORMATION pi;
            
            std::string cmdLine = "\"" + csgoExePath + "\" -steam -insecure";
            
            if (CreateProcessA(nullptr, const_cast<LPSTR>(cmdLine.c_str()), 
                nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
    } else {
        std::cout << "Open CSGO.\n";
    }

    if (!GetFullPathNameA(DLL_NAME, MAX_PATH, dllPath, nullptr)) {
        std::cout << "Failed to get full path of the DLL.\n";
        return 1;
    }

    const DWORD fileAttribs = GetFileAttributesA(dllPath);
    if (fileAttribs == INVALID_FILE_ATTRIBUTES) {
        std::cout << "Could not find skeet.dll\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    if (!(fileAttribs & FILE_ATTRIBUTE_NORMAL) && (fileAttribs & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cout << "The specified path is a directory, not a DLL file.\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    const HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        const DWORD fileSize = GetFileSize(hFile, nullptr);
        CloseHandle(hFile);
        
        if (fileSize != INVALID_FILE_SIZE && fileSize < 9961472) {
            std::cout << "DLL appears to be invalid or corrupted\n";
            std::this_thread::sleep_for(std::chrono::seconds(3));
            return 1;
        }
    }

    std::cout << "PUP$ORE LIKES DICK!!!!!! (afterworld wuz here >_<)\n\n";

    DWORD processId = INVALID_PROCESS_ID;
    while ((processId = GetProcessByName(PROCESS_NAME)) == INVALID_PROCESS_ID) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "Process ID: " << processId << "\n\n";
    std::cout << "Waiting for game modules to load...\n";

    if (WaitForModules(processId)) {
        std::cout << "Modules found, waiting 7 seconds before injecting...\n\n";
        std::this_thread::sleep_for(std::chrono::seconds(7));
    }

    const HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cout << "Failed to open target process.\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    std::cout << "Opened handle to process successfully\n";

    VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(0x43310000), 0x2FC000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    VirtualAllocEx(hProcess, nullptr, 0x1000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    const LPVOID pathAddr = VirtualAllocEx(hProcess, nullptr, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pathAddr) {
        std::cout << "Failed to allocate memory in target process.\n";
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    std::cout << "Memory allocated at 0x" << std::hex << reinterpret_cast<DWORD>(pathAddr) << std::dec << '\n';

    if (!WriteProcessMemory(hProcess, pathAddr, dllPath, strlen(dllPath) + 1, nullptr)) {
        std::cout << "Failed to write DLL path to process memory.\n";
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    std::cout << "DLL path written successfully.\n";

    const HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cout << "Failed to get kernel32.dll handle.\n";
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    const FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLibraryAddr) {
        std::cout << "Failed to get LoadLibraryA address.\n";
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    std::cout << "LoadLibraryA address at 0x" << std::hex << reinterpret_cast<DWORD>(loadLibraryAddr) << std::dec << '\n';

    const HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr), pathAddr, 0, nullptr);
    
    if (!hThread) {
        std::cout << "Failed to create remote thread.\n";
        CloseHandle(hProcess);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    DWORD exitCode = 0;
    WaitForSingleObject(hThread, INFINITE);
    if (GetExitCodeThread(hThread, &exitCode)) {
        std::cout << "DLL Injected! Return status: 0x" << std::hex << exitCode << std::dec << '\n';
    } else {
        std::cout << "DLL Injected but failed to get return status (Error: " << GetLastError() << ")\n";
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    std::this_thread::sleep_for(std::chrono::seconds(3));

    return 0;
}