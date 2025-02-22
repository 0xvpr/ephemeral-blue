#ifdef UNICODE
#undef UNICODE
#endif
#ifdef _UNICODE
#undef _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include <filesystem>
#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <ranges>

std::string to_lower(std::string s) {
    std::ranges::transform( s,
                            s.begin(),
                            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

/* [[deprecated("make additional changes to use a whitelist vector.")]] */
bool is_in_system_directory(const std::filesystem::path& module_path)
{
    std::string lower_parent_path = to_lower(module_path.parent_path().string());
    if (lower_parent_path.starts_with("c:\\windows\\system32") ||
        lower_parent_path.starts_with("c:\\windows\\syswow64"))
    {
        return true;
    }

    return false;
}

bool is_verified_digital_sigature(const std::filesystem::path& file_path)
{
    if (file_path.empty()) {
        return false;
    }

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    std::size_t w_file_path_size = file_path.string().size()+1;
    auto w_file_path = std::make_unique<wchar_t *>( new wchar_t[w_file_path_size] );
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, *w_file_path, w_file_path_size, file_path.string().c_str(), _TRUNCATE);

//  // DEBUG
//  std::cout  << file_path << ":";
//  std::wcout << *w_file_path << "\n";

    WINTRUST_FILE_INFO fileData{};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = *w_file_path;
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    WINTRUST_DATA win_trust_data{};
    win_trust_data.cbStruct = sizeof(win_trust_data);
    win_trust_data.dwUIChoice = WTD_UI_NONE;
    win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    win_trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    win_trust_data.pFile = &fileData;
    win_trust_data.dwStateAction = WTD_STATEACTION_IGNORE;
    win_trust_data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    auto result = WinVerifyTrust( static_cast<HWND>(INVALID_HANDLE_VALUE), 
                                  &policy_guid, 
                                  &win_trust_data );

    return (result == ERROR_SUCCESS);
}

int main(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    HANDLE process_handle_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if ( process_handle_snapshot == INVALID_HANDLE_VALUE ) {
        std::cerr << "CreateToolhelp32Snapshot (process) failed.\n";
        return 1;
    }

    PROCESSENTRY32 process_entry32{};
    process_entry32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve the first process entry
    if ( !Process32First(process_handle_snapshot, &process_entry32 )) {
        std::cerr << "Process32FirstA failed.\n";
        CloseHandle(process_handle_snapshot);
        return 1;
    }

    do {
        DWORD process_id = process_entry32.th32ProcessID;
        std::string process_name( process_entry32.szExeFile );

        if ( !process_id ) {
            continue;
        }

        HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
        if (process_handle == nullptr) {
            continue;
        }

        HANDLE module_handle_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
        if (module_handle_snapshot == INVALID_HANDLE_VALUE) {
            CloseHandle(process_handle);
            continue;
        }

        MODULEENTRY32 module_entry32{};
        module_entry32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(module_handle_snapshot, &module_entry32)) {
            do {
                std::filesystem::path module_path (module_entry32.szExePath);
                std::string module_name = module_entry32.szModule;

                // Check if path exists?

                // Check if module has a verified signature
                if (!is_in_system_directory(module_path) && !is_verified_digital_sigature(module_path)) {
                    std::cout << "[SUSPICIOUS DLL] Process: " << process_name << " (PID:  " << process_id << ")\n"
                                 "                 Module:  " << module_name  << " (Path: " << module_path << ")\n";
                }
            } while (Module32Next(module_handle_snapshot, &module_entry32));
        }

        CloseHandle(module_handle_snapshot);
        CloseHandle(process_handle);

    } while (Process32Next(process_handle_snapshot, &process_entry32));

    CloseHandle(process_handle_snapshot);

    std::cout << "DLL injection detection scan complete.\n";
    return 0;
}
