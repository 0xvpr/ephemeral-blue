#ifdef    UNICODE
#undef    UNICODE
#endif
#ifdef    _UNICODE
#undef    _UNICODE
#endif

#include  "severity.hpp"
#include  "verifier.hpp"
#include  "utility.hpp"

#ifndef   WIN32_LEAN_AND_MEAN
#define   WIN32_LEAN_AND_MEAN
#include  <windows.h>
#include  <tlhelp32.h>
#endif // WIN32_LEAN_AND_MEAN

#include  <iostream>
#include  <memory>

struct entry_t {
    std::string process_name;
    DWORD       process_id; 
    std::string module_name;
    std::string module_path; 
};

/* [[deprecated("make additional changes to use a whitelist vector.")]] */
bool is_in_system_directory(const std::filesystem::path& module_path)
{
    std::string lower_parent_path = utility::to_lower(module_path.parent_path().string());
    if (lower_parent_path.starts_with("c:\\windows\\system32") ||
        lower_parent_path.starts_with("c:\\windows\\syswow64"))
    {
        return true;
    }

    return false;
}

bool check_process(auto module_path, severity::flags::flag_t flags) {
    if (!is_in_system_directory(module_path))
        flags |= severity::flags::non_windows_path;
    if (!verifier::is_verified_digital_sigature(module_path))
        flags |= severity::flags::signature_invalid;

    return true;
}

severity::threshold::threshold_t calculcate_score(severity::flags::flag_t flags) {
    using severity::flags::abnormal_process;
    using severity::flags::kernel_threat;
    using severity::flags::known_bad_hash;

    if (flags & (known_bad_hash | kernel_threat | abnormal_process))
        return severity::threshold::high;
    
    return severity::threshold::none;
}

int main(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    auto threshold = severity::threshold::high;

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

    std::vector<entry_t> suspicious_entries;
    suspicious_entries.reserve(4096);

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

                // Perform all checks
                severity::flags::flag_t flags{};
                check_process(module_path, flags);
                auto score = calculcate_score(flags);

                // Check if module has a verified signature
                if (score >= threshold) {
                    suspicious_entries.emplace_back(process_name, process_id, module_name, module_path.string());
                }
            } while (Module32Next(module_handle_snapshot, &module_entry32));
        }

        CloseHandle(module_handle_snapshot);
        CloseHandle(process_handle);

    } while (Process32Next(process_handle_snapshot, &process_entry32));

    CloseHandle(process_handle_snapshot);

    for (const auto& entry : suspicious_entries) {
        std::cout << "[SUSPICIOUS DLL] Process: " << entry.process_name << " (PID:  " << entry.process_id << ")\n"
                     "                 Module:  " << entry.module_name  << " (Path: " << entry.module_path << ")\n";
    }

    std::cout << "DLL injection detection scan complete.\n";
    return 0;
}
