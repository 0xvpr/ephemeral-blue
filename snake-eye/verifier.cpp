#include  "verifier.hpp"

#include  "windows.h"
#include  "wincrypt.h"
#include  "wintrust.h"
#include  "softpub.h"

bool verifier::is_verified_digital_sigature(const std::filesystem::path& file_path)
{
    if (file_path.empty()) {
        return false;
    }

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    std::size_t w_file_path_size = file_path.string().size()+1;
    auto w_file_path = std::make_unique<wchar_t *>( new wchar_t[w_file_path_size] );
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, *w_file_path, w_file_path_size, file_path.string().c_str(), _TRUNCATE);

#ifdef    DEBUG
    std::cout  << file_path << ":";
    std::wcout << *w_file_path << "\n";
#endif // DEBUG

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

