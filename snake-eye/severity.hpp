#ifndef   SEVERITY_HEADER
#define   SEVERITY_HEADER

#include <type_traits>
#include <cstdint>

namespace severity {

namespace flags {

enum flag_t : std::uint64_t {
    none                = 0ull,
    
    // File-based checks
    digest_mismatch     = 1ull << 0,
    hash_mismatch       = 1ull << 1,
    known_bad_hash      = 1ull << 2,

    // Signature-based checks
    signature_missing   = 1ull << 3,
    signature_invalid   = 1ull << 4,
    untrusted_publisher = 1ull << 5,
    
    // Path-based checks
    suspicious_path     = 1ull << 6,
    non_windows_path    = 1ull << 7,
    
    // Behavioural-based checks
    abnormal_process    = 1ull << 8,
    not_in_whitelist    = 1ull << 9,
    
    // Critical flags
    kernel_threat       = 1ull << 63
};

inline flag_t operator | (flag_t lhs, flag_t rhs)
{
    return static_cast<flag_t>(
        static_cast<std::underlying_type_t<flag_t>>(lhs) |
        static_cast<std::underlying_type_t<flag_t>>(rhs)
    );
}

inline flag_t& operator |= (flag_t& lhs, flag_t rhs)
{
    lhs = lhs | rhs;

    return lhs;
}

inline bool operator & (flag_t lhs, flag_t rhs)
{
    return (
        static_cast<std::underlying_type_t<flag_t>>(lhs) &
        static_cast<std::underlying_type_t<flag_t>>(rhs)
    ) != 0;
}

} // namespace flags

namespace threshold {
    enum threshold_t : std::uint64_t {
        none     = 0,
        low      = 1,
        medium   = 2,
        high     = 3,
        critical = 5
    };
} // namespace threshold

} // namespace severity

#endif // SEVERITY_HEADER
