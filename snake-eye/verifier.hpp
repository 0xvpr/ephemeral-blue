#ifndef   VERIFIER_HEADER
#define   VERIFIER_HEADER

#include <filesystem>

namespace verifier {

bool is_verified_digital_sigature(const std::filesystem::path& file_path);

} // namespace verifier

#endif // VERIFIER_HEADER
