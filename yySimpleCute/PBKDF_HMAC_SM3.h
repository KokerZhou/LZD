// 基于口令的密钥派生函数PBKDF。
// 按GM-T 0091-2020执行。

#ifndef PBKDF_HMAC_SM3_h
#define PBKDF_HMAC_SM3_h

#include <cstdint>
#include <vector>

namespace yySimpleCute
{
class PBKDF_HMAC_SM3
{
private:
	static std::vector<bool> F(const std::vector<bool> &P, const std::vector<bool> &S, std::uint32_t C, std::size_t i);

public:
	static std::vector<bool> DoPBKDF(const std::vector<bool> &P, const std::vector<bool> &S, std::uint32_t c,
									 std::size_t dkLen);
};
} // namespace yySimpleCute
#endif
