// 基于口令的密钥派生函数PBKDF。
// 按GM-T 0091-2020执行。
#include "PBKDF_HMAC_SM3.h"

#include <stdexcept>

#include "HMAC_SM3.h"
#include "Util.h"

namespace yySimpleCute
{
std::vector<bool> PBKDF_HMAC_SM3::F(const std::vector<bool> &P, const std::vector<bool> &S, std::uint32_t C,
									std::size_t i)
{
	// [附录A] [A.2 伪随机函数] HMAC-SM3为基于SM3密码杂凑算法计算消息鉴别码的函数，可作为一个PRF使用。
	// 与计算HMAC相同，该PRF的第一个参数用作HMAC的“密钥”，第二个参数用作HMAC的“明文”，输出为杂凑值的全部长度。
	// 在本文件的PBKDF中，“密钥”就是口令，而“明文”就是盐值。HMAC-SM3的密钥长度可变，输出长度为32字节（256位）。

	// [6 基于口令的密钥派生函数] c)
	auto v(S);
	for (std::size_t j = 0; j < 32; ++j)
		v.push_back(i & (1 << (31 - j)));

	auto Ui = HMAC_SM3::DoHMAC(P, v), U(Ui);
	for (std::uint32_t j = 0; j < C - 1; ++j)
	{
		Ui = HMAC_SM3::DoHMAC(P, Ui);
		for (std::size_t k = 0; k < Ui.size(); ++k)
			U[k] = U[k] ^ Ui[k];
	}
	return U;
}

std::vector<bool> PBKDF_HMAC_SM3::DoPBKDF(const std::vector<bool> &P, const std::vector<bool> &S, std::uint32_t c,
										  std::size_t dkLen)
{
	// [4 符号和缩略语] 伪随机函数输出的字节数，正整数。
	const std::size_t hLen = 32;
	// [6 基于口令的密钥派生函数] a)
	if (dkLen > ((1ULL << 32) - 1) * hLen)
		throw std::invalid_argument(__func__);
	// [6 基于口令的密钥派生函数] b)
	std::size_t n = dkLen / hLen;

	// [6 基于口令的密钥派生函数] d)
	std::vector<bool> DK{};
	for (std::size_t i = 0; i < n; ++i)
	{
		auto Ti = F(P, S, c, i + 1);
		DK.insert(DK.end(), Ti.begin(), Ti.end());
	}
	return std::vector<bool>(DK.begin(), DK.begin() + dkLen * 8);
}
} // namespace yySimpleCute

#if 0

#include <iostream>

int main(int argc, const char *argv[])
{
	using namespace yySimpleCute;
	unsigned char buf[]{'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd',
						'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd',
						'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd',
						'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd'};
	std::vector<bool> v = szunsigned_char_to_vector_bool(buf);

	unsigned char key[]{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	std::vector<bool> k = szunsigned_char_to_vector_bool(key);

	std::cout.fill('0');
	auto u = vector_bool_to_array_uint32_t_N<32>(PBKDF_HMAC_SM3::DoPBKDF(v, k, 10000, 1024 / 8));
	for (auto i : u)
	{
		std::cout.width(8);
		std::cout << std::hex << i;
		std::cout << " ";
	}
	std::cout << std::endl;
	return 0;
}
#endif
