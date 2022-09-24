// 密钥杂凑消息鉴别码HMAC。
// 按GB-T 15852.2-2012执行。

#include "HMAC_SM3.h"

#include <stdexcept>

#include "SM3.h"
#include "Util.h"

namespace yySimpleCute
{
std::vector<bool> HMAC_SM3::DoHMAC(const std::vector<bool> &K, const std::vector<bool> &D, std::size_t m)
{
	std::size_t k = K.size();
	// <GB-T 32905-2016> [5 算法描述] [5.3 迭代压缩] [5.3.1 迭代过程] 将填充后的消息m'按512比特进行分组
	const std::size_t L1 = 512;
	// <GB-T 32905-2016> [5 算法描述] [5.4 输出杂凑值] 输出256比特的杂凑值
	const std::size_t L2 = 256;
#if 0
	// [7 MAC算法2]
	if (k < L2 || k > L1)
		throw std::invalid_argument(__func__);
#endif

	// [7 MAC算法2] [7.1 MAC算法2的描述] [7.1.1 密钥扩展]
	auto EK(K);
#if 1
	// <GM-T 0091-2020> [附录A] [A.2 伪随机函数]
	// HMAC-SM3对密钥长度没有限制，但当密钥长度大于256位时，HMAC-SM3把它杂凑到256位。
	// FIXME: 标准可能有误（大于512位？）
	if (k > L1)
	{
		EK = array_uint32_t_N_to_vector_bool<L2 / 32>(SM3::DoHash(K));
		k = L2;
	}
#endif
	for (std::size_t i = 0; i < L1 - k; ++i)
		EK.push_back(0);
	const std::uint8_t IPAD = 0x36;
	const std::uint8_t OPAD = 0x5C;
	auto EK1(EK), EK2(EK);
	for (std::size_t i = 0; i < L1; ++i)
	{
		EK1[i] = EK1[i] ^ !!(IPAD & (1 << (7 - i % 8)));
		EK2[i] = EK2[i] ^ !!(OPAD & (1 << (7 - i % 8)));
	}

	// [7 MAC算法2] [7.1 MAC算法2的描述] [7.1.2 杂凑操作]
	auto v1(EK1);
	v1.insert(v1.end(), D.begin(), D.end());
	auto H_ = array_uint32_t_N_to_vector_bool(SM3::DoHash(v1));
	// [7 MAC算法2] [7.1 MAC算法2的描述] [7.1.3 输出变换]
	auto v2(EK2);
	v2.insert(v2.end(), H_.begin(), H_.end());
	auto H__ = array_uint32_t_N_to_vector_bool(SM3::DoHash(v2));
	// [7 MAC算法2] [7.1 MAC算法2的描述] [7.1.4 截断操作]
	return std::vector<bool>(H__.begin(), H__.begin() + m);
}
} // namespace yySimpleCute

// 测试
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
	auto u = vector_bool_to_array_uint32_t_N<8>(HMAC_SM3::DoHMAC(k, v));
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
