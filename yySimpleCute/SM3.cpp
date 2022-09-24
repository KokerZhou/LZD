// SM3密码杂凑算法。
// 按GB-T 32905-2016执行。

#include "SM3.h"

#include <bitset>
#include <stdexcept>

namespace yySimpleCute
{
// [3 符号] 32比特循环左移k比特运算
inline std::uint32_t SM3::RotateLeft(std::uint32_t x, std::uint32_t k)
{
	return (x << (k % 32)) | (x >> (32 - (k % 32)));
}

// [4 常数与函数] [4.1 初始值]
const std::array<std::uint32_t, 8> SM3::IV{0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
										   0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};
// [4 常数与函数] [4.2 常量]
inline std::uint32_t SM3::Tj(std::uint32_t j)
{
	if (j < 16)
		return 0x79cc4519;
	else if (j < 64)
		return 0x7a879d8a;
	else
		throw std::out_of_range(__func__);
}
// [4 常数与函数] [4.3 布尔函数]
inline std::uint32_t SM3::FFj(std::uint32_t j, std::uint32_t X, std::uint32_t Y, std::uint32_t Z)
{
	if (j < 16)
		return X ^ Y ^ Z;
	else if (j < 64)
		return (X & Y) | (X & Z) | (Y & Z);
	else
		throw std::out_of_range(__func__);
}
inline std::uint32_t SM3::GGj(std::uint32_t j, std::uint32_t X, std::uint32_t Y, std::uint32_t Z)
{
	if (j < 16)
		return X ^ Y ^ Z;
	else if (j < 64)
		return (X & Y) | (~X & Z);
	else
		throw std::out_of_range(__func__);
}
// [4 常数与函数] [4.4 置换函数]
inline std::uint32_t SM3::P0(std::uint32_t X)
{
	return X ^ RotateLeft(X, 9) ^ RotateLeft(X, 17);
}
inline std::uint32_t SM3::P1(std::uint32_t X)
{
	return X ^ RotateLeft(X, 15) ^ RotateLeft(X, 23);
}

// [5 算法描述] [5.2 填充]
std::vector<bool> SM3::Fill(const std::vector<bool> &m)
{
	std::size_t l = m.size();
	auto m_ = m;
	m_.push_back(1);
	for (std::size_t k = 0; (l + 1 + k) % 512 != 448; ++k)
		m_.push_back(0);

	std::bitset<64> bitl(l);
	for (std::size_t i = 0; i < 64; ++i)
		m_.push_back(bitl[63 - i]);

	return m_;
}
// [5 算法描述] [5.3 迭代压缩] [5.3.1 迭代过程]
std::array<std::uint32_t, 8> SM3::Iterate(const std::vector<bool> &m_)
{
	std::size_t n = m_.size() / 512;
	auto V = IV;
	for (std::size_t i = 0; i < n; ++i)
	{
		std::array<std::uint32_t, 16> B{};
		for (std::size_t j = 0; j < 16; ++j)
		{
			for (std::size_t k = 0; k < 32; ++k)
			{
				B[j] |= m_[i * 512 + j * 32 + k] << (31 - k);
			}
		}
		V = CF(V, B);
	}
	return V;
}
// [5 算法描述] [5.3 迭代压缩] [5.3.3 压缩函数]
std::array<std::uint32_t, 8> SM3::CF(const std::array<std::uint32_t, 8> &V_i, const std::array<std::uint32_t, 16> &B_i)
{
	auto A = V_i[0], B = V_i[1], C = V_i[2], D = V_i[3], E = V_i[4], F = V_i[5], G = V_i[6], H = V_i[7];

	// [5 算法描述] [5.3 迭代压缩] [5.3.2 消息扩展]
	std::array<std::uint32_t, 68> W{};
	std::array<std::uint32_t, 64> W_{};
	for (std::size_t j = 0; j < 16; ++j)
		W[j] = B_i[j];
	for (std::size_t j = 16; j < 68; ++j)
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ RotateLeft(W[j - 3], 15)) ^ RotateLeft(W[j - 13], 7) ^ W[j - 6];
	for (std::size_t j = 0; j < 64; ++j)
		W_[j] = W[j] ^ W[j + 4];

	for (std::size_t j = 0; j < 64; ++j)
	{
		std::uint32_t SS1 = RotateLeft(RotateLeft(A, 12) + E + RotateLeft(Tj(j), j), 7);
		std::uint32_t SS2 = SS1 ^ RotateLeft(A, 12);
		std::uint32_t TT1 = FFj(j, A, B, C) + D + SS2 + W_[j];
		std::uint32_t TT2 = GGj(j, E, F, G) + H + SS1 + W[j];
		D = C;
		C = RotateLeft(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = RotateLeft(F, 19);
		F = E;
		E = P0(TT2);
	}
	return {V_i[0] ^ A, V_i[1] ^ B, V_i[2] ^ C, V_i[3] ^ D, V_i[4] ^ E, V_i[5] ^ F, V_i[6] ^ G, V_i[7] ^ H};
}

std::array<std::uint32_t, 8> SM3::DoHash(const std::vector<bool> &m)
{
	// [5 算法描述] [5.1 概述]
	return Iterate(Fill(m));
}
} // namespace yySimpleCute

// 测试
#if 0

#include <iostream>

#include "Util.h"

int main(int argc, const char *argv[])
{
	using namespace yySimpleCute;
	unsigned char buf[]{'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd',
						'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd',
						'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd',
						'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd'};
	std::vector<bool> v = szunsigned_char_to_vector_bool(buf);

	std::cout.fill('0');
	for (auto i : SM3::DoHash(v))
	{
		std::cout.width(8);
		std::cout << std::hex << i;
		std::cout << " ";
	}
	std::cout << std::endl;
	return 0;
}
#endif
