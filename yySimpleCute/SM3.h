// SM3密码杂凑算法。
// 按GB-T 32905-2016执行。

#ifndef SM3_h
#define SM3_h

#include <array>
#include <cstdint>
#include <vector>

namespace yySimpleCute
{
class SM3
{
private:
	// [3 符号] 32比特循环左移k比特运算
	static inline std::uint32_t RotateLeft(std::uint32_t x, std::uint32_t k);

	// [4 常数与函数] [4.1 初始值]
	static const std::array<std::uint32_t, 8> IV;
	// [4 常数与函数] [4.2 常量]
	static inline std::uint32_t Tj(std::uint32_t j);
	// [4 常数与函数] [4.3 布尔函数]
	static inline std::uint32_t FFj(std::uint32_t j, std::uint32_t X, std::uint32_t Y, std::uint32_t Z);
	static inline std::uint32_t GGj(std::uint32_t j, std::uint32_t X, std::uint32_t Y, std::uint32_t Z);
	// [4 常数与函数] [4.4 置换函数]
	static inline std::uint32_t P0(std::uint32_t X);
	static inline std::uint32_t P1(std::uint32_t X);

	// [5 算法描述] [5.2 填充]
	static std::vector<bool> Fill(const std::vector<bool> &m);
	// [5 算法描述] [5.3 迭代压缩] [5.3.1 迭代过程]
	static std::array<std::uint32_t, 8> Iterate(const std::vector<bool> &m_);
	// [5 算法描述] [5.3 迭代压缩] [5.3.3 压缩函数]
	static std::array<std::uint32_t, 8> CF(const std::array<std::uint32_t, 8> &V_i,
										   const std::array<std::uint32_t, 16> &B_i);

public:
	static std::array<std::uint32_t, 8> DoHash(const std::vector<bool> &m);
};
} // namespace yySimpleCute
#endif
