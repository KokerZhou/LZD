#ifndef Util_h
#define Util_h

#include <array>
#include <bitset>
#include <stdexcept>
#include <vector>

namespace yySimpleCute
{
//        0000000000000000000000000000111100000000000000000000000000001010
//        ^      ^       ^       ^       ^       ^       ^       ^       ^
// bitset 63     56      48      40      32      24      16      8       0
// vector 0      7       15      23      31      39      47      55      63
// array  [0] | (<< 31)  [0] | (<< 16)           [1] | (<< 24)           [1] | (<< 0)
template <std::size_t N> std::bitset<N * 32> array_uint32_t_N_to_bitset_Nx32(const std::array<std::uint32_t, N> &a)
{
	std::bitset<N * 32> b;
	for (std::size_t i = 0; i < N; ++i)
	{
		std::bitset<32> bi(a[i]);
		for (std::size_t j = 0; j < 32; ++j)
			b[(N - 1 - i) * 32 + j] = bi[j];
	}
	return b;
}
template <std::size_t N> std::vector<bool> array_uint32_t_N_to_vector_bool(const std::array<std::uint32_t, N> &a)
{
	std::vector<bool> v(N * 32);
	for (std::size_t i = 0; i < N; ++i)
	{
		std::bitset<32> b(a[i]);
		for (std::size_t j = 0; j < 32; ++j)
			v[i * 32 + j] = b[31 - j];
	}
	return v;
}
template <std::size_t N> std::array<std::uint32_t, N> bitset_Nx32_to_array_uint32_t_N(const std::bitset<N * 32> &b)
{
	std::array<std::uint32_t, N> a{};
	for (std::size_t i = 0; i < N; ++i)
	{
		for (std::size_t j = 0; j < 32; ++j)
		{
			a[N - 1 - i] |= b[i * 32 + j] << j;
		}
	}
	return a;
}
template <std::size_t N> std::vector<bool> bitset_N_to_vector_bool(const std::bitset<N> &b)
{
	std::vector<bool> v(N);
	for (std::size_t i = 0; i < N; ++i)
		v[i] = b[N - 1 - i];
	return v;
}
template <std::size_t N> std::array<std::uint32_t, N> vector_bool_to_array_uint32_t_N(const std::vector<bool> &v)
{
	if (v.size() != N * 32)
		throw std::invalid_argument(__func__);
	std::array<std::uint32_t, N> a{};
	for (std::size_t i = 0; i < N; ++i)
	{
		for (std::size_t j = 0; j < 32; ++j)
		{
			a[i] |= v[i * 32 + j] << (31 - j);
		}
	}
	return a;
}
template <std::size_t N> std::bitset<N> vector_bool_to_bitset_N(const std::vector<bool> &v)
{
	if (v.size() != N)
		throw std::invalid_argument(__func__);
	std::bitset<N> b;
	for (std::size_t i = 0; i < N; ++i)
		b[i] = v[N - 1 - i];
	return b;
}

std::vector<bool> szunsigned_char_to_vector_bool(const unsigned char *buf, std::size_t N);
template <std::size_t N> std::vector<bool> szunsigned_char_to_vector_bool(const unsigned char (&buf)[N])
{
	return szunsigned_char_to_vector_bool(buf, N);
}
std::vector<bool> szchar_to_vector_bool(const char *buf, std::size_t N);
template <std::size_t N> std::vector<bool> szchar_to_vector_bool(const char (&buf)[N])
{
	return szchar_to_vector_bool(buf, N);
}
} // namespace yySimpleCute
#endif
