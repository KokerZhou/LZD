// 杂凑——确定性随机比特生成器Hash_DRBG。
// 按NIST SP 800-90Ar1执行。

#include "Hash_DRBG_SM3.h"

#include <algorithm>
#include <bitset>
#include <stdexcept>

#include "SM3.h"
#include "Util.h"

namespace yySimpleCute
{

std::vector<bool> Hash_DRBG_SM3::add(const std::vector<bool> &lhs, const std::vector<bool> &rhs)
{
	std::size_t len = std::min(lhs.size(), rhs.size());
	auto reverse_lhs(lhs), reverse_rhs(rhs);
	std::reverse(reverse_lhs.begin(), reverse_lhs.end());
	std::reverse(reverse_rhs.begin(), reverse_rhs.end());
	std::vector<bool> ret{};
	std::size_t i = 0;
	bool f = 0;
	std::uint8_t t = 0;
	for (; i < len; ++i)
	{
		t = reverse_lhs[i] + reverse_rhs[i] + f;
		f = t >> 1;
		ret.push_back(t & 1);
	}
	for (; i < reverse_lhs.size(); ++i)
	{
		t = reverse_lhs[i] + f;
		f = t >> 1;
		ret.push_back(t & 1);
	}
	for (; i < reverse_rhs.size(); ++i)
	{
		t = reverse_rhs[i] + f;
		f = t >> 1;
		ret.push_back(t & 1);
	}
	if (f)
	{
		ret.push_back(1);
	}
	std::reverse(ret.begin(), ret.end());
	return ret;
}

// [10 DRBG Algorithm Specifications] [10.3 Auxiliary Functions]
// [10.3.1 Derivation Function Using a Hash Function (Hash_df)]
std::vector<bool> Hash_DRBG_SM3::Hash_df(const std::vector<bool> &input_string, std::size_t no_of_bits_to_return)
{
	std::vector<bool> temp{};
	std::size_t len = no_of_bits_to_return / outlen + !!(no_of_bits_to_return % outlen);
	std::uint8_t counter = 0x01;
	for (std::size_t i = 0; i < len; ++i)
	{
		std::vector<bool> v{};
		for (std::size_t j = 0; j < 8; ++j)
			v.push_back(counter & (1 << (7 - j)));
		for (std::size_t j = 0; j < 32; ++j)
			v.push_back(no_of_bits_to_return & (1 << (31 - j)));
		v.insert(v.end(), input_string.begin(), input_string.end());
		auto hash = array_uint32_t_N_to_vector_bool(SM3::DoHash(v));
		temp.insert(temp.end(), hash.begin(), hash.end());
		++counter;
	}
	return std::vector<bool>(temp.begin(), temp.begin() + no_of_bits_to_return);
}
std::vector<bool> Hash_DRBG_SM3::Hashgen(std::size_t requested_number_of_bits, const std::vector<bool> &V)
{
	std::size_t m = requested_number_of_bits / outlen + !!(requested_number_of_bits % outlen);
	auto data(V);
	std::vector<bool> W{};
	for (std::size_t i = 0; i < m; ++i)
	{
		auto w = array_uint32_t_N_to_vector_bool(SM3::DoHash(data));
		W.insert(W.end(), w.begin(), w.end());
		auto t = add(data, {1});
		if (t.size() > seedlen)
			t = std::vector<bool>(t.end() - seedlen, t.end());
		data = t;
	}
	return std::vector<bool>(W.begin(), W.begin() + requested_number_of_bits);
}

// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
// [10.1.1 Hash_DRBG] [10.1.1.2 Instantiation of Hash_DRBG]
void Hash_DRBG_SM3::Instantiate(const std::vector<bool> &entropy_input, const std::vector<bool> &nonce,
								const std::vector<bool> &personalization_string, std::uint32_t security_strength)
{
	auto seed_material(entropy_input);
	seed_material.insert(seed_material.end(), nonce.begin(), nonce.end());
	seed_material.insert(seed_material.end(), personalization_string.begin(), personalization_string.end());
	auto seed = Hash_df(seed_material, seedlen);
	V = seed;
	// Comment: Precede V with a byte of zeros.
	std::vector<bool> v{0, 0, 0, 0, 0, 0, 0, 0};
	v.insert(v.end(), V.begin(), V.end());
	C = Hash_df(v, seedlen);
	reseed_counter = 1;
}
// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
// [10.1.1 Hash_DRBG] [10.1.1.3 Reseeding a Hash_DRBG Instantiation]
void Hash_DRBG_SM3::Reseed(const std::vector<bool> &entropy_input, const std::vector<bool> &additional_input)
{
	std::vector<bool> seed_material{0, 0, 0, 0, 0, 0, 0, 1};
	seed_material.insert(seed_material.end(), V.begin(), V.end());
	seed_material.insert(seed_material.end(), entropy_input.begin(), entropy_input.end());
	seed_material.insert(seed_material.end(), additional_input.begin(), additional_input.end());
	auto seed = Hash_df(seed_material, seedlen);
	V = seed;
	// Comment: Preceed with a byte of all zeros.
	std::vector<bool> v{0, 0, 0, 0, 0, 0, 0, 0};
	v.insert(v.end(), V.begin(), V.end());
	C = Hash_df(v, seedlen);
	reseed_counter = 1;
}
// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
// [10.1.1 Hash_DRBG] [10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG]
std::vector<bool> Hash_DRBG_SM3::Generate(std::size_t requested_number_of_bits,
										  const std::vector<bool> &additional_input)
{
	// 1. If reseed_counter > reseed_interval, then return an indication that a reseed is required.
	if (reseed_counter > reseed_interval)
		throw std::runtime_error(__func__);
	if (additional_input.size() != 0)
	{
		std::vector<bool> v{0, 0, 0, 0, 0, 0, 1, 0};
		v.insert(v.end(), V.begin(), V.end());
		v.insert(v.end(), additional_input.begin(), additional_input.end());
		auto w = array_uint32_t_N_to_vector_bool(SM3::DoHash(v));
		auto t = add(V, w);
		if (t.size() > seedlen)
			t = std::vector<bool>(t.end() - seedlen, t.end());
		V = t;
	}
	auto returned_bits = Hashgen(requested_number_of_bits, V);
	std::vector<bool> v{0, 0, 0, 0, 0, 0, 1, 1};
	v.insert(v.end(), V.begin(), V.end());
	auto H = array_uint32_t_N_to_vector_bool(SM3::DoHash(v));
	auto t = add(add(add(V, H), C), bitset_N_to_vector_bool(std::bitset<64>(reseed_counter)));
	if (t.size() > seedlen)
		t = std::vector<bool>(t.end() - seedlen, t.end());
	V = t;
	++reseed_counter;
	return returned_bits;
}
std::vector<bool> Hash_DRBG_SM3::Generate(std::size_t requested_number_of_bits)
{
	// 1. If reseed_counter > reseed_interval, then return an indication that a reseed is required.
	if (reseed_counter > reseed_interval)
		throw std::runtime_error(__func__);
	auto returned_bits = Hashgen(requested_number_of_bits, V);
	std::vector<bool> v{0, 0, 0, 0, 0, 0, 1, 1};
	v.insert(v.end(), V.begin(), V.end());
	auto H = array_uint32_t_N_to_vector_bool(SM3::DoHash(v));
	auto t = add(add(add(V, H), C), bitset_N_to_vector_bool(std::bitset<64>(reseed_counter)));
	if (t.size() > seedlen)
		t = std::vector<bool>(t.end() - seedlen, t.end());
	V = t;
	++reseed_counter;
	return returned_bits;
}
} // namespace yySimpleCute

// 测试
#if 0

#include <iostream>

int main(int argc, const char *argv[])
{
	using namespace yySimpleCute;

	unsigned char ent[] = {0xcf, 0x67, 0x7f, 0xbb, 0xc2, 0xbc, 0x6f, 0x67, 0x38, 0x6f, 0x13, 0x67, 0x92,
						   0xda, 0xb9, 0x1f, 0x04, 0x30, 0xef, 0xa0, 0x6b, 0x41, 0xa5, 0x4b, 0x4a, 0x3e,
						   0xc1, 0x3c, 0x1a, 0xcf, 0xbc, 0x14, 0xfc, 0x72, 0xc7, 0xa5, 0x1c, 0x5b, 0x7c,
						   0xb1, 0xe3, 0x66, 0x11, 0xd3, 0x3e, 0xbc, 0xb9, 0xba, 0x87, 0xf6, 0x7c, 0x9a,
						   0x89, 0xd8, 0xdd, 0x22, 0xdb, 0x7b, 0x9d, 0x5b, 0x74, 0x6e, 0xf3, 0x1a};
	std::vector<bool> v_ent = szunsigned_char_to_vector_bool(ent);

	unsigned char nonce[] = {'n', 'o', 'n', 'c', 'e'};
	std::vector<bool> v_nonce = szunsigned_char_to_vector_bool(nonce);

	unsigned char pstr[] = {'p', 's', 't', 'r'};
	std::vector<bool> v_pstr = szunsigned_char_to_vector_bool(pstr);

	std::cout.fill('0');
	{
		Hash_DRBG_SM3 hash_drbg_sm3;
		hash_drbg_sm3.Instantiate(v_ent, v_nonce, v_pstr);
		auto v = hash_drbg_sm3.Generate(32);
		for (auto i : vector_bool_to_array_uint32_t_N<1>(v))
		{
			std::cout.width(8);
			std::cout << std::hex << i;
			std::cout << " ";
		}
		std::cout << std::endl;
	}
	{
		Hash_DRBG_SM3 hash_drbg_sm3;
		hash_drbg_sm3.Instantiate(v_ent, v_nonce, v_pstr);
		for (std::size_t i = 0; i < 4; ++i)
		{
			auto v = hash_drbg_sm3.Generate(8);

			std::cout.width(2);
			std::cout << std::hex << vector_bool_to_bitset_N<8>(v).to_ulong();
		}
		std::cout << std::endl;
	}
	return 0;
}
#endif
