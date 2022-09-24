// 杂凑——确定性随机比特生成器Hash_DRBG。
// 按NIST SP 800-90Ar1执行。

#ifndef Hash_DRBG_SM3_h
#define Hash_DRBG_SM3_h

#include <cstdint>
#include <vector>

namespace yySimpleCute
{
class Hash_DRBG_SM3
{
private:
	// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
	// Table 2: Definitions for Hash-Based DRBG Mechanisms
	const std::size_t outlen = 256;
	const std::uint64_t reseed_interval = 1ULL << 48;
	const std::uint64_t seedlen = 440;

	// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
	// [10.1.1 Hash_DRBG] [10.1.1.1 Hash_DRBG Internal State]
	// 1. The working_state:
	//    a. A value (V) of seedlen bits that is updated during each call to the DRBG.
	std::vector<bool> V;
	//    b. A constant (C) of seedlen bits that depends on the seed.
	std::vector<bool> C;
	//    c. A counter (reseed_counter) that indicates the number of requests for pseudorandom
	//       bits since new entropy_input was obtained during instantiation or reseeding.
	std::uint64_t reseed_counter;
	// 2. Administrative information:
	//    a. The security_strength of the DRBG instantiation.
	std::uint32_t security_strength;
	//    b. A prediction_resistance_flag that indicates whether or not a prediction resistance
	//       capability is available for the DRBG instantiation.
	bool prediction_resistance_flag;

	std::vector<bool> add(const std::vector<bool> &lhs, const std::vector<bool> &rhs);

	// [10 DRBG Algorithm Specifications] [10.3 Auxiliary Functions]
	// [10.3.1 Derivation Function Using a Hash Function (Hash_df)]
	std::vector<bool> Hash_df(const std::vector<bool> &input_string, std::size_t no_of_bits_to_return);
	std::vector<bool> Hashgen(std::size_t requested_number_of_bits, const std::vector<bool> &V);

public:
	// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
	// [10.1.1 Hash_DRBG] [10.1.1.2 Instantiation of Hash_DRBG]
	void Instantiate(const std::vector<bool> &entropy_input, const std::vector<bool> &nonce,
					 const std::vector<bool> &personalization_string, std::uint32_t security_strength = 256);
	// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
	// [10.1.1 Hash_DRBG] [10.1.1.3 Reseeding a Hash_DRBG Instantiation]
	void Reseed(const std::vector<bool> &entropy_input, const std::vector<bool> &additional_input);
	// [10 DRBG Algorithm Specifications] [10.1 DRBG Mechanisms Based on Hash Functions]
	// [10.1.1 Hash_DRBG] [10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG]
	std::vector<bool> Generate(std::size_t requested_number_of_bits, const std::vector<bool> &additional_input);
	std::vector<bool> Generate(std::size_t requested_number_of_bits);
};
} // namespace yySimpleCute
#endif
