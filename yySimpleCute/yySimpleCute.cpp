#include <array>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <wincrypt.h>
#elif defined(__linux__)
#include <cstdio>
#endif

#include "CRC32.h"
#include "Hash_DRBG_SM3.h"
#include "PBKDF_HMAC_SM3.h"
#include "SM3.h"
#include "Util.h"

void GetRandom(unsigned char *buf, std::size_t bufSize)
{
	bool fail = true;
#if defined(_WIN32)
	// TODO: This API is deprecated. New and existing software should start using Cryptography Next Generation
	// APIs. Microsoft may remove this API in future releases.
	HCRYPTPROV hCryptProv = 0;
	if (CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		fail = CryptGenRandom(hCryptProv, (DWORD)bufSize, buf) != TRUE;
		CryptReleaseContext(hCryptProv, 0);
	}
#elif defined(__linux__)
	std::FILE *fp = std::fopen("/dev/urandom", "r");
	if (fp != NULL)
	{
		fail = std::fread(buf, 1, bufSize, fp) != bufSize;
		std::fclose(fp);
	}
#endif
	if (fail)
		throw std::runtime_error(__func__);
}

template <std::size_t bufSize> void GetRandom(unsigned char (&buf)[bufSize])
{
	return GetRandom(buf, bufSize);
}

std::vector<char> ReadFile(const std::string &fileName)
{
	std::ifstream ifs(fileName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
	if (!ifs)
		throw std::runtime_error(__func__);
	auto fileSize = ifs.tellg();
	ifs.seekg(0, std::ios::beg);
	std::vector<char> ret(fileSize);
	ifs.read(ret.data(), fileSize);
	return ret;
}

int main(int argc, const char *argv[])
{
	using namespace yySimpleCute;

	const std::uint32_t iter_ent = 4096;
	const std::uint32_t iter_chk = iter_ent + 4;
	const std::size_t SaltLen = 128;
	const std::size_t EntLen = 512;
	const std::size_t ChkLen = 256;
	const std::size_t NonceLen = 256;

	const unsigned char pstr[] = {'L', 'Z', 'D', ' ', 'N', 'I', 'S', 'T', ' ', 'S', 'P', ' ', '8', '0', '0', '-',
								  '9', '0', 'A', 'r', '1', ' ', 'H', 'A', 'S', 'H', '_', 'D', 'R', 'B', 'G'};

	std::vector<bool> v_pstr = szunsigned_char_to_vector_bool(pstr);

	int mode;
	while (std::cout << "0 - Exit, 1 - Encrypt, 2 - Decrypt" << std::endl, std::cin >> mode, mode)
	{
		if (mode == 1)
		{
			std::string ifileName = "", ofileName = "", passwd = "";
			std::vector<std::uint8_t> Data{};

			std::cout << "输入：";
			while (ifileName == "")
				std::getline(std::cin, ifileName);
			auto v_input = ReadFile(ifileName);

			std::cout << "输出：";
			while (ofileName == "")
				std::getline(std::cin, ofileName);
			std::ofstream ofs(ofileName, std::ios::binary);

			std::cout << "密码：";
			while (passwd == "")
				std::getline(std::cin, passwd);
			auto v_passwd = szchar_to_vector_bool(passwd.data(), passwd.length());

			unsigned char Salt[SaltLen / 8];
			GetRandom(Salt);
			auto v_salt = szunsigned_char_to_vector_bool(Salt);

			std::vector<unsigned char> v_salt_ex(Salt, Salt + SaltLen / 8);
			Data.insert(Data.end(), v_salt_ex.begin(), v_salt_ex.end());

			auto v_ent = PBKDF_HMAC_SM3::DoPBKDF(v_passwd, v_salt, iter_ent, EntLen / 8);

			auto v_chk = PBKDF_HMAC_SM3::DoPBKDF(v_passwd, v_salt, iter_chk, ChkLen / 8);

			std::array<std::uint8_t, 32> t{};
			for (std::size_t i = 0; i < 32; ++i)
			{
				std::uint8_t x = 0;
				for (std::size_t j = 0; j < 8; ++j)
				{
					x |= v_chk[i * 8 + j] << (7 - j);
				}
				t[i] = x;
			}

			unsigned char Nonce[NonceLen / 8];
			GetRandom(Nonce);
			auto v_nonce = szunsigned_char_to_vector_bool(Nonce);

			std::vector<unsigned char> v_nonce_ex(Nonce, Nonce + NonceLen / 8);
			Data.insert(Data.end(), v_nonce_ex.begin(), v_nonce_ex.end());

			for (std::size_t i = 0; i < 8; ++i)
			{
				Data.push_back(t[i] ^ t[i + 8] ^ t[i + 16] ^ t[i + 24]);
			}

			Hash_DRBG_SM3 hash_drbg_sm3;
			hash_drbg_sm3.Instantiate(v_ent, v_nonce, v_pstr);
			auto v_rnd = hash_drbg_sm3.Generate(v_input.size() * 8 + 256);

			std::vector<bool> v_input_ex{};

			for (std::size_t i = 0; i < v_input.size(); ++i)
			{
				std::uint8_t xorKey = 0;
				for (std::size_t j = 0; j < 8; ++j)
					xorKey |= v_rnd[i * 8 + j] << (7 - j);
				Data.push_back(xorKey ^ (unsigned char)v_input[i]);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b10000000);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b01000000);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b00100000);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b00010000);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b00001000);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b00000100);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b00000010);
				v_input_ex.push_back((unsigned char)v_input[i] & 0b00000001);
			}

			auto v_hash = array_uint32_t_N_to_vector_bool(SM3::DoHash(v_input_ex));

			for (std::size_t i = 0; i < 32; ++i)
			{
				std::uint8_t xorKey = 0, hashVal = 0;
				for (std::size_t j = 0; j < 8; ++j)
				{
					xorKey |= v_rnd[v_input.size() * 8 + i * 8 + j] << (7 - j);
					hashVal |= v_hash[i * 8 + j] << (7 - j);
				}

				Data.push_back(xorKey ^ hashVal);
			}
			ofs << "LZD" << (char)0;
			auto crc32 = CRC32::DoCRC(Data.data(), Data.size());
			ofs.write((const char *)&crc32, 4);
			ofs.write((const char *)Data.data(), Data.size());
			std::cout << "成功。" << std::endl;
		}
		else if (mode == 2)
		{
			std::string ifileName = "", ofileName = "", passwd = "";

			std::cout << "输入：";
			while (ifileName == "")
				std::getline(std::cin, ifileName);
			auto v_input = ReadFile(ifileName);

			if (v_input.size() < 8 + SaltLen / 8 + NonceLen / 8 + 8 + 256 / 8)
			{
				std::cout << "错误的文件大小。" << std::endl;
				continue;
			}
			if (v_input[0] != 'L' || v_input[1] != 'Z' || v_input[2] != 'D')
			{
				std::cout << "错误的文件签名。" << std::endl;
				continue;
			}
			if (v_input[3] != 0)
			{
				std::cout << "错误的文件版本。" << std::endl;
				continue;
			}
			std::uint32_t true_crc32 = *(std::uint32_t *)(v_input.data() + 4);
			std::uint32_t crc32 = CRC32::DoCRC(v_input.data() + 8, v_input.size() - 8);

			if (true_crc32 != crc32)
			{
				std::cout << "错误的循环冗余校验码。" << std::endl;
				continue;
			}

			std::cout << "输出：";
			while (ofileName == "")
				std::getline(std::cin, ofileName);
			std::ofstream ofs(ofileName, std::ios::binary);

			std::cout << "密码：";
			while (passwd == "")
				std::getline(std::cin, passwd);
			auto v_passwd = szchar_to_vector_bool(passwd.data(), passwd.length());

			auto v_salt = szchar_to_vector_bool(v_input.data() + 8, SaltLen / 8);

			auto v_chk = PBKDF_HMAC_SM3::DoPBKDF(v_passwd, v_salt, iter_chk, ChkLen / 8);

			std::array<std::uint8_t, 32> t{};
			for (std::size_t i = 0; i < 32; ++i)
			{
				std::uint8_t x = 0;
				for (std::size_t j = 0; j < 8; ++j)
				{
					x |= v_chk[i * 8 + j] << (7 - j);
				}
				t[i] = x;
			}

			bool fail_chk = false;
			for (std::size_t i = 0; i < 8; ++i)
			{
				if ((std::uint8_t)v_input[8 + SaltLen / 8 + NonceLen / 8 + i] !=
					(t[i] ^ t[i + 8] ^ t[i + 16] ^ t[i + 24]))
				{
					fail_chk = true;
					break;
				}
			}
			if (fail_chk)
			{
				std::cout << "口令识别失败。" << std::endl;
				continue;
			}

			auto v_nonce = szchar_to_vector_bool(v_input.data() + 8 + SaltLen / 8, NonceLen / 8);

			auto v_ent = PBKDF_HMAC_SM3::DoPBKDF(v_passwd, v_salt, iter_ent, EntLen / 8);

			std::size_t ctLen = v_input.size() - (8 + SaltLen / 8 + NonceLen / 8 + 8 + 256 / 8);

			Hash_DRBG_SM3 hash_drbg_sm3;
			hash_drbg_sm3.Instantiate(v_ent, v_nonce, v_pstr);
			auto v_rnd = hash_drbg_sm3.Generate(ctLen * 8 + 256);

			std::vector<std::uint8_t> Data{};
			std::vector<bool> v_input_ex{};

			for (std::size_t i = 0; i < ctLen; ++i)
			{
				std::uint8_t xorKey = 0;
				for (std::size_t j = 0; j < 8; ++j)
					xorKey |= v_rnd[i * 8 + j] << (7 - j);
				Data.push_back(xorKey ^ (unsigned char)v_input[(8 + SaltLen / 8 + NonceLen / 8 + 8) + i]);
				v_input_ex.push_back(Data[i] & 0b10000000);
				v_input_ex.push_back(Data[i] & 0b01000000);
				v_input_ex.push_back(Data[i] & 0b00100000);
				v_input_ex.push_back(Data[i] & 0b00010000);
				v_input_ex.push_back(Data[i] & 0b00001000);
				v_input_ex.push_back(Data[i] & 0b00000100);
				v_input_ex.push_back(Data[i] & 0b00000010);
				v_input_ex.push_back(Data[i] & 0b00000001);
			}

			auto v_hash = array_uint32_t_N_to_vector_bool(SM3::DoHash(v_input_ex));

			bool fail_hash = false;
			for (std::size_t i = 0; i < 32; ++i)
			{
				std::uint8_t xorKey = 0, hashVal = 0;
				for (std::size_t j = 0; j < 8; ++j)
				{
					xorKey |= v_rnd[ctLen * 8 + i * 8 + j] << (7 - j);
					hashVal |= v_hash[i * 8 + j] << (7 - j);
				}
				if ((xorKey ^ hashVal) != (std::uint8_t)v_input[(8 + SaltLen / 8 + NonceLen / 8 + 8) + ctLen + i])
				{
					fail_hash = true;
					break;
				}
			}
			if (fail_hash)
			{
				std::cout << "杂凑校验失败。" << std::endl;
				continue;
			}
			ofs.write((const char *)Data.data(), Data.size());
			std::cout << "成功。" << std::endl;
		}
	}
	return 0;
}
