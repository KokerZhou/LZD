#include "Util.h"

namespace yySimpleCute
{
std::vector<bool> szunsigned_char_to_vector_bool(const unsigned char *buf, std::size_t N)
{
	std::vector<bool> v(N * 8);
	for (std::size_t i = 0; i < N; ++i)
	{
		v[i * 8 + 0] = buf[i] & 0b10000000;
		v[i * 8 + 1] = buf[i] & 0b01000000;
		v[i * 8 + 2] = buf[i] & 0b00100000;
		v[i * 8 + 3] = buf[i] & 0b00010000;
		v[i * 8 + 4] = buf[i] & 0b00001000;
		v[i * 8 + 5] = buf[i] & 0b00000100;
		v[i * 8 + 6] = buf[i] & 0b00000010;
		v[i * 8 + 7] = buf[i] & 0b00000001;
	}
	return v;
}
std::vector<bool> szchar_to_vector_bool(const char *buf, std::size_t N)
{
	std::vector<bool> v(N * 8);
	for (std::size_t i = 0; i < N; ++i)
	{
		v[i * 8 + 0] = (unsigned char)buf[i] & 0b10000000;
		v[i * 8 + 1] = (unsigned char)buf[i] & 0b01000000;
		v[i * 8 + 2] = (unsigned char)buf[i] & 0b00100000;
		v[i * 8 + 3] = (unsigned char)buf[i] & 0b00010000;
		v[i * 8 + 4] = (unsigned char)buf[i] & 0b00001000;
		v[i * 8 + 5] = (unsigned char)buf[i] & 0b00000100;
		v[i * 8 + 6] = (unsigned char)buf[i] & 0b00000010;
		v[i * 8 + 7] = (unsigned char)buf[i] & 0b00000001;
	}
	return v;
}
} // namespace yySimpleCute
