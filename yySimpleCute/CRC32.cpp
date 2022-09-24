#include "CRC32.h"

namespace yySimpleCute
{
std::uint32_t CRC32::DoCRC(const void *buf, std::size_t len, std::uint32_t crc)
{
	const std::uint8_t *p = (std::uint8_t *)buf;
	crc = ~crc;
	while (len--)
	{
		crc ^= *p++;
		for (int k = 0; k < 8; k++)
			crc = crc & 1 ? (crc >> 1) ^ 0xedb88320 : crc >> 1;
	}
	return ~crc;
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
	std::cout << std::hex << CRC32::DoCRC(buf, sizeof(buf) / sizeof(*buf)) << std::endl;
	return 0;
}
#endif
