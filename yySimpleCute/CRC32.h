#ifndef CRC32_h
#define CRC32_h

#include <cstdint>

namespace yySimpleCute
{
class CRC32
{
public:
	static std::uint32_t DoCRC(const void *buf, std::size_t len, std::uint32_t crc = 0);
};
} // namespace yySimpleCute
#endif
