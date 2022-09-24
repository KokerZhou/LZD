// 密钥杂凑消息鉴别码HMAC。
// 按GB-T 15852.2-2012执行。

#ifndef HMAC_SM3_h
#define HMAC_SM3_h

#include <vector>

namespace yySimpleCute
{
class HMAC_SM3
{
public:
	static std::vector<bool> DoHMAC(const std::vector<bool> &K, const std::vector<bool> &D, std::size_t m = 256);
};
} // namespace yySimpleCute
#endif
