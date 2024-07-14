#ifndef CRYPTOMANAGER_H
#define CRYPTOMANAGER_H

#include <vector>
#include <string>

class CryptoManager {
public:
    static std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data);
};

#endif // CRYPTOMANAGER_H
