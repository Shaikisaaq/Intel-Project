#ifndef IMAGEPROCESSOR_H
#define IMAGEPROCESSOR_H

#include <string>
#include <vector>

class ImageProcessor {
public:
    static std::vector<unsigned char> loadImage(const std::string& filePath);
    static void saveImage(const std::string& filePath, const std::vector<unsigned char>& data);
};

#endif // IMAGEPROCESSOR_H
