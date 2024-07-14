#include "ImageProcessor.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

std::vector<unsigned char> ImageProcessor::loadImage(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Failed to open image file for reading: " << filePath << std::endl;
        throw std::runtime_error("Failed to open image file for reading");
    }

    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void ImageProcessor::saveImage(const std::string& filePath, const std::vector<unsigned char>& data) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Failed to open image file for writing: " << filePath << std::endl;
        throw std::runtime_error("Failed to open image file for writing");
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}
