#include "CryptoManager.h"
#include "CertificateManager.h"
#include "ImageProcessor.h"
#include <iostream>
#include <fstream>

int main() {
    try {
        std::string inputImagePath = "../ImageEncryptor/iron2.jpg";
        std::string encryptedImagePath = "C:/Users/isaaq/source/repos/ImageEncryptor/encrypted.enc";
        std::string decryptedImagePath = "C:/Users/isaaq/source/repos/ImageEncryptor/decrypted.jpg";
        std::string certFile = "C:/Users/isaaq/source/repos/ImageEncryptor/certificate.pem";
        std::string keyFile = "C:/Users/isaaq/source/repos/ImageEncryptor/private_key.pem";

        // Ensure the paths exist
        std::ifstream inputImageFile(inputImagePath);
        if (!inputImageFile) {
            std::cerr << "Error: Input image file does not exist: " << inputImagePath << std::endl;
            return 1;
        }
        int choice;
        std::vector<unsigned char> image;
        std::vector<unsigned char> encryptedImage;
            std::vector<unsigned char> decryptedImage;

        do {
            std::cout << "\nMenu:\n";
            std::cout << "1. Encrypt Image\n";
            std::cout << "2. Decrypt Image\n";
            std::cout << "3. Exit\n";
            std::cout << "Enter your choice: ";
            std::cin >> choice;

            switch (choice) {
            case 1:
                image = ImageProcessor::loadImage(inputImagePath);
                encryptedImage= CryptoManager::encrypt(image);
                ImageProcessor::saveImage(encryptedImagePath, encryptedImage);
                break;
            case 2:
                decryptedImage= CryptoManager::decrypt(encryptedImage);
                ImageProcessor::saveImage(decryptedImagePath, decryptedImage);
                std::cout << "Image decrypted succes";
                break;
            case 3:
                std::cout << "Exiting..." << std::endl;
                break;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
            }
        } while (choice != 3);


    }
    catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
