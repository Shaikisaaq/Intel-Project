cmake_minimum_required(VERSION 3.10)

project(ImageEncryptor)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(ImageEncryptor 
    src/main.cpp 
    src/CryptoManager.cpp 
    src/CertificateManager.cpp 
    src/ImageProcessor.cpp
)

find_package(OpenSSL REQUIRED)
target_link_libraries(ImageEncryptor OpenSSL::SSL OpenSSL::Crypto)
