#ifndef CERTIFICATEMANAGER_H
#define CERTIFICATEMANAGER_H

#include <string>

class CertificateManager {
public:
    static void generateCertificate(const std::string& certFile, const std::string& keyFile);
};

#endif // CERTIFICATEMANAGER_H
