#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include "certificate_creator.h"

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -d, --domain <hostname>    Set hostname (default: server1.server.com)" << std::endl;
    std::cout << "  -p, --password <password>  Set password (default: 11111111)" << std::endl;
    std::cout << "  --ip <ip_address>          Set IP address (optional)" << std::endl;
    std::cout << "  -h, --help                 Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << "  " << programName << " -d myserver.com -p mypassword123 --ip 192.168.1.100" << std::endl;
}

int main(int argc, char** argv) {
    try {
        std::cout << "=== OpenSSL Certificate Creator ===" << std::endl;
        std::cout << "OpenSSL version: " << OpenSSL_version(OPENSSL_VERSION) << std::endl;
        std::cout << "OpenSSL version number: " << OPENSSL_VERSION_NUMBER << std::endl;
        std::cout << std::endl;
        
        // 解析命令行参数
        std::string hostname = "server1.server.com";
        std::string password = "11111111";
        std::string ipAddress = "";
        
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            
            if (arg == "-h" || arg == "--help") {
                printUsage(argv[0]);
                return 0;
            } else if (arg == "-d" || arg == "--domain") {
                if (i + 1 < argc) {
                    hostname = argv[++i];
                } else {
                    std::cerr << "Error: Missing hostname after -d/--domain" << std::endl;
                    return 1;
                }
            } else if (arg == "-p" || arg == "--password") {
                if (i + 1 < argc) {
                    password = argv[++i];
                } else {
                    std::cerr << "Error: Missing password after -p/--password" << std::endl;
                    return 1;
                }
            } else if (arg == "--ip") {
                if (i + 1 < argc) {
                    ipAddress = argv[++i];
                } else {
                    std::cerr << "Error: Missing IP address after --ip" << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Error: Unknown argument: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }
        
        // 显示配置信息
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Hostname: " << hostname << std::endl;
        std::cout << "  Password: " << password << std::endl;
        std::cout << "  IP Address: " << (ipAddress.empty() ? "Not specified" : ipAddress) << std::endl;
        std::cout << std::endl;
        
        // 创建证书创建器
        CertificateCreator creator;
        creator.setHostName(hostname);
        creator.setPassword(password);
        if (!ipAddress.empty()) {
            creator.setIPAddress(ipAddress);
        }
        
        // 生成证书
        std::cout << "Starting certificate generation..." << std::endl;
        if (creator.generateCertificate()) {
            std::cout << std::endl;
            std::cout << "=== Certificate Generation Completed Successfully! ===" << std::endl;
            std::cout << "Generated files:" << std::endl;
            std::cout << "  - server.key (Private key)" << std::endl;
            std::cout << "  - server.csr (Certificate Signing Request)" << std::endl;
            std::cout << "  - server.crt (Self-signed certificate)" << std::endl;
            std::cout << "  - server.pfx (PKCS12 format)" << std::endl;
            std::cout << "  - cert_extensions (Certificate extensions)" << std::endl;
            std::cout << std::endl;
            std::cout << "You can now use these files for your SSL/TLS configuration." << std::endl;
        } else {
            std::cerr << "Certificate generation failed!" << std::endl;
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred" << std::endl;
        return 1;
    }
    
    return 0;
}