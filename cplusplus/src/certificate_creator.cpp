#include "certificate_creator.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

CertificateCreator::CertificateCreator() 
    : privateKey_(nullptr), csr_(nullptr), certificate_(nullptr), p12_(nullptr) {
    
    // 设置默认值
    hostname_ = "server1.server.com";
    password_ = "11111111";
    ipAddress_ = "";
    
    // 设置文件路径
    keyFile_ = "server.key";
    csrFile_ = "server.csr";
    crtFile_ = "server.crt";
    pfxFile_ = "server.pfx";
    p12File_ = "server.p12";
    jksFile_ = "server.jks";
    extensionsFile_ = "cert_extensions";
    
    // 初始化OpenSSL - 使用更兼容的方式
    // 在OpenSSL 3.0中，很多初始化是自动的
}

CertificateCreator::~CertificateCreator() {
    cleanup();
}

void CertificateCreator::setHostName(const std::string& hostname) {
    hostname_ = hostname;
}

void CertificateCreator::setPassword(const std::string& password) {
    password_ = password;
}

void CertificateCreator::setIPAddress(const std::string& ip) {
    ipAddress_ = ip;
}

bool CertificateCreator::generateCertificate() {
    std::cout << "Generating certificate for hostname: " << hostname_ << std::endl;
    std::cout << "Password: " << password_ << std::endl;
    std::cout << "IP: " << (ipAddress_.empty() ? "Not specified" : ipAddress_) << std::endl;
    
    try {
        // 生成RSA密钥
        if (!generateRSAKey()) {
            std::cerr << "Failed to generate RSA key" << std::endl;
            return false;
        }
        
        // 创建证书签名请求
        if (!createCSR()) {
            std::cerr << "Failed to create CSR" << std::endl;
            return false;
        }
        
        // 创建证书扩展
        if (!createCertificateExtensions()) {
            std::cerr << "Failed to create certificate extensions" << std::endl;
            return false;
        }
        
        // 创建自签名证书
        if (!createSelfSignedCertificate()) {
            std::cerr << "Failed to create self-signed certificate" << std::endl;
            return false;
        }
        
        // 创建PKCS12文件
        if (!createPKCS12()) {
            std::cerr << "Failed to create PKCS12 file" << std::endl;
            return false;
        }
        
        std::cout << "Certificate generation completed successfully!" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception during certificate generation: " << e.what() << std::endl;
        return false;
    }
}

bool CertificateCreator::generateRSAKey() {
    std::cout << "Generating RSA private key..." << std::endl;
    
    // 生成RSA密钥对
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Failed to create RSA key context" << std::endl;
        return false;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Failed to initialize RSA key generation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // 设置RSA密钥大小 - 使用参数方式
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Failed to set RSA key size" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (EVP_PKEY_keygen(ctx, &privateKey_) <= 0) {
        std::cerr << "Failed to generate RSA key pair" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // 保存私钥到文件
    FILE* keyFile = fopen(keyFile_.c_str(), "w");
    if (!keyFile) {
        std::cerr << "Failed to open key file for writing" << std::endl;
        return false;
    }
    
    if (PEM_write_PrivateKey(keyFile, privateKey_, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        std::cerr << "Failed to write private key to file" << std::endl;
        fclose(keyFile);
        return false;
    }
    
    fclose(keyFile);
    std::cout << "RSA private key generated and saved to " << keyFile_ << std::endl;
    
    return true;
}

bool CertificateCreator::createCSR() {
    std::cout << "Creating Certificate Signing Request..." << std::endl;
    
    // 创建CSR
    csr_ = X509_REQ_new();
    if (!csr_) {
        std::cerr << "Failed to create CSR" << std::endl;
        return false;
    }
    
    // 设置CSR版本
    if (X509_REQ_set_version(csr_, 0) != 1) {
        std::cerr << "Failed to set CSR version" << std::endl;
        return false;
    }
    
    // 设置公钥
    if (X509_REQ_set_pubkey(csr_, privateKey_) != 1) {
        std::cerr << "Failed to set public key in CSR" << std::endl;
        return false;
    }
    
    // 创建主题名称
    X509_NAME* name = X509_REQ_get_subject_name(csr_);
    
    // 设置国家
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"CN", -1, -1, 0);
    
    // 设置州/省
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)"Beijing", -1, -1, 0);
    
    // 设置城市
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)"Beijing", -1, -1, 0);
    
    // 设置组织
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"Company", -1, -1, 0);
    
    // 设置组织单位
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)"Company.cn", -1, -1, 0);
    
    // 设置通用名称
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)hostname_.c_str(), -1, -1, 0);
    
    // 签名CSR
    if (X509_REQ_sign(csr_, privateKey_, EVP_sha256()) <= 0) {
        std::cerr << "Failed to sign CSR" << std::endl;
        return false;
    }
    
    // 保存CSR到文件
    FILE* csrFile = fopen(csrFile_.c_str(), "w");
    if (!csrFile) {
        std::cerr << "Failed to open CSR file for writing" << std::endl;
        return false;
    }
    
    if (PEM_write_X509_REQ(csrFile, csr_) != 1) {
        std::cerr << "Failed to write CSR to file" << std::endl;
        fclose(csrFile);
        return false;
    }
    
    fclose(csrFile);
    std::cout << "CSR created and saved to " << csrFile_ << std::endl;
    
    return true;
}

bool CertificateCreator::createCertificateExtensions() {
    std::cout << "Creating certificate extensions..." << std::endl;
    
    std::ofstream extFile(extensionsFile_);
    if (!extFile.is_open()) {
        std::cerr << "Failed to open extensions file for writing" << std::endl;
        return false;
    }
    
    if (!ipAddress_.empty()) {
        extFile << "subjectAltName=IP:" << ipAddress_ << ",DNS:" << hostname_;
    } else {
        extFile << "subjectAltName=DNS:" << hostname_;
    }
    
    extFile.close();
    std::cout << "Certificate extensions created and saved to " << extensionsFile_ << std::endl;
    
    return true;
}

bool CertificateCreator::createSelfSignedCertificate() {
    std::cout << "Creating self-signed certificate..." << std::endl;
    
    // 创建证书
    certificate_ = X509_new();
    if (!certificate_) {
        std::cerr << "Failed to create certificate" << std::endl;
        return false;
    }
    
    // 设置证书版本
    if (X509_set_version(certificate_, 2) != 1) {
        std::cerr << "Failed to set certificate version" << std::endl;
        return false;
    }
    
    // 设置序列号
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!serial) {
        std::cerr << "Failed to create serial number" << std::endl;
        return false;
    }
    
    // 生成随机序列号
    BIGNUM* bn = BN_new();
    if (!bn) {
        std::cerr << "Failed to create BIGNUM" << std::endl;
        ASN1_INTEGER_free(serial);
        return false;
    }
    
    // 使用更兼容的随机数生成
    BN_rand(bn, 64, 0, 0);
    BN_to_ASN1_INTEGER(bn, serial);
    BN_free(bn);
    
    if (X509_set_serialNumber(certificate_, serial) != 1) {
        std::cerr << "Failed to set serial number" << std::endl;
        ASN1_INTEGER_free(serial);
        return false;
    }
    
    ASN1_INTEGER_free(serial);
    
    // 设置有效期 - 使用更兼容的方式
    time_t now = time(nullptr);
    if (X509_time_adj(X509_getm_notBefore(certificate_), 0, &now) == nullptr) {
        std::cerr << "Failed to set not before time" << std::endl;
        return false;
    }
    
    time_t later = now + (3650 * 24 * 60 * 60); // 10 years
    if (X509_time_adj(X509_getm_notAfter(certificate_), 0, &later) == nullptr) {
        std::cerr << "Failed to set not after time" << std::endl;
        return false;
    }
    
    // 设置主题名称
    X509_NAME* name = X509_get_subject_name(certificate_);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)"Beijing", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)"Beijing", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"Company", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)"Company.cn", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)hostname_.c_str(), -1, -1, 0);
    
    // 设置颁发者名称（自签名，所以与主题相同）
    if (X509_set_issuer_name(certificate_, name) != 1) {
        std::cerr << "Failed to set issuer name" << std::endl;
        return false;
    }
    
    // 设置公钥
    if (X509_set_pubkey(certificate_, privateKey_) != 1) {
        std::cerr << "Failed to set public key" << std::endl;
        return false;
    }
    
    // 添加扩展
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, certificate_, certificate_, nullptr, nullptr, 0);
    
    // 添加主题备用名称扩展
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, 
        (ipAddress_.empty() ? ("DNS:" + hostname_).c_str() : ("IP:" + ipAddress_ + ",DNS:" + hostname_).c_str()));
    
    if (ext) {
        X509_add_ext(certificate_, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // 签名证书
    if (X509_sign(certificate_, privateKey_, EVP_sha256()) <= 0) {
        std::cerr << "Failed to sign certificate" << std::endl;
        return false;
    }
    
    // 保存证书到文件
    FILE* crtFile = fopen(crtFile_.c_str(), "w");
    if (!crtFile) {
        std::cerr << "Failed to open certificate file for writing" << std::endl;
        return false;
    }
    
    if (PEM_write_X509(crtFile, certificate_) != 1) {
        std::cerr << "Failed to write certificate to file" << std::endl;
        fclose(crtFile);
        return false;
    }
    
    fclose(crtFile);
    std::cout << "Self-signed certificate created and saved to " << crtFile_ << std::endl;
    
    return true;
}

bool CertificateCreator::createPKCS12() {
    std::cout << "Creating PKCS12 file..." << std::endl;
    
    // 创建PKCS12文件
    p12_ = PKCS12_create(password_.c_str(), "server", privateKey_, certificate_, nullptr, 0, 0, 0, 0, 0);
    if (!p12_) {
        std::cerr << "Failed to create PKCS12" << std::endl;
        return false;
    }
    
    // 保存PKCS12到文件
    FILE* p12File = fopen(pfxFile_.c_str(), "wb");
    if (!p12File) {
        std::cerr << "Failed to open PKCS12 file for writing" << std::endl;
        return false;
    }
    
    if (i2d_PKCS12_fp(p12File, p12_) != 1) {
        std::cerr << "Failed to write PKCS12 to file" << std::endl;
        fclose(p12File);
        return false;
    }
    
    fclose(p12File);
    std::cout << "PKCS12 file created and saved to " << pfxFile_ << std::endl;
    
    return true;
}

bool CertificateCreator::generateCRT() {
    std::cout << "Generating CRT format..." << std::endl;
    // 这里可以实现从PKCS12提取CRT的逻辑
    return true;
}

bool CertificateCreator::generateP12() {
    std::cout << "Generating P12 format..." << std::endl;
    // 这里可以实现P12格式转换的逻辑
    return true;
}

bool CertificateCreator::generateJKS() {
    std::cout << "Generating JKS format..." << std::endl;
    // 这里可以实现JKS格式转换的逻辑
    return true;
}

bool CertificateCreator::createZipFile() {
    std::cout << "Creating ZIP file..." << std::endl;
    // 这里可以实现ZIP文件创建的逻辑
    return true;
}

void CertificateCreator::cleanup() {
    if (privateKey_) {
        EVP_PKEY_free(privateKey_);
        privateKey_ = nullptr;
    }
    
    if (csr_) {
        X509_REQ_free(csr_);
        csr_ = nullptr;
    }
    
    if (certificate_) {
        X509_free(certificate_);
        certificate_ = nullptr;
    }
    
    if (p12_) {
        PKCS12_free(p12_);
        p12_ = nullptr;
    }
}
