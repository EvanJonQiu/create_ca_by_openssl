#ifndef CERTIFICATE_CREATOR_H
#define CERTIFICATE_CREATOR_H

#include <string>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

class CertificateCreator {
public:
    CertificateCreator();
    ~CertificateCreator();
    
    // 设置证书信息
    void setHostName(const std::string& hostname);
    void setPassword(const std::string& password);
    void setIPAddress(const std::string& ip);
    
    // 生成证书
    bool generateCertificate();
    
    // 生成特定格式的证书
    bool generateCRT();
    bool generateP12();
    bool generateJKS();
    
    // 打包文件
    bool createZipFile();

private:
    // 生成RSA密钥
    bool generateRSAKey();
    
    // 创建证书签名请求
    bool createCSR();
    
    // 创建自签名证书
    bool createSelfSignedCertificate();
    
    // 创建PKCS12文件
    bool createPKCS12();
    
    // 创建证书扩展
    bool createCertificateExtensions();
    
    // 清理资源
    void cleanup();

private:
    std::string hostname_;
    std::string password_;
    std::string ipAddress_;
    
    // OpenSSL对象
    EVP_PKEY* privateKey_;
    X509_REQ* csr_;
    X509* certificate_;
    PKCS12* p12_;
    
    // 文件路径
    std::string keyFile_;
    std::string csrFile_;
    std::string crtFile_;
    std::string pfxFile_;
    std::string p12File_;
    std::string jksFile_;
    std::string extensionsFile_;
};

#endif // CERTIFICATE_CREATOR_H
