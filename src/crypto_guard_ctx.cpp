#include "crypto_guard_ctx.h"

#include <cstring>
#include <iostream>
#include <memory>

#include <boost/signals2/detail/scope_guard.hpp>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {

    using uniqueCtxPtr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    using uniqueMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

public:
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
        this->EncryptDecrypt(inStream, outStream, password, 1);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
        this->EncryptDecrypt(inStream, outStream, password, 0);
    }

    std::string CalculateChecksum(std::iostream &inStream) const {
        if (!inStream.good())
            throw std::runtime_error("Input stream isn't good");
        if (inStream.rdbuf()->in_avail() <= 0)
            throw std::runtime_error("Input stream is empty");

        uniqueMdCtxPtr ctx{EVP_MD_CTX_new()};
        if (!EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), NULL))
            throw std::runtime_error("Failed to init Digest EVP context: " + this->GetErrorMessage());

        unsigned char buffer[EVP_MAX_MD_SIZE];
        int read_from_stream = inStream.readsome(reinterpret_cast<char *>(buffer), EVP_MAX_MD_SIZE);
        do {
            if (!EVP_DigestUpdate(ctx.get(), buffer, read_from_stream))
                throw std::runtime_error("Failed in DigestUpdate: " + this->GetErrorMessage());

            read_from_stream = inStream.readsome(reinterpret_cast<char *>(buffer), EVP_MAX_MD_SIZE);
        } while (read_from_stream);

        unsigned int result_len = 0;
        std::memset(buffer, 0, EVP_MAX_MD_SIZE);
        if (!EVP_DigestFinal_ex(ctx.get(), buffer, &result_len))
            throw std::runtime_error("Failed in DigestFinal: " + this->GetErrorMessage());

        std::stringstream result;
        result << std::hex << std::setfill('0');

        for (size_t i = 0; i < result_len; ++i)
            result << std::setw(2) << static_cast<int>(static_cast<unsigned char>(buffer[i]));

        return result.str();
    }

private:
    AesCipherParams CreateChipherParamsFromPassword(std::string_view password) const {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error("Failed to create a key from password: " + this->GetErrorMessage());
        }

        return params;
    }

    std::string GetErrorMessage() const noexcept {
        std::string result;
        result.resize(256);
        ERR_error_string_n(ERR_get_error(), result.data(), result.size());
        return result;
    }

    void EncryptDecrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                        const int &mode) const {
        if (!inStream.good())
            throw std::runtime_error("Input stream isn't good");
        if (inStream.rdbuf()->in_avail() <= 0)
            throw std::runtime_error("Input stream is empty");
        if (!outStream.good())
            throw std::runtime_error("Output stream isn't good");

        auto params = this->CreateChipherParamsFromPassword(password);
        params.encrypt = mode;

        uniqueCtxPtr ctx{EVP_CIPHER_CTX_new()};

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt))
            throw std::runtime_error{"Failed to init Cipher EVP context:" + this->GetErrorMessage()};

        unsigned char inBuffer[EVP_MAX_BLOCK_LENGTH];
        unsigned char outBuffer[EVP_MAX_BLOCK_LENGTH];
        int outLen;

        int read_from_stream = inStream.readsome(reinterpret_cast<char *>(inBuffer), EVP_MAX_BLOCK_LENGTH);
        do {
            outLen = 0;
            if (!EVP_CipherUpdate(ctx.get(), outBuffer, &outLen, inBuffer, read_from_stream))
                throw std::runtime_error("Failed in CipherUpdate: " + this->GetErrorMessage());

            outStream.write((const char *)outBuffer, outLen);
            if (outStream.bad())
                throw std::runtime_error("Failed to write encrypted data in out stream");

            read_from_stream = inStream.readsome(reinterpret_cast<char *>(inBuffer), EVP_MAX_BLOCK_LENGTH);
        } while (read_from_stream);

        if (!EVP_CipherFinal_ex(ctx.get(), outBuffer, &outLen))
            throw std::runtime_error("Failed in EVP_CipherFinal_ex: " + this->GetErrorMessage());

        outStream.write(reinterpret_cast<const char *>(outBuffer), outLen);
        if (outStream.bad())
            throw std::runtime_error("Failed to write encrypted data in out stream");
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
