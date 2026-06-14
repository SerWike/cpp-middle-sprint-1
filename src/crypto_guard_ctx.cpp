#include "crypto_guard_ctx.h"

#include <iostream>
#include <memory>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {}

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {}

    std::string CalculateChecksum(std::iostream &inStream) const { return "NOT_IMPLEMENTED"; }
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
    std::string res = pImpl_->CalculateChecksum(inStream);
    return res;
}

}  // namespace CryptoGuard
