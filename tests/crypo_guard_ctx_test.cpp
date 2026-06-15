#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <stdexcept>

// TODO Check empty password
// EncryptDecrypt with differents password

TEST(TestCryptoGuard, EncryptEmptyInputStream) {
    std::stringstream input;
    std::stringstream output;
    std::string password;

    CryptoGuard::CryptoGuardCtx cryptor;
    ASSERT_THROW(cryptor.EncryptFile(input, output, password), std::runtime_error);
}

TEST(TestCryptoGuard, EncryptDecrypt) {
    std::stringstream plain("simple string to encrypt");
    std::stringstream encrypted;
    std::stringstream decrypted;
    std::string password = "strong password";

    CryptoGuard::CryptoGuardCtx cryptor;
    ASSERT_NO_THROW(cryptor.EncryptFile(plain, encrypted, password));
    ASSERT_NO_THROW(cryptor.DecryptFile(encrypted, decrypted, password));

    ASSERT_EQ(plain.view(), decrypted.view());
}

TEST(TestCryptoGuard, CheckSum) {
    std::stringstream input("Hello world!");
    /* Result of 'echo -n "Hello world!" | sha256sum' */
    std::string input_hash = "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a";

    CryptoGuard::CryptoGuardCtx cryptor;
    ASSERT_EQ(input_hash, cryptor.CalculateChecksum(input));
}
