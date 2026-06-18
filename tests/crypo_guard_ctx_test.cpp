#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <stdexcept>

TEST(TestCryptoGuard, EncryptValid) {
    std::string input_str = "Secret message";
    std::stringstream input(input_str);
    std::stringstream output;
    std::string password("password");

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(cryptor.EncryptFile(input, output, password));
    std::string output_str = output.str();

    ASSERT_FALSE(output_str.empty());
    ASSERT_GE(output_str.length(), input_str.length());
    ASSERT_NE(input_str, output_str);
}

TEST(TestCryptoGuard, EncryptBadInputStream) {
    std::string input_str = "Secret message";
    std::stringstream input(input_str);
    std::stringstream output;
    std::string password;

    CryptoGuard::CryptoGuardCtx cryptor;

    input.setstate(std::ios::badbit);
    ASSERT_THROW(cryptor.EncryptFile(input, output, password), std::runtime_error);
}

TEST(TestCryptoGuard, EncryptEmptyInputStream) {
    std::stringstream input;
    std::stringstream output;
    std::string password;

    CryptoGuard::CryptoGuardCtx cryptor;
    ASSERT_THROW(cryptor.EncryptFile(input, output, password), std::runtime_error);
}

TEST(TestCryptoGuard, EncryptBadOutputStream) {
    std::string input_str = "Secret message";
    std::stringstream input(input_str);
    std::stringstream output;
    std::string password;

    CryptoGuard::CryptoGuardCtx cryptor;

    output.setstate(std::ios::badbit);
    ASSERT_THROW(cryptor.EncryptFile(input, output, password), std::runtime_error);
}

/* ----------------------------------------------------------------------------------------------------------- */

TEST(TestCryptoGuard, DecryptValid) {
    std::string plain_str = "Secret message";
    std::stringstream plain(plain_str);
    std::stringstream encrypt, decrypt;
    std::string password("password");

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(cryptor.EncryptFile(plain, encrypt, password));
    ASSERT_NO_THROW(cryptor.DecryptFile(encrypt, decrypt, password));

    std::string decrypt_str = decrypt.str();

    ASSERT_FALSE(decrypt_str.empty());
    ASSERT_GE(plain_str.length(), decrypt_str.length());
    ASSERT_EQ(plain_str, decrypt_str);
}

TEST(TestCryptoGuard, DecryptWithInvalidPassword) {
    std::string plain_str = "Secret message";
    std::stringstream plain(plain_str);
    std::stringstream encrypt, decrypt;
    std::string enc_password("password");
    std::string dec_password("another password");

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(cryptor.EncryptFile(plain, encrypt, enc_password));
    ASSERT_THROW(cryptor.DecryptFile(encrypt, decrypt, dec_password), std::runtime_error);

    std::string decrypt_str = decrypt.str();

    ASSERT_NE(plain_str, decrypt_str);
}

TEST(TestCryptoGuard, DecryptLess16ByteInput) {
    std::string plain_str = "less 16";
    std::stringstream plain(plain_str);
    std::stringstream encrypt, decrypt;
    std::string password("password");

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(cryptor.EncryptFile(plain, encrypt, password));
    ASSERT_NO_THROW(cryptor.DecryptFile(encrypt, decrypt, password));

    std::string decrypt_str = decrypt.str();

    ASSERT_FALSE(decrypt_str.empty());
    ASSERT_GE(plain_str.length(), decrypt_str.length());
    ASSERT_EQ(plain_str, decrypt_str);
}

TEST(TestCryptoGuard, Decrypt16ByteInput) {
    std::string plain_str = "16 byte input))";
    std::stringstream plain(plain_str);
    std::stringstream encrypt, decrypt;
    std::string password("password");

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(cryptor.EncryptFile(plain, encrypt, password));
    ASSERT_NO_THROW(cryptor.DecryptFile(encrypt, decrypt, password));

    std::string decrypt_str = decrypt.str();

    ASSERT_FALSE(decrypt_str.empty());
    ASSERT_GE(plain_str.length(), decrypt_str.length());
    ASSERT_EQ(plain_str, decrypt_str);
}

TEST(TestCryptoGuard, DecryptMore16ByteInput) {
    std::string plain_str = "More then 16 byte input";
    std::stringstream plain(plain_str);
    std::stringstream encrypt, decrypt;
    std::string password("password");

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(cryptor.EncryptFile(plain, encrypt, password));
    ASSERT_NO_THROW(cryptor.DecryptFile(encrypt, decrypt, password));

    std::string decrypt_str = decrypt.str();

    ASSERT_FALSE(decrypt_str.empty());
    ASSERT_GE(plain_str.length(), decrypt_str.length());
    ASSERT_EQ(plain_str, decrypt_str);
}

/* ----------------------------------------------------------------------------------------------------------- */

TEST(TestCryptoGuard, CheckSumValid) {
    std::stringstream input("Hello world!");

    /* Result of 'echo -n "Hello world!" | sha256sum' */
    std::string valid_input_hash = "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a";
    std::string input_hash;

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(input_hash = cryptor.CalculateChecksum(input));
    ASSERT_EQ(valid_input_hash, input_hash);
}

TEST(TestCryptoGuard, CheckSumBadInputStream) {
    std::stringstream input;

    CryptoGuard::CryptoGuardCtx cryptor;

    input.setstate(std::ios::badbit);
    ASSERT_THROW(cryptor.CalculateChecksum(input), std::runtime_error);
}

TEST(TestCryptoGuard, CheckSumEmptyInputStream) {
    std::stringstream input;

    CryptoGuard::CryptoGuardCtx cryptor;
    ASSERT_THROW(cryptor.CalculateChecksum(input), std::runtime_error);
}

TEST(TestCryptoGuard, EncryptDecryptWithCheckSum) {
    std::string plain_str = "less 16";
    std::stringstream plain(plain_str), plain_copy_for_checksum(plain_str);
    std::stringstream encrypt, decrypt;
    std::string password("password");

    std::string plain_checksum, decrypt_checksum;

    CryptoGuard::CryptoGuardCtx cryptor;

    ASSERT_NO_THROW(plain_checksum = cryptor.CalculateChecksum(plain_copy_for_checksum));
    ASSERT_NO_THROW(cryptor.EncryptFile(plain, encrypt, password));
    ASSERT_NO_THROW(cryptor.DecryptFile(encrypt, decrypt, password));

    std::stringstream decrypt_copy_for_checksum(decrypt.str());
    ASSERT_NO_THROW(decrypt_checksum = cryptor.CalculateChecksum(decrypt_copy_for_checksum));

    std::string decrypt_str = decrypt.str();

    ASSERT_EQ(plain_checksum, decrypt_checksum);
    ASSERT_FALSE(decrypt_str.empty());
    ASSERT_GE(plain_str.length(), decrypt_str.length());
    ASSERT_EQ(plain_str, decrypt_str);
}
