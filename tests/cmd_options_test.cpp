#include "cmd_options.h"
#include <gtest/gtest.h>

TEST(ProgramOptions, CorrectChecksumTest) {
    char *argv[] = {
        "Reserved for executable file path", "--command", "checksum", "-i", "input.txt",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};
    options.Parse(argc, argv);

    EXPECT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM, options.GetCommand());
    EXPECT_EQ("input.txt", options.GetInputFile());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, CorrectEncryptTest) {
    char *argv[] = {"Reserved for executable file path",
                    "--command",
                    "encrypt",
                    "--input",
                    "raw.txt",
                    "-o",
                    "encrypted.txt",
                    "-p",
                    "1234"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};
    options.Parse(argc, argv);

    EXPECT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT, options.GetCommand());
    EXPECT_EQ("raw.txt", options.GetInputFile());
    EXPECT_EQ("encrypted.txt", options.GetOutputFile());
    EXPECT_EQ("1234", options.GetPassword());
}

TEST(ProgramOptions, CorrectDecryptTest) {
    char *argv[] = {"Reserved for executable file path",
                    "--command",
                    "decrypt",
                    "-i",
                    "encrypted.txt",
                    "--output",
                    "decrypted.txt",
                    "-p",
                    "1234"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};
    options.Parse(argc, argv);

    EXPECT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT, options.GetCommand());
    EXPECT_EQ("encrypted.txt", options.GetInputFile());
    EXPECT_EQ("decrypted.txt", options.GetOutputFile());
    EXPECT_EQ("1234", options.GetPassword());
}

TEST(ProgramOptions, InvalidCommandTest) {
    char *argv[] = {"Reserved for executable file path",
                    "--command",
                    "invalid",
                    "-i",
                    "input.txt",
                    "--output",
                    "output.txt",
                    "-p",
                    "password"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};
    options.Parse(argc, argv);

    EXPECT_NE(CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM, options.GetCommand());
    EXPECT_NE(CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT, options.GetCommand());
    EXPECT_NE(CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT, options.GetCommand());
    EXPECT_EQ("input.txt", options.GetInputFile());
    EXPECT_EQ("output.txt", options.GetOutputFile());
    EXPECT_EQ("password", options.GetPassword());
}
