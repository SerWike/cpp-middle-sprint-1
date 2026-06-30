#include "cmd_options.h"
#include <gtest/gtest.h>

TEST(ProgramOptions, ValidParamTest) {
    char *argv[] = {
        (char *)"Reserved for executable file path",
        (char *)"--command",
        (char *)"encrypt",
        (char *)"-i",
        (char *)"input.txt",
        (char *)"-o",
        (char *)"output.txt",
        (char *)"-p",
        (char *)"password",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};

    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT, options.GetCommand());
    EXPECT_EQ("input.txt", options.GetInputFile());
    EXPECT_EQ("output.txt", options.GetOutputFile());
    EXPECT_EQ("password", options.GetPassword());
}

TEST(ProgramOptions, ValidParamTestDifferentOrder) {
    char *argv[] = {
        (char *)"Reserved for executable file path",
        (char *)"-o",
        (char *)"output.txt",
        (char *)"--command",
        (char *)"decrypt",
        (char *)"-p",
        (char *)"password",
        (char *)"-i",
        (char *)"input.txt",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};

    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT, options.GetCommand());
    EXPECT_EQ("input.txt", options.GetInputFile());
    EXPECT_EQ("output.txt", options.GetOutputFile());
    EXPECT_EQ("password", options.GetPassword());
}

TEST(ProgramOptions, EmptyParamWhenUseHelp) {
    char *argv[] = {(char *)"Reserved for executable file path", (char *)"--help"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};

    testing::internal::CaptureStdout();
    EXPECT_NO_THROW(options.Parse(argc, argv));
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_FALSE(output.empty());
    EXPECT_EQ((CryptoGuard::ProgramOptions::COMMAND_TYPE)-1, options.GetCommand());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, InvalidCommand) {
    char *argv[] = {(char *)"Reserved for executable file path", (char *)"--command", (char *)"invalid"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};
    EXPECT_THROW(options.Parse(argc, argv), std::runtime_error);

    EXPECT_EQ((CryptoGuard::ProgramOptions::COMMAND_TYPE)-1, options.GetCommand());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, NoParamValue) {
    char *argv[] = {(char *)"Reserved for executable file path", (char *)"--input"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};
    EXPECT_THROW(options.Parse(argc, argv), std::runtime_error);

    EXPECT_EQ((CryptoGuard::ProgramOptions::COMMAND_TYPE)-1, options.GetCommand());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, NoParams) {
    char *argv[] = {(char *)"Reserved for executable file path"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options = {};
    EXPECT_NO_THROW(options.Parse(argc, argv));

    EXPECT_EQ((CryptoGuard::ProgramOptions::COMMAND_TYPE)-1, options.GetCommand());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}
