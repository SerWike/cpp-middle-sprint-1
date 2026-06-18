#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <ios>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream input, output;
            std::string password = options.GetPassword();

            input.open(options.GetInputFile(), std::ios_base::in);
            if (!input.is_open())
                throw std::runtime_error(std::format("Failed to open input file: \"{}\"", options.GetInputFile()));
            output.open(options.GetOutputFile(), std::ios_base::out);
            if (!output.is_open())
                throw std::runtime_error(std::format("Failed to open output file: \"{}\"", options.GetOutputFile()));

            cryptoCtx.EncryptFile(input, output, password);

            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream input, output;
            std::string password = options.GetPassword();

            input.open(options.GetInputFile(), std::ios_base::in);
            if (!input.is_open())
                throw std::runtime_error(std::format("Failed to open input file: \"{}\"", options.GetInputFile()));
            output.open(options.GetOutputFile(), std::ios_base::out);
            if (!output.is_open())
                throw std::runtime_error(std::format("Failed to open output file: \"{}\"", options.GetOutputFile()));

            cryptoCtx.DecryptFile(input, output, password);

            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream input;
            input.open(options.GetInputFile(), std::ios_base::in);
            if (!input.is_open())
                throw std::runtime_error(std::format("Failed to open input file: \"{}\"", options.GetInputFile()));

            std::string checksum = cryptoCtx.CalculateChecksum(input);
            std::print("Checksum: {}\n", checksum);
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}