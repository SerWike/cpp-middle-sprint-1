#include "cmd_options.h"

#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <print>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    this->desc_.add_options()("help", "Help message")("command", po::value<std::string>(),
                                                      "Command (allowed 'encrypt', 'decrypt', 'checksum')")(
        "input,i", po::value<std::string>(), "Input file")("output,o", po::value<std::string>(), "Output file")(
        "password,p", po::value<std::string>(), "Password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, this->desc_), vm);
        po::notify(vm);
    } catch (const std::exception &e) {
        std::print("Failed to parse parameters: %s", e.what());
    }

    if (vm.contains("help")) {
        this->desc_.print(std::cout);
        return;
    }

    if (vm.contains("command")) {
        std::string_view param_command = vm["command"].as<std::string>();
        if (this->commandMapping_.contains(param_command))
            this->command_ = this->commandMapping_.at(param_command);
        else {
            std::print("Invalid command: %s", param_command);
            this->desc_.print(std::cout);
        }
    }
    if (vm.contains("input"))
        this->inputFile_ = vm["input"].as<std::string>();
    if (vm.contains("output"))
        this->outputFile_ = vm["output"].as<std::string>();
    if (vm.contains("password"))
        this->password_ = vm["password"].as<std::string>();
}

}  // namespace CryptoGuard
