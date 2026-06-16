#include "cmd_options.h"

#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    this->desc_.add_options()("help", "Help message");
    this->desc_.add_options()("command", po::value<std::string>(),
                              "Command (allowed 'encrypt', 'decrypt', 'checksum')");
    this->desc_.add_options()("input,i", po::value<std::string>(), "Input file");
    this->desc_.add_options()("output,o", po::value<std::string>(), "Output file");
    this->desc_.add_options()("password,p", po::value<std::string>(), "Password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, this->desc_), vm);
        po::notify(vm);
    } catch (const std::exception &e) {
        throw std::runtime_error(std::format("Failed to parse parameters: %s", e.what()));
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
            throw std::runtime_error(
                std::format("Invalid command: %s\n Allowed: 'encrypt', 'decrypt', 'checksum'", param_command));
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
