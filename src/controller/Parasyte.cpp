/*
    Copyright (C) 2024 by alexbsec
    Permission is hereby granted, free of charge, to any person obtaining a copy of this
    software and associated documentation files (the "Software"), to deal in the Software
    without restriction, including without l> imitation the rights to use, copy, modify, merge,
    publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
    to whom the Software is furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or
    substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
    BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
    OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Include declarations

#include "Parasyte.hpp"
#include "Cli.hpp"

/* CODE START */

namespace parasyte {
namespace controller {
  cli::ScanCommand::ScanCommand(parasyte::network::NetScanner& net_scanner, const parasyte::network::ScannerParams& params, std::vector<uint16_t> ports) 
  : net_scanner_(net_scanner), params_(params), ports_(ports) {}

  void cli::ScanCommand::Execute() {
    output_ = parasyte::utils::general::OutputWidget(3, "Starting scan...");
    boost::asio::ip::address_v4 ip = boost::asio::ip::make_address_v4(params_.host);
    net_scanner_.SetUpHosts({ip});
    for (auto port : ports_) {
      output_ = parasyte::utils::general::OutputWidget(3, "Scanning port " + std::to_string(port) + "...");
      net_scanner_.scanner->StartScan(port);
      net_scanner_.RunIoContext();
      std::map<std::pair<boost::asio::ip::address_v4, int>, parasyte::network::port_status> port_info = net_scanner_.scanner->port_info();
      for (const auto& entry : port_info) {
        const auto& key = entry.first;
        const auto& status = entry.second;
        net_scanner_.scanner->DetectVersion(key.first);
      }
    }

    output_ = parasyte::utils::general::OutputWidget(0, "Scan complete.");
  }

  void cli::TargetCommand::Execute() {}

  cli::MemoryCommand::MemoryCommand(parasyte::network::NetScanner& net_scanner) : net_scanner_(net_scanner) {}

  void cli::MemoryCommand::Execute() {
    std::map<std::pair<boost::asio::ip::address_v4, int>, parasyte::network::port_status> port_info_map = net_scanner_.scanner->port_info();
    std::vector<parasyte::network::services::ServerInfo> server_info = net_scanner_.scanner->GetAllServerInfo();
    bool is_scan_complete = net_scanner_.scanner->IsScanComplete();
    if (!is_scan_complete) {
      output_ = parasyte::utils::general::OutputWidget(1, "Scan yet to be completed.");
      return;
    }

    if (port_info_map.empty()) {
      output_ = parasyte::utils::general::OutputWidget(2, "Something went wrong as the scan completed with no output.");
      return;
    }

    cache_lines_.push_back("\n======== PORT SCAN INFO ========\n");

    for (const auto& entry : port_info_map) {
      const auto& key = entry.first;
      const auto& status = entry.second;
      std::string status_str;
      switch (status) {
        case parasyte::network::port_status::OPEN:
          status_str = "OPEN";
          break;
        case parasyte::network::port_status::CLOSED:
          status_str = "CLOSED";
          break;
        case parasyte::network::port_status::FILTERED:
          status_str = "FILTERED";
          break;
        default:
          status_str = "UNKNOWN";
          break;
      }
      cache_lines_.push_back("Host: " + key.first.to_string() + " Port: " + std::to_string(key.second) + " Status: " + status_str + "\n");
    }

    cache_lines_.push_back("======== SERVERS INFO ========\n");


    if (server_info.empty()) {
      cache_lines_.push_back("No servers found.\n");
    } else {
      for (const auto& server : server_info) {
        cache_lines_.push_back("Server: " + server.server + " Version: " + server.version + " Host: " + server.host + " Port: " + std::to_string(server.port) + "\n");
      }
    }

    for (const auto& line : cache_lines_) {
      output_ = parasyte::utils::general::OutputWidget(4, line);
    }
  }

  cli::CLI::CLI(parasyte::network::NetScanner& net_scanner, const parasyte::network::ScannerParams& params, std::vector<uint16_t> ports) :
  net_scanner_(net_scanner), params_(params), ports_(ports) {
      commands_["scan"] = std::make_shared<cli::ScanCommand>(net_scanner_, params_, ports_);
      commands_["memory"] = std::make_shared<cli::MemoryCommand>(net_scanner_);
  }

  cli::CLI::~CLI() {}

  void cli::CLI::Run(const std::string& cmd) {
    if (commands_.find(cmd) != commands_.end()) {
      commands_[cmd]->Execute();
    } else {
      parasyte::utils::general::OutputWidget(0, "Command not found.");
    }
  }

  Parasyte::Parasyte(boost::asio::io_context& io_context, const ScannerParams& params, std::vector<uint16_t> ports) : 
  io_context_(io_context), params_(params), net_scanner_(io_context, params), ports_(ports), error_handler_(error_handler::ErrorHandler::error_type::ERROR)  {}

  void Parasyte::Init() {
    cli::CLI cli(net_scanner_, params_, ports_);

    std::string input;
    while (true) {
      std::cout << "parasyte >> ";
      std::cin >> input;
      if (input == "exit") {
        break;
      }
      cli.Run(input);
    }
  }

  Parasyte::~Parasyte() {}

}
}