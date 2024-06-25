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

  // Parasyte::Parasyte(boost::asio::io_context& io_context, const ScannerParams& params, std::vector<uint16_t> ports) : 
  // io_context_(io_context), net_scanner_(io_context, params), ports_(ports) {}

  Parasyte::~Parasyte() {}

}
}