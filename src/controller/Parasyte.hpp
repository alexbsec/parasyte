#ifndef PARASYTE_CONTROLLER_PARASYTE_HPP_
#define PARASYTE_CONTROLLER_PARASYTE_HPP_

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

#include "../error_handler/ErrorHandler.hpp"
#include "../exploits/ExploitBase.hpp"
#include "../network/NetScanner.hpp"
#include "../utils/Logger.hpp"

/* CODE START */

namespace parasyte {
namespace controller {
  class Parasyte {
      using ServerInfo = parasyte::network::services::ServerInfo;
      using IExploiter = parasyte::exploits::IExploiter;
      using ExploitBase = parasyte::exploits::ExploitBase;
      using NetScanner = parasyte::network::NetScanner;
      using Logger = parasyte::utils::logging::Logger;
      using ScannerParams = parasyte::network::ScannerParams;
      using ErrorHandler = parasyte::error_handler::ErrorHandler;

    public:
      Parasyte(boost::asio::io_context& io_context, const ScannerParams& params, std::vector<uint16_t> ports);
      ~Parasyte();

    private:
      boost::asio::io_context& io_context_;
      NetScanner net_scanner_;
      std::vector<uint16_t> ports_;
      Logger logger_ = Logger("parasyte.log");
      ErrorHandler error_handler_;
      std::map<std::pair<boost::asio::ip::address_v4, int>, bool> is_host_port_infected_;

      // Methods
  };
}
}

#endif  // PARASYTE_CONTROLLER_PARASYTE_HPP_