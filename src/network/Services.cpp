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

#include "Services.hpp"
#include <iostream>
#include "NetUtils.hpp"

/* CODE START */

namespace parasyte {
namespace network {
  namespace services {
    ServiceDetector::ServiceDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port)
        : io_context_(io_context)
        , host_(host)
        , port_(port)
        , resolver_(io_context)
        , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR) {}

    ServiceDetector::~ServiceDetector() {}

    void ServiceDetector::DetectService() {
      ResolveHost();
    }

    std::map<std::string, IServiceDetector::resolver_results> const& ServiceDetector::GetResolverResults() const {
      return resolver_results_;
    }

    void ServiceDetector::ResolveHost() {
      tcp_resolver::query query(host_, std::to_string(port_));
      resolver_.async_resolve(query, [this](const error_code& ec, tcp_resolver_results results) {
        if (ec) {
          error_handler_.HandleError(ec.message());
          return;
        }

        for (const auto& result : results) {
          auto endpoint = result.endpoint();
          resolver_results_[endpoint.address().to_string()] = resolver_results{
            result.host_name(), result.service_name(), endpoint.port(), std::to_string(endpoint.protocol().protocol())
          };
        }
      });
    }

    VersionDetector::VersionDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port)
        : io_context_(io_context)
        , host_(host)
        , port_(port)
        , resolver_(io_context)
        , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR) {}

    VersionDetector::~VersionDetector() {}

    void VersionDetector::GrabBanner() {}

    void VersionDetector::DetectVersion() {}
  }
}
}