#ifndef PARASYTE_NETWORK_SERVICES_HPP_
#define PARASYTE_NETWORK_SERVICES_HPP_

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
#include <boost/asio/basic_socket.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "../error_handler/ErrorHandler.hpp"
#include "../utils/Logger.hpp"

/* CODE START */

namespace parasyte {
namespace network {
  namespace services {
    using error_code = boost::system::error_code;
    using tcp = boost::asio::ip::tcp;
    using tcp_socket = tcp::socket;
    using tcp_resolver = tcp::resolver;
    using tcp_resolver_results = tcp::resolver::results_type;

    class IServiceDetector {
      public:
        virtual ~IServiceDetector() = default;
        virtual void DetectService() = 0;
    };

    class IVersionDetector {
      public:
        virtual ~IVersionDetector() = default;
        virtual void DetectVersion() = 0;
    };

    class ServiceDetector : public IServiceDetector {
      public:
        ServiceDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port);
        ~ServiceDetector() override;

        void DetectService() override;

      private:
        void ResolveHost();
        void OnResolveHost(const error_code& ec, tcp_resolver_results results);
        void OnConnect(const error_code& ec);
        boost::asio::io_context& io_context_;
        std::string host_;
        uint16_t port_;
    };

    class VersionDetector : IVersionDetector {
      public:
        VersionDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port);
        ~VersionDetector() override;

        void DetectVersion() override;

      private:
        void ResolveHost();
        void OnResolveHost(const error_code& ec, tcp_resolver_results results);
        void OnConnect(const error_code& ec);
        boost::asio::io_context& io_context_;
        std::string host_;
        uint16_t port_;
    };

    class FTPDetector : public ServiceDetector {
      public:
        FTPDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port);
        ~FTPDetector() override;

        void DetectService() override;
    };

    class SMBDetector : public ServiceDetector {
      public:
        SMBDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port);
        ~SMBDetector() override;

        void DetectService() override;
    };

  }
}
}

#endif  // PARASYTE_NETWORK_SERVICES_HPP_