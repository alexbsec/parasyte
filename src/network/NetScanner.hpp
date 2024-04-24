#ifndef PARASYTE_NETWORK_NETSCANNER_HPP_
#define PARASYTE_NETWORK_NETSCANNER_HPP_

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
#include <netinet/in.h>
#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>

#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/basic_socket.hpp>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>

#include "../error_handler/ErrorHandler.hpp"
#include "../utils/Logger.hpp"
#include "NetUtils.hpp"
#include "Services.hpp"

/* CODE START */

namespace parasyte {
namespace network {

  std::unique_ptr<services::IVersionDetector>
  SetVersionDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port);

  enum class ScannerType {
    RAW,
    TCP,
  };

  struct ScannerParams {
      std::string host;
      parasyte::network::utils::RawProtocol::basic_raw_socket::protocol_type protocol;
      int timeout;
      ScannerType scanner_type;
  };

  class Scanner {
    public:
      using error_code = boost::system::error_code;
      using stream_buffer = boost::asio::streambuf;
      using basic_timer = boost::asio::basic_waitable_timer<std::chrono::steady_clock>;
      using shared_timer = std::shared_ptr<basic_timer>;
      using shared_buffer = std::shared_ptr<stream_buffer>;
      using LogLevel = parasyte::utils::logging::LogLevel;

      enum port_status {
        OPEN,
        CLOSED,
        FILTERED,
        ABORTED,
      };

      struct ScanInfo {
          uint16_t port;
          std::chrono::steady_clock::time_point send_time;
          uint16_t sequence_number = 0;
          uint16_t own_port = 0;
      };

      enum {
        default_timeout = 4000,
        buffer_size = 2048,
      };

      virtual ~Scanner() = default;
      virtual void StartScan(uint16_t port_number) = 0;
      virtual std::map<int, port_status> const& port_info() const {
        return port_info_;
      };
      virtual std::map<std::string, services::IServiceDetector::resolver_results> const& GetResolverResults() const = 0;
      virtual void DetectVersion() = 0;

    protected:
      std::map<int, port_status> port_info_;
      parasyte::network::services::ServerInfo server_info_ = {"", ""};
  };

  class NetScanner {
    public:
      NetScanner(boost::asio::io_context& io_context, ScannerParams const& params);
      ~NetScanner();

      void SwapScannerType(ScannerParams const& params);
      void StartScan(uint16_t port_number);
      std::unique_ptr<Scanner> scanner;

    private:
      boost::asio::io_context& io_context_;
      parasyte::utils::logging::Logger logger_ = parasyte::utils::logging::Logger("scanner.log", 0);
      parasyte::error_handler::ErrorHandler error_handler_;
  };

  class RawScanner : public Scanner {
    public:
      RawScanner(
        boost::asio::io_context& io_context,
        const std::string& host,
        parasyte::network::utils::RawProtocol::basic_raw_socket::protocol_type protocol,
        int miliseconds
      );
      ~RawScanner();

      void StartScan(uint16_t port_number) override;
      std::map<int, port_status> const& port_info() const override;
      std::map<std::string, services::IServiceDetector::resolver_results> const& GetResolverResults() const override;
      void DetectVersion() override;

    private:
      void StartTimer(int milliseconds, ScanInfo scan_info, shared_timer timer);
      void StartReceive(ScanInfo scan_info, shared_timer timer);
      void HandleScan(error_code error, std::size_t len, ScanInfo scan_info, shared_buffer buffer);
      void HandleReceive(error_code error, std::size_t len, ScanInfo scan_info, shared_buffer buffer, shared_timer timer);
      void Timeout(error_code error, ScanInfo scan_info, shared_timer timer);
      using SrcSeq = std::tuple<uint16_t, uint32_t>;
      SrcSeq MakeSegment(stream_buffer& buffer, uint16_t port);
      SrcSeq MakeIPv4Segment(stream_buffer& buffer, uint16_t port);
      SrcSeq MakeIPv6Segment(stream_buffer& buffer, uint16_t port);
      void PopulatePortInfo(int port, port_status status);
      parasyte::network::services::ServerInfo server_info_ = {"", ""};
      std::map<int, port_status> port_info_;
      services::ServiceDetector service_detector_;
      std::unique_ptr<services::IVersionDetector> version_detector_;
      std::map<std::string, services::IServiceDetector::resolver_results> resolver_results_;

      int timeout_miliseconds_;
      std::set<uint16_t> timeout_port_;
      boost::asio::io_context& io_context_;
      parasyte::network::utils::RawProtocol::basic_raw_socket socket_;
      parasyte::network::utils::RawProtocol::basic_raw_socket::protocol_type protocol_;
      parasyte::network::utils::RawProtocol::endpoint destination_;

      parasyte::network::utils::RouteTableIPv4 route_table_ipv4_;
      parasyte::network::utils::RouteTableIPv6 route_table_ipv6_;
      parasyte::error_handler::ErrorHandler error_handler_;
      parasyte::utils::logging::Logger logger_ = parasyte::utils::logging::Logger("scanner.log", 0);
  };

  class TCPScanner : public Scanner {
    public:
      TCPScanner(boost::asio::io_context& io_context, const std::string& host, int miliseconds);
      ~TCPScanner();

      void StartScan(uint16_t port_number) override;
      std::map<int, port_status> const& port_info() const override;
      std::map<std::string, services::IServiceDetector::resolver_results> const& GetResolverResults() const override;
      void DetectVersion() override;

    private:
      int timeout_milliseconds_;
      parasyte::network::services::ServerInfo server_info_ = {"", ""};
      std::map<int, port_status> port_info_;
      boost::asio::io_context& io_context_;
      std::string host_;
      parasyte::error_handler::ErrorHandler error_handler_;
      parasyte::utils::logging::Logger logger_ = parasyte::utils::logging::Logger("scanner.log", 0);
      parasyte::network::services::ServiceDetector service_detector_;
      std::unique_ptr<parasyte::network::services::IVersionDetector> version_detector_;
  };
}
}

#endif  // PARASYTE_NETWORK_NETSCANNER_HPP_
