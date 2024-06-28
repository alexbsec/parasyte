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

#include <boost/asio.hpp>
#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/basic_socket.hpp>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/bind/bind.hpp>
#include <boost/process.hpp>

#include "../error_handler/ErrorHandler.hpp"
#include "../utils/Logger.hpp"
#include "NetUtils.hpp"
#include "Services.hpp"

/* CODE START */

namespace parasyte {
namespace network {

  std::unique_ptr<services::IVersionDetector>
  SetVersionDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port);

  enum class port_status {
    OPEN,
    CLOSED,
    FILTERED,
    ABORTED,
  };

  enum class ScannerType {
    RAW,
    TCP,
  };

  struct ScannerParams {
      std::string host;
      parasyte::network::utils::RawProtocol::basic_raw_socket::protocol_type protocol;
      int timeout;
      ScannerType scanner_type;
      bool send_ping;
  };

  class Pinger {
    public:
      Pinger(boost::asio::io_context& io_context, const boost::asio::ip::address_v4& network, uint8_t netmask);
      ~Pinger();

      void Ping();
      void StartSend();
      void SetUpHosts(std::vector<boost::asio::ip::address_v4> const& hosts) {
        up_hosts_ = hosts;
      }
      std::vector<boost::asio::ip::address_v4> const& GetUpHosts() const;

    private:
      static unsigned short GetIdentifier() {
#if defined(BOOST_ASIO_WINDOWS)
        return static_cast<unsigned short>(::GetCurrentProcessId());
#else
        return static_cast<unsigned short>(::getpid());
#endif
      }
      boost::asio::io_context& io_context_;
      std::vector<boost::asio::ip::address_v4> destinations_;
      std::vector<boost::asio::ip::address_v4> up_hosts_;
      uint32_t MakeNetmask(uint8_t netmask);
      bool PingAddr(const boost::asio::ip::address_v4& addr);
      parasyte::error_handler::ErrorHandler error_handler_;
      parasyte::utils::logging::Logger logger_ = parasyte::utils::logging::Logger("parasyte.log");
  };

  class Scanner {
    public:
      using error_code = boost::system::error_code;
      using stream_buffer = boost::asio::streambuf;
      using basic_timer = boost::asio::basic_waitable_timer<std::chrono::steady_clock>;
      using shared_timer = std::shared_ptr<basic_timer>;
      using shared_buffer = std::shared_ptr<stream_buffer>;
      using LogLevel = parasyte::utils::logging::LogLevel;

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
      virtual std::map<std::pair<boost::asio::ip::address_v4, int>, port_status> const& port_info() const {
        return port_info_;
      };
      virtual std::map<std::string, services::IServiceDetector::resolver_results> const& GetResolverResults(
        boost::asio::ip::address_v4 host
      ) const = 0;
      virtual void DetectVersion(boost::asio::ip::address_v4 host) = 0;
      virtual std::vector<parasyte::network::services::ServerInfo> GetAllServerInfo() = 0;
      virtual bool IsScanComplete() const = 0;
      virtual void SetUpHosts(std::vector<boost::asio::ip::address_v4> const& hosts) = 0;
      virtual void EmplaceServiceDetector() = 0;

    protected:
      std::map<std::pair<boost::asio::ip::address_v4, int>, port_status> port_info_;
      std::vector<parasyte::network::services::ServerInfo> servers_info_ = {{"", "", "", 0}};
  };

  class NetScanner {
    public:
      NetScanner(boost::asio::io_context& io_context, ScannerParams const& params);
      NetScanner(const NetScanner&) = delete;
      NetScanner& operator=(const NetScanner&) = delete;
      ~NetScanner();

      void SwapScannerType(ScannerParams const& params);
      void StartScan(uint16_t port_number);
      void Ping();
      void SetUpHosts(std::vector<boost::asio::ip::address_v4> const& hosts) {
        if (pinger != nullptr) {
          pinger->SetUpHosts(hosts);
        }
        up_hosts_ = hosts;
        scanner->SetUpHosts(hosts);
        scanner->EmplaceServiceDetector();
      }
      void RunIoContext() {
        io_context_.run();
      }
      boost::asio::io_context& GetIoContext() {
        return io_context_;
      }
      std::unique_ptr<Scanner> scanner;
      std::unique_ptr<Pinger> pinger;
      std::vector<boost::asio::ip::address_v4> const& GetUpHosts() const;

    private:
      boost::asio::io_context& io_context_;
      parasyte::utils::logging::Logger logger_ = parasyte::utils::logging::Logger("parasyte.log", 0);
      parasyte::error_handler::ErrorHandler error_handler_;
      std::vector<boost::asio::ip::address_v4> up_hosts_;
  };

  class TCPScanner : public Scanner {
    public:
      TCPScanner(boost::asio::io_context& io_context, const std::vector<boost::asio::ip::address_v4>& hosts, int miliseconds);
      ~TCPScanner();

      void StartScan(uint16_t port_number) override;
      std::map<std::pair<boost::asio::ip::address_v4, int>, port_status> const& port_info() const override;
      std::map<std::string, services::IServiceDetector::resolver_results> const& GetResolverResults(
        boost::asio::ip::address_v4 host
      ) const override;
      void DetectVersion(boost::asio::ip::address_v4 host) override;
      std::vector<parasyte::network::services::ServerInfo> GetAllServerInfo() override;
      bool IsScanComplete() const {
        return is_scan_complete_;
      }
      void SetUpHosts(std::vector<boost::asio::ip::address_v4> const& hosts) {
        hosts_ = hosts;
      }
      void EmplaceServiceDetector() {
        for (auto& host : hosts_) {
          service_detectors_.try_emplace(host, io_context_, host.to_string(), static_cast<uint16_t>(0));
        }
      }

    private:
      int timeout_milliseconds_;
      bool is_scan_complete_ = false;
      std::vector<parasyte::network::services::ServerInfo> servers_info_ = {{"", "", "", 0}};
      std::map<boost::asio::ip::address_v4, int> hosts_ports_;
      std::map<std::pair<boost::asio::ip::address_v4, int>, port_status> port_info_;
      boost::asio::io_context& io_context_;
      std::vector<boost::asio::ip::address_v4> hosts_ = {};
      parasyte::error_handler::ErrorHandler error_handler_;
      parasyte::utils::logging::Logger logger_ = parasyte::utils::logging::Logger("parasyte.log", 0);
      std::map<boost::asio::ip::address_v4, parasyte::network::services::ServiceDetector> service_detectors_;
      std::map<boost::asio::ip::address_v4, std::unique_ptr<parasyte::network::services::IVersionDetector>> version_detectors_;
  };
}
}

#endif  // PARASYTE_NETWORK_NETSCANNER_HPP_
