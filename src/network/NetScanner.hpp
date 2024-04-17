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
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>

#include "../error_handler/ErrorHandler.hpp"
#include "NetUtils.hpp"

/* CODE START */

namespace parasyte {
namespace network {
  class NetScanner {
      using error_code = boost::system::error_code;
      using stream_buffer = boost::asio::streambuf;
      using basic_timer = boost::asio::basic_waitable_timer<std::chrono::steady_clock>;
      using shared_timer = std::shared_ptr<basic_timer>;
      using shared_buffer = std::shared_ptr<stream_buffer>;

      struct ScanInfo {
          uint16_t port;
          std::chrono::steady_clock::time_point send_time;
          uint16_t sequence_number = 0;
          uint16_t own_port = 0;
      };

    public:
      enum port_status {
        OPEN,
        CLOSED,
        FILTERED,
        ABORTED,
      };

      enum {
        default_timeout = 4000,
        buffer_size = 2048,
      };

      NetScanner(
        boost::asio::io_context& io_context,
        const std::string& host,
        parasyte::network::utils::RawProtocol::basic_raw_socket::protocol_type protocol,
        int miliseconds
      );
      ~NetScanner();

      void StartScan(uint16_t port_number);
      std::map<int, port_status> const& port_info() const;

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

      int timeout_miliseconds_;
      std::set<uint16_t> timeout_port_;
      boost::asio::io_context& io_context_;
      parasyte::network::utils::RawProtocol::basic_raw_socket socket_;
      parasyte::network::utils::RawProtocol::basic_raw_socket::protocol_type protocol_;
      parasyte::network::utils::RawProtocol::endpoint destination_;
      std::map<int, port_status> port_info_;
      parasyte::network::utils::RouteTableIPv4 route_table_ipv4_;
      parasyte::network::utils::RouteTableIPv6 route_table_ipv6_;
      parasyte::error_handler::ErrorHandler error_handler_;
  };
}
}

#endif  // PARASYTE_NETWORK_NETSCANNER_HPP_
