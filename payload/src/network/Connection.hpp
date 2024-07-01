#ifndef PARASYTE_PAYLOAD_NETWORK_CONNECTION_HPP_
#define PARASYTE_PAYLOAD_NETWORK_CONNECTION_HPP_

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

/* CODE START */

namespace parasyte {
namespace payload {
  namespace network {
    class Connection {
      public:
        Connection(boost::asio::io_context& io_context, const std::string& rhost_encrypted, const uint16_t& rport);
        ~Connection();

      private:
        boost::asio::io_context& io_context_;
        std::string rhost_encrypted_;
        uint16_t rport_;
    };

  }
}
}

#endif // PARASYTE_PAYLOAD_NETWORK_CONNECTION_HPP_