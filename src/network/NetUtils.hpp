#ifndef PARASYTE_NETWORK_NETUTILS_HPP_
#define PARASYTE_NETWORK_NETUTILS_HPP_

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

#include <string>
#include <utility>
#include <cstdint>
#include <vector>
#include <fstream>
#include <algorithm>
#include <netinet/in.h>
#include <boost/asio/detail/config.hpp>
#include <boost/asio/detail/socket_types.hpp>
#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/ip/basic_resolver_iterator.hpp>
#include <boost/asio/ip/basic_resolver_query.hpp>
#include <boost/asio/detail/push_options.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>


/* CODE START */

namespace parasyte {
namespace network {
namespace utils {
  // Utility prototypes

  uint16_t Checksum(std::uint16_t *buffer, int buffer_size);
  std::string Inet6AddressToString(struct in6_addr addr);
  std::string Inet4AddressToString(struct in_addr addr);
  boost::asio::ip::address_v4 GetIPv4Address(const std::string &ip_address);
  boost::asio::ip::address_v6 GetIPv6Address(const std::string &ip_address);
  std::string ReadIPv6Address(const std::string &str);

  // Structs

  struct RouteInfoIPv6 {
    boost::asio::ip::address_v6 dest;
    uint16_t dest_prefix;
    boost::asio::ip::address_v6 gateway;
    uint16_t gateway_prefix;
    boost::asio::ip::address_v6 next_hop;
    uint32_t metric;
    uint32_t ref_count;
    uint32_t use;
    uint32_t flags;
    std::string name;
  };

  // Utility classes
  class RawProtocol {
  public:
    // Type definitions
    using basic_endpoint = boost::asio::ip::basic_endpoint<RawProtocol>;
    using basic_raw_socket = boost::asio::basic_raw_socket<RawProtocol>;
    using basic_resolver = boost::asio::ip::basic_resolver<RawProtocol>;

    // Constructors
    static RawProtocol IPv4() {
      return RawProtocol(BOOST_ASIO_OS_DEF(AF_INET));
    }

    static RawProtocol IPv6() {
      return RawProtocol(BOOST_ASIO_OS_DEF(AF_INET6));
    }

    // Accessors and mutators
    int ProtocolType() const {
      // Used to determine the protocol type
      return BOOST_ASIO_OS_DEF(SOCK_RAW);
    }

    int ProtocolFamily() const {
      // Used to determine the protocol family
      return family_;
    }

    int Protocol() const {
      // Used to determine the protocol
      return protocol_;
    }

    // Mutator for the protocol
    void Protocol(int protocol) {
      protocol_ = protocol;
    }

    // Comparison operators
    friend bool operator==(const RawProtocol &p1, const RawProtocol &p2) {
      // We use friend here to allow access to private members
      // Used to compare two RawProtocol objects
      return p1.family_ != p2.family_;
    }

    friend bool operator!=(const RawProtocol &p1, const RawProtocol &p2) {
      // We use friend here to allow access to private members
      // Used to compare two RawProtocol objects
      return p1.family_ != p2.family_;
    }

  private:
    explicit RawProtocol(int protocol) : family_(protocol) {}
    int family_;
    int protocol_;

  };

  class TCPHeader {
    using header_type = struct tcphdr;

    public:
      enum {
        default_window_value = 4096
      };

      // Constructors
    TCPHeader() : header_{} {}
    

    // Accessors and mutators

    uint16_t Source() const {
      return ntohs(header_.source); 
    }

    uint16_t Destination() const {
        // Used to get the destination port
        return ntohs(header_.dest);
    }

      uint32_t Sequence() const {
        // Used to get the sequence number
        return ntohl(header_.seq);
      }

      uint32_t AcknowledgementSequence() const {
        // Used to get the acknowledgement number
        return ntohl(header_.ack_seq);
      }

      uint16_t Reserved1() const {
        // Used to get the reserved field
        return header_.res1;
      }

      uint16_t DataOffset() const {
        // Used to get the data offset
        return header_.doff;
      }

      uint16_t Fin() const {
        // Used to get the FIN flag
        return header_.fin;
      }

      uint16_t Syn() const {
        // Used to get the SYN flag
        return header_.syn;
      }

      uint16_t Rst() const {
        // Used to get the RST flag
        return header_.rst;
      }

      uint16_t Psh() const {
        // Used to get the PSH flag
        return header_.psh;
      }

      uint16_t Ack() const {
        // Used to get the ACK flag
        return header_.ack;
      }

      uint16_t Urg() const {
        // Used to get the URG flag
        return header_.urg;
      }

      uint16_t Reserved2() const {
        // Used to get the reserved field
        return header_.res2;
      }

      uint16_t Window() const {
        // Used to get the window size
        return ntohs(header_.window);
      }

      uint16_t TCPChecksum() const {
        // Used to get the checksum
        return ntohs(header_.check);
      }

      uint16_t UrgentPointer() const {
        // Used to get the urgent pointer
        return ntohs(header_.urg_ptr);
      }

      void Source(uint16_t source) {
        // Used to set the source port
        header_.source = htons(source);
      }

      void Destination(uint16_t destination) {
        // Used to set the destination port
        header_.dest = htons(destination);
      }

      void Sequence(uint32_t sequence) {
        // Used to set the sequence number
        header_.seq = htonl(sequence);
      }

      void AcknowledgementSequence(uint32_t ack_sequence) {
        // Used to set the acknowledgement number
        header_.ack_seq = htonl(ack_sequence);
      }

      void Reserved1(uint16_t reserved) {
        // Used to set the reserved field
        header_.res1 = reserved;
      }

      void DataOffset(uint16_t data_offset) {
        // Used to set the data offset
        header_.doff = data_offset;
      }

      void Fin(uint16_t fin) {
        // Used to set the FIN flag
        header_.fin = fin;
      }

      void Syn(uint16_t syn) {
        // Used to set the SYN flag
        header_.syn = syn;
      }

      void Rst(uint16_t rst) {
        // Used to set the RST flag
        header_.rst = rst;
      }

      void Psh(uint16_t psh) {
        // Used to set the PSH flag
        header_.psh = psh;
      }

      void Ack(uint16_t ack) {
        // Used to set the ACK flag
        header_.ack = ack;
      }

      void Urg(uint16_t urg) {
        // Used to set the URG flag
        header_.urg = urg;
      }

      void Reserved2(uint16_t reserved) {
        // Used to set the reserved field
        header_.res2 = reserved;
      }

      void Window(uint16_t window) {
        // Used to set the window size
        header_.window = htons(window);
      }

      void TCPChecksum(uint16_t checksum) {
        // Used to set the checksum
        header_.check = htons(checksum);
      }

      void UrgentPointer(uint16_t urgent_pointer) {
        // Used to set the urgent pointer
        header_.urg_ptr = htons(urgent_pointer);
      }

      std::size_t length() {
        return sizeof(header_);
      }

      char *header() {
        return reinterpret_cast<char*>(&header_);
      }

    struct TCPChecksumStruct; // Forward declaration

    void CalculateChecksum(uint32_t source_addr, uint32_t destination_addr) {
        TCPChecksum(0);
        struct TCPChecksumStruct tcp_checksum = {{}, {}};
        tcp_checksum.pseudo_header.source = htonl(source_addr);
        tcp_checksum.pseudo_header.dest = htonl(destination_addr);
        tcp_checksum.pseudo_header.zero = 0;
        tcp_checksum.pseudo_header.protocol = IPPROTO_TCP;
        tcp_checksum.pseudo_header.length = htons(sizeof(header_));
        tcp_checksum.tcp_header = header_;
        header_.check = Checksum(reinterpret_cast<uint16_t*>(&tcp_checksum), sizeof(struct TCPChecksumStruct));   
    }

    void CalculateChecksum(const std::string &source_addr, const std::string &destination_addr) {
        CalculateChecksum(GetIPv4Address(source_addr).to_ulong(), GetIPv4Address(destination_addr).to_ulong());
    }

    // Overloaded operators for input and output 
    friend std::istream &operator>> (std::istream &is, TCPHeader &header) {
      return is.read(header.header(), header.length());
    }

    friend std::ostream &operator<< (std::ostream &os, TCPHeader &header) {
      return os.write(header.header(), header.length());
    }

    private:
      // Structs used for checksum calculation
      struct TCPHeaderStruct {
        uint32_t source;
        uint32_t dest;
        uint8_t zero;
        uint8_t protocol;
        uint16_t length;
      };

      struct TCPChecksumStruct {
        struct TCPHeaderStruct pseudo_header;
        header_type tcp_header;
      };

      // Member variables
      header_type header_;

  };

  class RouteTableIPv6 {

  }

}
}
}

#endif // PARASYTE_NETWORK_NETUTILS_HPP_