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

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/detail/config.hpp>
#include <boost/asio/detail/push_options.hpp>
#include <boost/asio/detail/socket_types.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/ip/basic_resolver_iterator.hpp>
#include <boost/asio/ip/basic_resolver_query.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cstdint>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32  // For both 32-bit and 64-bit environments
#include <Winsock2.h>
#include <Ws2tcpip.h>
// Ensure to link against the Ws2_32.lib library
#elif defined(__linux__)
#include <linux/ipv6.h>
#elif defined(__APPLE__)
#include <netinet/ip6.h>
#endif

/* CODE START */

namespace parasyte {
namespace network {
  namespace utils {
    // Utility prototypes

    uint16_t Checksum(std::uint16_t* buffer, size_t buffer_size);
    std::string Inet6AddressToString(const struct in6_addr* addr);
    std::string Inet4AddressToString(const struct in_addr* addr);
    boost::asio::ip::address_v4 GetIPv4Address(const std::string& if_name);
    boost::asio::ip::address_v6 GetIPv6Address(const std::string& if_name);
    std::string ReadIPv6Address(std::string& str);
    std::string PortToService(uint16_t port_number, const std::string& protocol);

    // Structs
    struct in6_addr StringToAddress(std::string address);
    struct in_addr StringToAddressV4(std::string address);

    struct iphdr {
        unsigned int ihl : 4;      // IP header length
        unsigned int version : 4;  // Version
        uint8_t tos;               // Type of service
        uint16_t tot_len;          // Total length
        uint16_t id;               // Identification
        uint16_t frag_off;         // Fragment offset
        uint8_t ttl;               // Time to live
        uint8_t protocol;          // Protocol
        uint16_t check;            // Checksum
        uint32_t saddr;            // Source address
        uint32_t daddr;            // Destination address
    };

    struct RouteInfoIPv4 {
        std::string name;
        boost::asio::ip::address_v4 dest;
        boost::asio::ip::address_v4 gateway;
        boost::asio::ip::address_v4 netmask;
        int ref_count;
        int use;
        int metric;
        uint32_t flags;
        uint32_t mtu;
        uint32_t window;
        unsigned ip_route_table;
    };

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
        using endpoint = boost::asio::ip::basic_endpoint<RawProtocol>;
        using basic_raw_socket = boost::asio::basic_raw_socket<RawProtocol>;
        using basic_resolver = boost::asio::ip::basic_resolver<RawProtocol>;

        // Constructors
        static RawProtocol v4() {
          return RawProtocol(BOOST_ASIO_OS_DEF(AF_INET), IPPROTO_RAW);
        }

        static RawProtocol v6() {
          return RawProtocol(BOOST_ASIO_OS_DEF(AF_INET6), IPPROTO_RAW);
        }

        // Accessors and mutators
        int type() const {
          // Used to determine the protocol type
          return BOOST_ASIO_OS_DEF(SOCK_RAW);
        }

        int family() const {
          // Used to determine the protocol family
          return family_;
        }

        int protocol() const {
          // Used to determine the protocol
          return protocol_;
        }

        // Mutator for the protocol
        void protocol(int protocol) {
          protocol_ = protocol;
        }

        // Comparison operators
        friend bool operator==(const RawProtocol& p1, const RawProtocol& p2) {
          // We use friend here to allow access to private members
          // Used to compare two RawProtocol objects
          return p1.family_ != p2.family_;
        }

        friend bool operator!=(const RawProtocol& p1, const RawProtocol& p2) {
          // We use friend here to allow access to private members
          // Used to compare two RawProtocol objects
          return p1.family_ != p2.family_;
        }

      private:
        explicit RawProtocol(int family, int protocol) : family_(family), protocol_(protocol) {}
        int family_;
        int protocol_;
    };

    class TCPHeader {
        using header_type = struct tcphdr;

      public:
        enum {
          default_window_value = 4096,
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
          header_.res1 = reserved & 0x0F;
        }

        void DataOffset(uint16_t data_offset) {
          // Used to set the data offset
          // Bitwise AND operation to ensure that only the last four bits are set
          header_.doff = data_offset & 0x0F;
        }

        void Fin(uint16_t fin) {
          // Used to set the FIN flag
          header_.fin = (fin != 0) ? 1 : 0;
        }

        void Syn(uint16_t syn) {
          // Used to set the SYN flag
          header_.syn = (syn != 0) ? 1 : 0;
        }

        void Rst(uint16_t rst) {
          // Used to set the RST flag
          header_.rst = (rst != 0) ? 1 : 0;
        }

        void Psh(uint16_t psh) {
          // Used to set the PSH flag
          header_.psh = (psh != 0) ? 1 : 0;
        }

        void Ack(uint16_t ack) {
          // Used to set the ACK flag
          header_.ack = (ack != 0) ? 1 : 0;
        }

        void Urg(uint16_t urg) {
          // Used to set the URG flag
          header_.urg = (urg != 0) ? 1 : 0;
        }

        void Reserved2(uint16_t reserved) {
          // Used to set the reserved field
          // Bitwise AND operation to ensure that only the last two bits are set
          header_.res2 = reserved & 0x03;
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

        char* header() {
          return reinterpret_cast<char*>(&header_);
        }

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

        void CalculateChecksum(const std::string& source_addr, const std::string& destination_addr) {
          uint32_t s = static_cast<uint32_t>(GetIPv4Address(source_addr).to_ulong());
          uint32_t d = static_cast<uint32_t>(GetIPv4Address(destination_addr).to_ulong());
          CalculateChecksum(s, d);
        }

        // Overloaded operators for input and output
        friend std::istream& operator>>(std::istream& is, TCPHeader& header) {
          return is.read(header.header(), static_cast<std::streamsize>(header.length()));
        }

        friend std::ostream& operator<<(std::ostream& os, TCPHeader& header) {
          return os.write(header.header(), static_cast<std::streamsize>(header.length()));
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

    class RouteTableIPv4 {
      public:
        RouteTableIPv4();
        std::vector<RouteInfoIPv4>::const_iterator DefaultIPv4Route() const;
        std::vector<RouteInfoIPv4>::const_iterator Find(boost::asio::ip::address_v4 target) const;

      private:
        std::istream& InitStream(std::istream& stream);
        std::ifstream& ReadRouteInfo(std::ifstream& stream, RouteInfoIPv4& route_info);

        std::vector<RouteInfoIPv4> route_info_list_;
        const std::string proc_route_ipv4_{"/proc/net/route"};
    };

    class IPv4Header {
      public:
        using header_type = struct iphdr;
        IPv4Header() : header_{} {}

        uint8_t Version() const {
          return header_.version;
        }

        uint8_t HeaderLength() const {
          return header_.ihl;
        }

        uint8_t TypeOfService() const {
          return header_.tos;
        }

        uint16_t TotalLength() const {
          return ntohs(header_.tot_len);
        }

        uint16_t Identification() const {
          return ntohs(header_.id);
        }

        uint16_t FragmentOffset() const {
          return ntohs(header_.frag_off);
        }

        uint8_t TTL() const {
          return header_.ttl;
        }

        uint8_t Protocol() const {
          return header_.protocol;
        }

        uint16_t Checksum() const {
          return ntohs(header_.check);
        }

        boost::asio::ip::address_v4 SourceAddress() const {
          return boost::asio::ip::address_v4(ntohl(header_.saddr));
        }

        boost::asio::ip::address_v4 DestinationAddress() const {
          return boost::asio::ip::address_v4(ntohl(header_.daddr));
        }

        void Version(uint8_t version) {
          // Bitwise AND operation to ensure that only the last four bits are set
          header_.version = version & 0x0F;
        }

        void HeaderLength(uint8_t header_length) {
          // Bitwise AND operation to ensure that only the last four bits are set
          header_.ihl = header_length & 0x0F;
        }

        void TypeOfService(uint8_t type_of_service) {
          header_.tos = type_of_service;
        }

        void TotalLength(uint16_t total_length) {
          header_.tot_len = htons(total_length);
        }

        void Identification(uint16_t identification) {
          header_.id = htons(identification);
        }

        void FragmentOffset(uint16_t fragment_offset) {
          header_.frag_off = htons(fragment_offset);
        }

        void TTL(uint8_t ttl) {
          header_.ttl = ttl;
        }

        void Protocol(uint8_t protocol) {
          header_.protocol = protocol;
        }

        void Checksum(uint16_t checksum) {
          header_.check = htons(checksum);
        }

        void Checksum() {
          Checksum(0);
          Checksum(utils::Checksum(reinterpret_cast<uint16_t*>(&header_), static_cast<uint32_t>(Length())));
        }

        void SourceAddress(uint32_t source_address) {
          header_.saddr = htonl(source_address);
        }

        void DestinationAddress(uint32_t destination_address) {
          header_.daddr = htonl(destination_address);
        }

        void SourceAddress(boost::asio::ip::address_v4 source_address) {
          header_.saddr = htonl(static_cast<uint32_t>(source_address.to_ulong()));
        }

        void DestinationAddress(boost::asio::ip::address_v4 destination_address) {
          header_.daddr = htonl(static_cast<uint32_t>(destination_address.to_ulong()));
        }

        char* Header() {
          return reinterpret_cast<char*>(&header_);
        }

        std::size_t Length() {
          return sizeof(header_);
        }

        friend std::istream& operator>>(std::istream& stream, IPv4Header& header) {
          return stream.read(header.Header(), static_cast<std::streamsize>(header.Length()));
        }

        friend std::ostream& operator<<(std::ostream& stream, IPv4Header& header) {
          return stream.write(header.Header(), static_cast<std::streamsize>(header.Length()));
        }

      private:
        header_type header_;
    };

    class RouteTableIPv6 {
      public:
        RouteTableIPv6();
        std::vector<RouteInfoIPv6>::const_iterator DefaultIPv6Route() const;
        std::vector<RouteInfoIPv6>::const_iterator Find(boost::asio::ip::address_v6 target) const;

      private:
        auto InitStream(std::istream& stream) -> decltype(stream);
        auto ReadRouteInfo(std::ifstream& stream, RouteInfoIPv6& route_info) -> decltype(stream);

        std::vector<RouteInfoIPv6> route_info_list_;
        const std::string proc_route_ipv6_{"/proc/net/ipv6_route"};
    };

    class IPv6Header {
        using header_type = struct ipv6hdr;

      public:
        IPv6Header() : header_{} {}

        uint8_t Version() const {
          return header_.version;
        }

        uint8_t TrafficClass() const {
          return header_.priority;
        }

        uint16_t PayloadLength() const {
          return ntohs(header_.payload_len);
        }

        uint8_t NextHeader() const {
          return header_.nexthdr;
        }

        uint8_t HopLimit() const {
          return header_.hop_limit;
        }

        boost::asio::ip::address_v6 SourceAddress() const {
          return boost::asio::ip::make_address_v6(utils::Inet6AddressToString(&header_.saddr));
        }

        boost::asio::ip::address_v6 DestinationAddress() const {
          return boost::asio::ip::make_address_v6(utils::Inet6AddressToString(&header_.daddr));
        }

        void Version(uint8_t version) {
          // bitwise AND operation to ensure that only the last four bits are set
          header_.version = version & 0x0F;
        }

        void TrafficClass(uint8_t traffic_class) {
          // bitwise AND operation to ensure that only the last four bits are set
          header_.priority = traffic_class & 0x0F;
        }

        void PayloadLength(uint16_t payload_length) {
          header_.payload_len = htons(payload_length);
        }

        void NextHeader(uint8_t next_header) {
          header_.nexthdr = next_header;
        }

        void HopLimit(uint8_t hop_limit) {
          header_.hop_limit = hop_limit;
        }

        void SourceAddress(boost::asio::ip::address_v6 source_address) {
          header_.saddr = utils::StringToAddress(source_address.to_string());
        }

        void DestinationAddress(boost::asio::ip::address_v6 destination_address) {
          header_.daddr = utils::StringToAddress(destination_address.to_string());
        }

        char* Header() {
          return reinterpret_cast<char*>(&header_);
        }

        std::size_t Length() {
          return sizeof(header_);
        }

        friend std::istream& operator>>(std::istream& stream, IPv6Header& header) {
          return stream.read(header.Header(), static_cast<std::streamsize>(header.Length()));
        }

        friend std::ostream& operator<<(std::ostream& stream, IPv6Header& header) {
          return stream.write(header.Header(), static_cast<std::streamsize>(header.Length()));
        }

      private:
        header_type header_;
    };

    template<int Level, int Name, int Init = true>
    class BinaryOption {
      public:
        BinaryOption() = default;
        BinaryOption(bool option_value) : option_value_(option_value) {}
        ~BinaryOption() = default;

        template<typename Protocol>
        int level(Protocol const&) const {
          return Level;
        }

        template<typename Protocol>
        int name(Protocol const&) const {
          return Name;
        }

        template<typename Protocol>
        void* data(Protocol const&) {
          return reinterpret_cast<void*>(&option_value_);
        }

        template<typename Protocol>
        void const* data(Protocol const&) const {
          return reinterpret_cast<void const*>(&option_value_);
        }

        template<typename Protocol>
        int size(Protocol const&) const {
          return sizeof(option_value_);
        }

        void SetOptionValue(bool option_value) {
          option_value_ = option_value;
        }

        bool GetOptionValue() const {
          return option_value_;
        }

      private:
        bool option_value_ = Init;
    };

  }
}
}

#endif  // PARASYTE_NETWORK_NETUTILS_HPP_
