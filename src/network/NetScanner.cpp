#include <netinet/ip.h>
#include <chrono>
#include <functional>
#include <iostream>
#include <istream>
#include <ostream>
#include <random>

#include "../error_handler/ErrorHandler.hpp"
#include "NetScanner.hpp"
#include "NetUtils.hpp"

// Placeholders to later use in std::bind
using std::placeholders::_1;
using std::placeholders::_2;

namespace parasyte {
namespace network {
  NetScanner::NetScanner(
    boost::asio::io_context& io_context,
    const std::string& host,
    utils::RawProtocol::basic_raw_socket::protocol_type protocol,
    int miliseconds
  )
      : timeout_miliseconds_(miliseconds)
      , io_context_(io_context)
      , socket_(io_context.get_executor(), protocol)
      , protocol_(protocol)
      , error_handler_(error_handler::ErrorHandler::error_type::ERROR) {
    utils::RawProtocol::basic_resolver resolver(io_context);
    utils::RawProtocol::basic_resolver::query query(protocol, host, "", boost::asio::ip::resolver_query_base::numeric_service);
    destination_ = *resolver.resolve(query);
    if (protocol.family() == AF_INET) {
      socket_.set_option(utils::BinaryOption<SOL_IP, IP_HDRINCL, true>(true));
    }
  }

  NetScanner::~NetScanner() {
    socket_.close();
  }

  /**
   * @brief Starts a network scan on the specified port number.
   *
   * This function initiates a network scan by creating a segment buffer, making the segment with the specified port number,
   * and sending the segment asynchronously to the destination. It also handles the scan results by calling the HandleScan
   * function.
   *
   * @param port_number The port number to scan.
   */
  void NetScanner::StartScan(uint16_t port_number) {
    auto buffer = std::make_shared<stream_buffer>();
    MakeSegment(*buffer, port_number);
    auto send_time = std::chrono::steady_clock::now();
    // Asynchronously sends the data in the buffer to the destination using the socket.
    // The function async_send_to() takes the following parameters:
    // - buffer->data(): A pointer to the data in the buffer that needs to be sent.
    // - destination_: The destination endpoint to which the data will be sent.
    // - [this, buffer, scan_info = NetScanner::ScanInfo{port_number, send_time}]
    //   A lambda function that will be called when the send operation completes.
    //   It captures the current object instance (this), the buffer, and creates a scan_info object with the port_number and
    //   send_time.
    // - (const error_code& error, size_t len)
    //   The callback function that will be called when the send operation completes.
    //   It takes two parameters: error, which indicates if an error occurred during the send operation, and len, which
    //   represents the number of bytes sent. The callback function calls the HandleScan() function to handle the scan results.
    socket_.async_send_to(
      buffer->data(),
      destination_,
      [this, buffer, scan_info = NetScanner::ScanInfo{port_number, send_time}]  //
      (const boost::system::error_code& error, std::size_t len) {
        this->HandleScan(error, len, scan_info, buffer);
      }
    );
  }

  /**
   * @brief Returns a constant reference to the port_info_ map.
   *
   * @return A constant reference to the port_info_ map.
   */
  std::map<int, NetScanner::port_status> const& NetScanner::port_info() const {
    return port_info_;
  }

  /**
   * Starts a timer with the specified duration and scan information.
   *
   * @param milliseconds The duration of the timer in milliseconds.
   * @param scan_info The scan information to be passed to the timeout handler.
   * @param timer The shared pointer to the timer object.
   */
  void NetScanner::StartTimer(int milliseconds, ScanInfo scan_info, shared_timer timer) {
    timer->expires_from_now(std::chrono::milliseconds(milliseconds));
    timer->async_wait(std::bind(&NetScanner::Timeout, this, _1, scan_info, timer));
  }

  /**
   * @brief Starts the asynchronous receive operation for the NetScanner.
   *
   * This function initiates the asynchronous receive operation on the socket
   * associated with the NetScanner. It prepares a buffer to receive data and
   * calls the HandleReceive function when data is received.
   *
   * @param scan_info The ScanInfo object containing scan information.
   * @param timer The shared_timer object used for timing the receive operation.
   */
  void NetScanner::StartReceive(ScanInfo scan_info, shared_timer timer) {
    auto&& buffer = std::make_shared<stream_buffer>();
    socket_.async_receive(
      buffer->prepare(buffer_size),  //
      std::bind(&NetScanner::HandleReceive, this, _1, _2, scan_info, buffer, timer)
    );
  }

  /**
   * @brief Handles the receive operation for the NetScanner class.
   *
   * This function is called when a receive operation completes. It processes the received data,
   * updates the port status information, and handles any errors that occur during the operation.
   *
   * @param error The error code associated with the receive operation.
   * @param len The number of bytes received.
   * @param scan_info The scan information associated with the receive operation.
   * @param buffer The shared buffer containing the received data.
   * @param timer The shared timer used for timeout handling.
   */
  void NetScanner::HandleReceive(error_code error, size_t len, ScanInfo scan_info, shared_buffer buffer, shared_timer timer) {
    // Checks if the receive operation was aborted due to a timeout.
    if (error == boost::asio::error::operation_aborted) {
      if (timeout_port_.find(scan_info.port) == timeout_port_.end()) {
        StartReceive(scan_info, timer);
      } else {
        PopulatePortInfo(scan_info.port, port_status::FILTERED);
      }
      return;
    } else if (error) {  // Checks if an error occurred during the receive operation.
      error_handler_.HandleError(error.message());
      PopulatePortInfo(scan_info.port, port_status::ABORTED);
    } else {  // Processes the received data.
      buffer->commit(len);
      utils::TCPHeader header;
      std::istream stream(&(*buffer));
      stream >> header;
      if (header.Syn() && header.Ack()) {
        port_info_[header.Source()] = port_status::OPEN;
      } else if (header.Rst() && header.Ack()) {
        port_info_[header.Source()] = port_status::CLOSED;
      } else {
        StartReceive(scan_info, timer);
        return;
      }
    }
    timer->cancel();
  }

  /**
   * @brief Handles the completion of a network scan.
   *
   * This function is called when a network scan operation is completed. It checks for any errors and
   * calls the appropriate error handler if an error occurred. If no error occurred, it starts a timer
   * and initiates the receive operation for the scan.
   *
   * @param error The error code, if any, that occurred during the scan.
   * @param len The size of the received data.
   * @param scan_info The information about the scan.
   * @param buffer The shared buffer containing the received data.
   */
  void NetScanner::HandleScan(error_code error, std::size_t len, ScanInfo scan_info, shared_buffer buffer) {
    if (error) {
      error_handler_.HandleError(error.message());
    } else {
      shared_timer timer = std::make_shared<basic_timer>(io_context_);
      StartTimer(timeout_miliseconds_, scan_info, timer);
      StartReceive(scan_info, timer);
    }
  }

  /**
   * @brief Handles the timeout event for a network scan.
   *
   * This function is called when a timeout occurs during network scan. It checks the error code
   * and performs the necessary actions based on the error. If the error is an operation aborted error,
   * the function simply returns. If the error is any other type of error, it calls the error handler's
   * HandleError function with the error message. If there is no error, it adds the port associated with
   * the scan to the timeout_port_ set and cancels the socket.
   *
   * @param error The error code associated with the timeout event.
   * @param scan_info The information about the scan that timed out.
   * @param timer The shared timer object used for the scan.
   */
  void NetScanner::Timeout(error_code error, ScanInfo scan_info, [[maybe_unused]] shared_timer timer) {
    if (error == boost::asio::error::operation_aborted) {
      return;
    } else if (error) {
      error_handler_.HandleError(error.message());
    } else {
      timeout_port_.insert(scan_info.port);
      socket_.cancel();
    }
  }

  /**
   * @brief Function to create a segment for network scanning.
   *
   * This function takes a stream buffer and a port number as input and returns a tuple of two integers.
   * The first integer represents the starting index of the segment in the buffer, and the second integer represents the length
   * of the segment.
   *
   * @param buffer The stream buffer to create the segment from.
   * @param port The port number to include in the segment.
   * @return A tuple of two integers representing the segment.
   */
  NetScanner::SrcSeq NetScanner::MakeSegment(stream_buffer& buffer, uint16_t port) {
    if (protocol_.family() == AF_INET)  //
      return MakeIPv4Segment(buffer, port);
    return MakeIPv6Segment(buffer, port);
  }

  /**
   * @brief Creates an IPv4 segment using the provided stream buffer and port number.
   *
   * This tuple is used to store the result of the MakeIPv4Segment function.
   * The first integer represents the source address, and the second integer represents the destination address.
   *
   * @param buffer The stream buffer used to construct the IPv4 segment.
   * @param port The destination port for the TCP header.
   * @return A tuple of two integers representing the source and destination addresses.
   */
  NetScanner::SrcSeq NetScanner::MakeIPv4Segment(stream_buffer& buffer, uint16_t port) {
    buffer.consume(buffer.size());
    std::ostream stream(&buffer);
    utils::IPv4Header ipv4_header;
    auto daddr = destination_.address().to_v4();
    ipv4_header.Version(4);
    ipv4_header.HeaderLength((ipv4_header.Length() / 4) & 0xff);
    ipv4_header.TypeOfService(0x10);
    ipv4_header.FragmentOffset(IP_DF);  // Fix: Include the necessary header file that defines the constant "IP_DF"
    ipv4_header.TTL(IPDEFTTL);
    ipv4_header.Protocol(IPPROTO_TCP);
    ipv4_header.SourceAddress(utils::GetIPv4Address(route_table_ipv4_.Find(daddr)->name));
    ipv4_header.DestinationAddress(daddr);

    thread_local static std::mt19937 rng(std::random_device{}());
    uint16_t source = std::uniform_int_distribution<uint16_t>{}(rng);
    uint32_t sequence = std::uniform_int_distribution<uint32_t>{}(rng);
    utils::TCPHeader tcp_header;
    tcp_header.Source(source);
    tcp_header.Destination(port);
    tcp_header.Sequence(sequence);
    tcp_header.DataOffset(20 / 4);
    tcp_header.Syn(true);
    tcp_header.Window(utils::TCPHeader::default_window_value);
    {
      uint32_t s = static_cast<uint32_t>(ipv4_header.SourceAddress().to_ulong());
      uint32_t d = static_cast<uint32_t>(ipv4_header.DestinationAddress().to_ulong());
      tcp_header.CalculateChecksum(s, d);
    }

    ipv4_header.TotalLength(static_cast<uint16_t>(ipv4_header.Length() + tcp_header.length()));
    ipv4_header.Checksum();

    if (!(stream << ipv4_header << tcp_header)) {
      error_handler_.HandleError("Error creating IPv4 segment. Aborting scan.");
      return std::make_tuple(0, 0);
    }

    return {source, sequence};
  }

  /**
   * @brief Creates an IPv6 segment using the provided stream buffer and port number.
   *
   * @param buffer The stream buffer to use for creating the segment.
   * @param port The port number to set in the TCP header of the segment.
   * @return A tuple containing the source and sequence numbers of the segment.
   */
  NetScanner::SrcSeq NetScanner::MakeIPv6Segment(stream_buffer& buffer, uint16_t port) {
    buffer.consume(buffer.size());
    std::ostream stream(&buffer);

    utils::IPv6Header ipv6_header;
    auto daddr = destination_.address().to_v6();
    ipv6_header.Version(6);
    ipv6_header.NextHeader(IPPROTO_TCP);
    ipv6_header.SourceAddress(utils::GetIPv6Address(route_table_ipv6_.Find(daddr)->name));
    ipv6_header.DestinationAddress(daddr);

    thread_local static std::mt19937 rng(std::random_device{}());
    uint16_t source = std::uniform_int_distribution<uint16_t>{}(rng);
    uint32_t sequence = std::uniform_int_distribution<uint32_t>{}(rng);
    utils::TCPHeader tcp_header;
    tcp_header.Source(source);
    tcp_header.Destination(port);
    tcp_header.Sequence(sequence);
    tcp_header.DataOffset(20 / 4);
    tcp_header.Syn(true);
    tcp_header.Window(utils::TCPHeader::default_window_value);

    if (!(stream << ipv6_header << tcp_header)) {
      error_handler_.HandleError("Error creating IPv6 segment. Aborting scan.");
      return std::make_tuple(0, 0);
    }

    return {source, sequence};
  }

  /**
   * @brief Populates the port information for a given port.
   *
   * This function adds the port information to the port_info_ map if it doesn't already exist.
   *
   * @param port The port number.
   * @param status The status of the port.
   */
  void NetScanner::PopulatePortInfo(int port, port_status status) {
    if (port_info_.find(port) == port_info_.end()) {
      port_info_[port] = status;
    }
  }

}
}
