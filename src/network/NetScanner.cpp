#include "NetScanner.hpp"
#include <netinet/ip.h>
#include <boost/asio/ip/tcp.hpp>
#include <chrono>
#include <functional>
#include <iostream>
#include <istream>
#include <ostream>
#include <random>
#include "../error_handler/ErrorHandler.hpp"
#include "../utils/Logger.hpp"
#include "NetUtils.hpp"
#include "Services.hpp"

// Placeholders to later use in std::bind
using std::placeholders::_1;
using std::placeholders::_2;

namespace parasyte {
namespace network {
  /**
   * Creates a unique pointer to an object implementing the IVersionDetector interface.
   *
   * @param io_context The boost::asio::io_context object to use for asynchronous operations.
   * @param host The host to scan for the version.
   * @param port The port to use for the scan.
   * @return A unique pointer to an object implementing the IVersionDetector interface.
   */
  std::unique_ptr<services::IVersionDetector>
  SetVersionDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port) {
    switch (port) {
      case 21:
        return std::make_unique<services::FTPDetector>(io_context, host, port);
    }
  }

  /**
   * @brief Constructs a Pinger object.
   *
   * This constructor initializes a Pinger object with the specified parameters.
   *
   * @param io_context The boost::asio::io_context object to be used for asynchronous operations.
   * @param network The IPv4 network address.
   * @param netmask The network mask in CIDR notation.
   */
  Pinger::Pinger(boost::asio::io_context& io_context, const boost::asio::ip::address_v4& network, uint8_t netmask)
      : io_context_(io_context)
      , error_handler_(error_handler::ErrorHandler::error_type::ERROR) {
    uint32_t net = network.to_uint() & MakeNetmask(netmask);
    uint32_t broadcast = net | (~MakeNetmask(netmask));

    for (uint32_t addr = net + 1; addr < broadcast; ++addr) {
      destinations_.push_back(boost::asio::ip::address_v4(addr));
    }
  }

  /**
   * @brief Destructor for the Pinger class.
   *
   */
  Pinger::~Pinger() {}

  /**
   * @brief Sends a ping request and starts receiving responses.
   *
   * This function sends a ping request to a target host and starts
   * receiving the responses asynchronously.
   */
  void Pinger::Ping() {
    logger_.Log(parasyte::utils::logging::LogLevel::INFO, "----- START PINGER -----");
    StartSend();
  }

  /**
   * @brief Starts sending ICMP echo requests to the destinations.
   *
   * This function sends ICMP echo requests to the destinations specified in the `destinations_` container.
   * If there are no destinations, it sets an error and logs a message.
   *
   * @note This function is called recursively using `boost::asio::steady_timer` to send ICMP echo requests periodically.
   *
   * @return void
   */
  void Pinger::StartSend() {
    if (destinations_.empty()) {
      error_handler_.SetType(error_handler::ErrorHandler::error_type::ERROR);
      logger_.Log(parasyte::utils::logging::LogLevel::ERROR, "No destinations to ping. Aborting pinger.");
      error_handler_.HandleError("No destinations to ping. Aborting pinger.");
      return;
    }

    bool is_up;

    for (auto dest : destinations_) {
      is_up = PingAddr(dest);
      if (is_up) {
        logger_.Log(parasyte::utils::logging::LogLevel::INFO, dest.to_string() + " is up.");
        up_hosts_.push_back(dest);
      }
    }

    if (up_hosts_.empty()) {
      logger_.Log(parasyte::utils::logging::LogLevel::INFO, "No hosts are up.");
    }
  }

  /**
   * @brief Get the vector of up hosts.
   *
   * This function returns a constant reference to a vector of `boost::asio::ip::address_v4` objects.
   * The vector contains the IP addresses of the hosts that are currently up.
   *
   * @return A constant reference to the vector of up hosts.
   */
  std::vector<boost::asio::ip::address_v4> const& Pinger::GetUpHosts() const {
    return up_hosts_;
  }

  /**
   * Calculates the network mask based on the given netmask value.
   *
   * @param netmask The netmask value (ranging from 0 to 32).
   * @return The calculated network mask.
   */
  uint32_t Pinger::MakeNetmask(uint8_t netmask) {
    return (netmask == 0) ? 0 : (~0u << (32 - netmask));
  }

  /**
   * Pings the specified IPv4 address.
   *
   * @param addr The IPv4 address to ping.
   * @return True if the ping is successful, false otherwise.
   */
  bool Pinger::PingAddr(const boost::asio::ip::address_v4& addr) {
    boost::process::ipstream pipe_stream;
    std::string ipv4_str = addr.to_string();
    std::string command = "ping -c 1 " + ipv4_str;
    boost::process::child child_process(command, boost::process::std_out > pipe_stream);
    std::string line;
    while (pipe_stream && std::getline(pipe_stream, line) && !line.empty())
      continue;
    child_process.wait();
    return child_process.exit_code() == 0;
  }

  /**
   * @brief Constructs a NetScanner object.
   *
   * This constructor initializes a NetScanner object with the given parameters.
   * It creates a scanner based on the specified scanner type and assigns it to the 'scanner' member variable.
   * If no scanner type is specified, an error is handled and the scan is aborted.
   *
   * @param io_context The boost::asio::io_context object to be used for asynchronous operations.
   * @param params The ScannerParams object containing the scanner parameters.
   */
  NetScanner::NetScanner(boost::asio::io_context& io_context, ScannerParams const& params)
      : io_context_(io_context)
      , error_handler_(error_handler::ErrorHandler::error_type::ERROR) {
    boost::asio::ip::address_v4 local_ipv4 = utils::GetLocalIPv4Address();
    switch (params.scanner_type) {
      case ScannerType::RAW:
        scanner = std::make_unique<RawScanner>(io_context, local_ipv4.to_string(), params.protocol, params.timeout);
        break;
      case ScannerType::TCP:
        scanner = std::make_unique<TCPScanner>(io_context, local_ipv4.to_string(), params.timeout);
        break;
    }

    pinger = std::make_unique<Pinger>(io_context, local_ipv4, 24);

    if (scanner == nullptr) {
      error_handler_.HandleError("No scanner type specified. Aborting scan.");
      return;
    }

    if (pinger == nullptr) {
      error_handler_.HandleError("No pinger object created. Aborting scan.");
      return;
    }
  }

  NetScanner::~NetScanner(){};

  /**
   * @brief Swaps the scanner type based on the provided parameters.
   *
   * This function creates a new scanner object based on the scanner type specified in the `params` parameter.
   * The created scanner object is then assigned to the `scanner_` member variable.
   *
   * @param params The parameters containing the scanner type, host, protocol, and timeout.
   */
  void NetScanner::SwapScannerType(ScannerParams const& params) {
    switch (params.scanner_type) {
      case ScannerType::RAW:
        scanner = std::make_unique<RawScanner>(io_context_, params.host, params.protocol, params.timeout);
        break;
      case ScannerType::TCP:
        scanner = std::make_unique<TCPScanner>(io_context_, params.host, params.timeout);
        break;
    }
  }

  RawScanner::RawScanner(
    boost::asio::io_context& io_context,
    const std::string& host,
    utils::RawProtocol::basic_raw_socket::protocol_type protocol,
    int miliseconds
  )
      : timeout_miliseconds_(miliseconds)
      , io_context_(io_context)
      , socket_(io_context.get_executor(), protocol)
      , protocol_(protocol)
      , error_handler_(error_handler::ErrorHandler::error_type::ERROR)
      , service_detector_(io_context, host, 0) {
    utils::RawProtocol::basic_resolver resolver(io_context);
    utils::RawProtocol::basic_resolver::query query(protocol, host, "", boost::asio::ip::resolver_query_base::numeric_service);
    destination_ = *resolver.resolve(query);

    // Set IPHDRINCL option for the socket
    boost::asio::socket_base::send_buffer_size option(true);
    socket_.set_option(option);
    if (protocol.family() == AF_INET) {
      socket_.set_option(utils::BinaryOption<SOL_IP, IP_HDRINCL, true>(true));
    }
  }

  RawScanner::~RawScanner() {
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
  void RawScanner::StartScan(uint16_t port_number) {
    auto buffer = std::make_shared<stream_buffer>();
    MakeSegment(*buffer, port_number);
    auto send_time = std::chrono::steady_clock::now();
    logger_.Log(LogLevel::INFO, "Scanning port " + std::to_string(port_number));
    // Asynchronously sends the data in the buffer to the destination using the socket.
    // The function async_send_to() takes the following parameters:
    // - buffer->data(): A pointer to the data in the buffer that needs to be sent.
    // - destination_: The destination endpoint to which the data will be sent.
    // - [this, buffer, scan_info = RawScanner::ScanInfo{port_number, send_time}]
    //   A lambda function that will be called when the send operation completes.
    //   It captures the current object instance (this), the buffer, and creates a scan_info object with the port_number and
    //   send_time.
    // - (const error_code& error, size_t len)
    //   The callback function that will be called when the send operation completes.
    //   It takes two parameters: error, which indicates if an error occurred during the send operation, and len, which
    //   represents the number of bytes sent. The callback function calls the HandleScan() function to handle the scan results.
    auto&& sbuffer = std::make_shared<stream_buffer>();
    socket_.async_send_to(
      buffer->data(),
      destination_,
      [this, buffer, scan_info = RawScanner::ScanInfo{port_number, send_time}]  //
      (const boost::system::error_code& error, std::size_t len) {
        logger_.Log(
          LogLevel::INFO,
          "Sent bytes from port " + std::to_string(scan_info.own_port) + " with length " + std::to_string(len) + " bytes."
        );
        if (len == 0) {
          logger_.Log(LogLevel::WARNING, "Failed to send bytes from " + std::to_string(scan_info.own_port));
        }
        this->HandleScan(error, len, scan_info, buffer);
      }
    );
  }

  /**
   * @brief Returns a constant reference to the port_info_ map.
   *
   * @return A constant reference to the port_info_ map.
   */
  std::map<int, Scanner::port_status> const& RawScanner::port_info() const {
    return port_info_;
  }

  std::map<std::string, services::IServiceDetector::resolver_results> const& RawScanner::GetResolverResults() const {
    return service_detector_.GetResolverResults();
  }

  void RawScanner::DetectVersion() {
    if (version_detector_ == nullptr) {
      error_handler_.HandleError("Version detector not set");
      return;
    }
    version_detector_->DetectVersion();
  }

  /**
   * Starts a timer with the specified duration and scan information.
   *
   * @param milliseconds The duration of the timer in milliseconds.
   * @param scan_info The scan information to be passed to the timeout handler.
   * @param timer The shared pointer to the timer object.
   */
  void RawScanner::StartTimer(int milliseconds, ScanInfo scan_info, shared_timer timer) {
    logger_.Log(LogLevel::INFO, "Starting timer for port " + std::to_string(scan_info.port));
    timer->expires_from_now(std::chrono::milliseconds(milliseconds));
    timer->async_wait(std::bind(&RawScanner::Timeout, this, _1, scan_info, timer));
  }

  /**
   * @brief Starts the asynchronous receive operation for the RawScanner.
   *
   * This function initiates the asynchronous receive operation on the socket
   * associated with the RawScanner. It prepares a buffer to receive data and
   * calls the HandleReceive function when data is received.
   *
   * @param scan_info The ScanInfo object containing scan information.
   * @param timer The shared_timer object used for timing the receive operation.
   */
  void RawScanner::StartReceive(ScanInfo scan_info, shared_timer timer) {
    auto&& buffer = std::make_shared<stream_buffer>();
    logger_.Log(LogLevel::INFO, "Receiving data for port " + std::to_string(scan_info.port));
    socket_.async_receive(
      buffer->prepare(buffer_size),  //
      std::bind(&RawScanner::HandleReceive, this, _1, _2, scan_info, buffer, timer)
    );
  }

  /**
   * @brief Handles the receive operation for the RawScanner class.
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
  void RawScanner::HandleReceive(error_code error, size_t len, ScanInfo scan_info, shared_buffer buffer, shared_timer timer) {
    // Checks if the receive operation was aborted due to a timeout.
    if (error == boost::asio::error::operation_aborted) {
      if (timeout_port_.find(scan_info.port) == timeout_port_.end()) {
        StartReceive(scan_info, timer);
      } else {
        logger_.Log(LogLevel::WARNING, "Port " + std::to_string(scan_info.port) + " timed out.");
        logger_.Log(LogLevel::INFO, "Marking port as FILTERED for port " + std::to_string(scan_info.port));
        PopulatePortInfo(scan_info.port, port_status::FILTERED);
      }
    } else if (error) {  // Checks if an error occurred during the receive operation.
      error_handler_.HandleError(error.message());
      logger_.Log(LogLevel::ERROR, "Error receiving data for port " + std::to_string(scan_info.port));
      PopulatePortInfo(scan_info.port, port_status::ABORTED);
    } else {  // Processes the received data.
      logger_.Log(LogLevel::INFO, "Received data for port " + std::to_string(scan_info.port));
      buffer->commit(len);
      utils::TCPHeader header;
      std::istream stream(&(*buffer));
      stream >> header;
      if (header.Syn() && header.Ack()) {
        logger_.Log(LogLevel::INFO, "Port " + std::to_string(scan_info.port) + " is open.");
        port_info_[header.Source()] = port_status::OPEN;
      } else if (header.Rst() && header.Ack()) {
        logger_.Log(LogLevel::INFO, "Port " + std::to_string(scan_info.port) + " is closed.");
        port_info_[header.Source()] = port_status::CLOSED;
      } else {
        logger_.Log(
          LogLevel::INFO, "Port " + std::to_string(scan_info.port) + " status cannot be determined. Starting receive again."
        );
        StartReceive(scan_info, timer);
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
  void RawScanner::HandleScan(error_code error, std::size_t len, ScanInfo scan_info, shared_buffer buffer) {
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
  void RawScanner::Timeout(error_code error, ScanInfo scan_info, [[maybe_unused]] shared_timer timer) {
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
  RawScanner::SrcSeq RawScanner::MakeSegment(stream_buffer& buffer, uint16_t port) {
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
  RawScanner::SrcSeq RawScanner::MakeIPv4Segment(stream_buffer& buffer, uint16_t port) {
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
  RawScanner::SrcSeq RawScanner::MakeIPv6Segment(stream_buffer& buffer, uint16_t port) {
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
  void RawScanner::PopulatePortInfo(int port, port_status status) {
    port_info_[port] = status;
  }

  TCPScanner::TCPScanner(boost::asio::io_context& io_context, const std::string& host, int timeout_milliseconds)
      : io_context_(io_context)
      , host_(host)
      , timeout_milliseconds_(timeout_milliseconds)
      , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR)
      , service_detector_(io_context, host, 0) {}

  TCPScanner::~TCPScanner() {
    // TODO: Implement destructor
  }

  /**
   * @brief Starts a scan on the specified port number.
   *
   * This function starts a scan on the specified port number. It sets the port number in the service detector,
   * creates a TCP socket, opens it, and asynchronously connects to the specified host and port number. If the
   * connection is successful, the port status is set to OPEN and the service detector is called to detect the service.
   * If the connection fails, the port status is set to CLOSED.
   *
   * @param port_number The port number to scan.
   */
  void TCPScanner::StartScan(uint16_t port_number) {
    version_detector_ = SetVersionDetector(io_context_, host_, port_number);
    service_detector_.SetPort(port_number);
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
    socket->open(boost::asio::ip::tcp::v4());
    socket->async_connect(
      boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(host_), port_number),
      [this, socket, port_number](const error_code& error) {
        if (!error) {
          port_info_[port_number] = port_status::OPEN;
          service_detector_.DetectService();
        } else {
          port_info_[port_number] = port_status::CLOSED;
        }
      }
    );
  }

  /**
   * @brief Get the port information.
   *
   * This function returns a constant reference to a map containing the port information.
   * The map is of type std::map<int, Scanner::port_status>, where the key is an integer representing the port number,
   * and the value is an enum Scanner::port_status representing the status of the port.
   *
   * @return A constant reference to the port information map.
   */
  std::map<int, Scanner::port_status> const& TCPScanner::port_info() const {
    return port_info_;
  }

  /**
   * @brief A map that associates a string key with a resolver_results value.
   *
   * The key is of type std::string, and the value is of type services::IServiceDetector::resolver_results.
   * This map is used to store resolver results in the TCPScanner class.
   */
  std::map<std::string, services::IServiceDetector::resolver_results> const& TCPScanner::GetResolverResults() const {
    return service_detector_.GetResolverResults();
  }

  /**
   * @brief Detects the version using the version detector.
   * If the version detector is not set, an error is handled.
   */
  void TCPScanner::DetectVersion() {
    if (version_detector_ == nullptr) {
      error_handler_.HandleError("Version detector not set");
      return;
    }
    version_detector_->DetectVersion();
    server_info_ = version_detector_->GetServerInfo();
  }

}
}
