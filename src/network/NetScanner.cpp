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

    return nullptr;
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
    pinger = std::make_unique<Pinger>(io_context, local_ipv4, 24);
    if (params.send_ping) {
      std::cout << "Pinger created. Starting to ping...\n";
      Ping();
    } else {
      // assumes host param is up
      up_hosts_.push_back(boost::asio::ip::address_v4::from_string(params.host));
    }
    switch (params.scanner_type) {
      case ScannerType::RAW:
        // scanner = std::make_unique<RawScanner>(io_context, local_ipv4.to_string(), params.protocol, params.timeout);
        break;
      case ScannerType::TCP:
        scanner = std::make_unique<TCPScanner>(io_context, up_hosts_, params.timeout);
        break;
    }

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
        // scanner = std::make_unique<RawScanner>(io_context_, params.host, params.protocol, params.timeout);
        break;
      case ScannerType::TCP:
        scanner = std::make_unique<TCPScanner>(io_context_, up_hosts_, params.timeout);
        break;
    }
  }

  /**
   * @brief Sends a ping request to the hosts and retrieves the list of hosts that are up.
   *
   * This function sends a ping request to the hosts using the `pinger` object and retrieves
   * the list of hosts that are up.
   *
   * @note The `pinger` object must be initialized before calling this function.
   */
  void NetScanner::Ping() {
    pinger->Ping();
    up_hosts_ = pinger->GetUpHosts();
  }

  std::vector<boost::asio::ip::address_v4> const& NetScanner::GetUpHosts() const {
    return up_hosts_;
  }

  TCPScanner::TCPScanner(
    boost::asio::io_context& io_context,
    const std::vector<boost::asio::ip::address_v4>& hosts,
    int timeout_milliseconds
  )
      : io_context_(io_context)
      , hosts_(hosts)
      , timeout_milliseconds_(timeout_milliseconds)
      , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR) {
    for (auto host : hosts_) {
      service_detectors_.try_emplace(host, io_context, host.to_string(), static_cast<uint16_t>(0));
    }
  }
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
    for (auto host_ : hosts_) {
      version_detectors_.try_emplace(host_, SetVersionDetector(io_context_, host_.to_string(), port_number));
      service_detectors_.at(host_).SetPort(port_number);
      auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
      socket->open(boost::asio::ip::tcp::v4());
      socket->async_connect(
        boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(host_.to_string()), port_number),
        [this, socket, port_number, host_](const error_code& error) {
          if (!error) {
            port_info_[std::make_pair(host_, port_number)] = port_status::OPEN;
            service_detectors_.at(host_).DetectService();
          } else {
            port_info_[std::make_pair(host_, port_number)] = port_status::CLOSED;
          }
          hosts_ports_.emplace(host_, port_number);
        }
      );
    }
    is_scan_complete_ = true;
  }

  /**
   * @brief Get the port information.
   *
   * This function returns a constant reference to a map containing the port information.
   * The map is of type std::map<int, port_status>, where the key is an integer representing the port number,
   * and the value is an enum port_status representing the status of the port.
   *
   * @return A constant reference to the port information map.
   */
  std::map<std::pair<boost::asio::ip::address_v4, int>, port_status> const& TCPScanner::port_info() const {
    return port_info_;
  }

  /**
   * @brief A map that associates a string key with a resolver_results value.
   *
   * The key is of type std::string, and the value is of type services::IServiceDetector::resolver_results.
   * This map is used to store resolver results in the TCPScanner class.
   */
  std::map<std::string, services::IServiceDetector::resolver_results> const& TCPScanner::GetResolverResults(
    boost::asio::ip::address_v4 host
  ) const {
    return service_detectors_.at(host).GetResolverResults();
  }

  /**
   * @brief Detects the version using the version detector.
   * If the version detector is not set, an error is handled.
   */
  void TCPScanner::DetectVersion(boost::asio::ip::address_v4 host) {
    if (version_detectors_.at(host) == nullptr || version_detectors_.empty()) {
      error_handler_.SetType(error_handler::ErrorHandler::error_type::ERROR);
      error_handler_.HandleError("Version detector not set");
      return;
    }

    if (port_info_.empty()) {
      error_handler_.SetType(error_handler::ErrorHandler::error_type::ERROR);
      error_handler_.HandleError("Port info is empty");
      return;
    }

    if (port_info_.at(std::make_pair(host, hosts_ports_.at(host))) != port_status::OPEN) {
      return;
    }

    version_detectors_.at(host)->DetectVersion();
    servers_info_.push_back(version_detectors_.at(host)->GetServerInfo());
  }

  std::vector<parasyte::network::services::ServerInfo> TCPScanner::GetAllServerInfo() {
    // for (auto info : servers_info_) {
    //   std::cout << "server: " << info.server << std::endl;
    // }
    return servers_info_;
  }

}
}
