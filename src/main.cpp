#include <iostream>
#include "exploits/ExploitBase.hpp"
#include "network/NetScanner.hpp"
#include "network/NetUtils.hpp"
#include "network/Services.hpp"

int main() {
  // try {
  boost::asio::io_context io_context;
  std::string host = "192.168.0.157";
  parasyte::network::utils::RawProtocol protocol = parasyte::network::utils::RawProtocol::v4();
  int timeout = 10000;
  parasyte::network::ScannerParams params = {host, protocol, timeout, parasyte::network::ScannerType::TCP};
  parasyte::network::NetScanner net_scanner(io_context, params);
  uint16_t port_to_scan = 21;
  std::cout << "Scan started...\n";
  net_scanner.scanner->StartScan(port_to_scan);
  io_context.run();
  std::map<std::pair<boost::asio::ip::address_v4, int>, parasyte::network::port_status> port_info =
    net_scanner.scanner->port_info();

  for (const auto& entry : port_info) {
    const auto& key = entry.first;      // This is the pair of IP address and port
    const auto& status = entry.second;  // This is the port status
    net_scanner.scanner->DetectVersion(key.first);

    std::cout << "IP: " << key.first.to_string() << ", Port: " << key.second << " - Status: ";
    switch (status) {
      case parasyte::network::port_status::OPEN:
        std::cout << "OPEN";
        break;
      case parasyte::network::port_status::CLOSED:
        std::cout << "CLOSED";
        break;
      case parasyte::network::port_status::FILTERED:
        std::cout << "FILTERED";
        break;
    }
    std::cout << std::endl;
  }

  std::vector<parasyte::network::services::ServerInfo> servers_info = net_scanner.scanner->GetAllServerInfo();
  for (const auto& server_info : servers_info) {
    parasyte::exploits::ExploitBase ebase = parasyte::exploits::ExploitBase(io_context, server_info, false);
    ebase.exploiter->Exploit();
    std::cout << "Server: " << server_info.server << ", Version: " << server_info.version << ", Host: " << server_info.host
              << ", Port: " << server_info.port << std::endl;
  }

  return 0;

  // net_scanner.scanner->StartScan(port_to_scan);
  // io_context.run();
  // std::cout << "PORT\tSTATUS\n";

  // for (auto pair : net_scanner.scanner->port_info()) {
  //   using pstate = parasyte::network::port_status;
  //   static std::map<pstate, std::string> const pstr = {
  //     {pstate::OPEN, "open"},
  //     {pstate::CLOSED, "closed"},
  //     {pstate::FILTERED, "filtered"},
  //     {pstate::ABORTED, "aborted"},
  //   };
  //   std::cout << pair.first << '\t' << pstr.at(pair.second) << "\n";
  //   std::map<std::string, parasyte::network::services::IServiceDetector::resolver_results> rrs =
  //     net_scanner.scanner->GetResolverResults();
  //   if (rrs.empty()) {
  //     std::cout << "No results found\n";
  //     continue;
  //   } else {
  //     std::cout << "Host Name: " << rrs.begin()->second.host_name << "\n";
  //     std::cout << "Service Name: " << parasyte::network::utils::PortToService(rrs.begin()->second.port, "tcp") << "\n";
  //     std::cout << "Port: " << rrs.begin()->second.port << "\n";
  //     std::cout << "Protocol: " << rrs.begin()->second.protocol << "\n";
  //     net_scanner.scanner->DetectVersion();
  //   }
  // }
  // catch (const std::exception &e) {
  //   std::cerr << "Exception: " << e.what() << "\n";
  // }
  return 0;
}
