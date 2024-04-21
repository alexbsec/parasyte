#include <iostream>
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
  net_scanner.scanner->StartScan(port_to_scan);
  io_context.run();
  std::cout << "PORT\tSTATUS\n";

  for (auto pair : net_scanner.scanner->port_info()) {
    using pstate = parasyte::network::Scanner::port_status;
    static std::map<pstate, std::string> const pstr = {
      {pstate::OPEN, "open"},
      {pstate::CLOSED, "closed"},
      {pstate::FILTERED, "filtered"},
      {pstate::ABORTED, "aborted"},
    };
    std::cout << pair.first << '\t' << pstr.at(pair.second) << "\n";
    std::map<std::string, parasyte::network::services::IServiceDetector::resolver_results> rrs =
      net_scanner.scanner->GetResolverResults();
    if (rrs.empty()) {
      std::cout << "No results found\n";
      continue;
    } else {
      std::cout << "Host Name: " << rrs.begin()->second.host_name << "\n";
      std::cout << "Service Name: " << parasyte::network::utils::PortToService(rrs.begin()->second.port, "tcp") << "\n";
      std::cout << "Port: " << rrs.begin()->second.port << "\n";
      std::cout << "Protocol: " << rrs.begin()->second.protocol << "\n";
    }
  }
  // catch (const std::exception &e) {
  //   std::cerr << "Exception: " << e.what() << "\n";
  // }
  return 0;
}
