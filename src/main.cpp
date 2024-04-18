#include <iostream>
#include "network/NetScanner.hpp"
#include "network/NetUtils.hpp"

int main() {
  try {
    boost::asio::io_context io_context;
    std::string host = "127.0.0.1";
    parasyte::network::utils::RawProtocol protocol = parasyte::network::utils::RawProtocol::v4();
    int timeout = 10000;
    parasyte::network::ScannerParams params = {host, protocol, timeout, parasyte::network::ScannerType::RAW};
    parasyte::network::NetScanner net_scanner(io_context, params);
    uint16_t port_to_scan = 5555;
    net_scanner.StartScan(port_to_scan);
    io_context.run();
    std::cout << "PORT\tSTATUS\n";
    auto const &info = net_scanner.scanner->port_info();
    for (auto pair : net_scanner.scanner->port_info()) {
      using pstate = parasyte::network::Scanner::port_status;
      static std::map<pstate, std::string> const pstr = {
        {pstate::OPEN, "open"},
        {pstate::CLOSED, "closed"},
        {pstate::FILTERED, "filtered"},
        {pstate::ABORTED, "aborted"},
      };
      std::cout << pair.first << '\t' << pstr.at(pair.second) << "\n";
    }
  }
  catch (const std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
