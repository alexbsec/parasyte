#include <iostream>
#include "exploits/ExploitBase.hpp"
#include "network/Services.hpp"
#include "controller/Parasyte.hpp"

int main () {
  boost::asio::io_context io_context;
  std::string host = "192.168.0.203";
  boost::asio::ip::address_v4 ip = boost::asio::ip::make_address_v4(host);
  parasyte::network::utils::RawProtocol protocol = parasyte::network::utils::RawProtocol::v4();
  int timeout = 10000;
  parasyte::network::ScannerParams params = {host, protocol, timeout, parasyte::network::ScannerType::TCP, true};
  std::vector<uint16_t> ports = {21};
  parasyte::controller::Parasyte parasyte(io_context, params, ports);
  parasyte.Init();
  return 0;
}

