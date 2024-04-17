#include "network/NetScanner.hpp"
#include "network/NetUtils.hpp"
#include <iostream>

int main() {
    try {
        boost::asio::io_context io_context;
        std::string host = "192.168.88.88";
        parasyte::network::utils::RawProtocol protocol = parasyte::network::utils::RawProtocol::v4();
        int timeout = 10000;
        parasyte::network::NetScanner scanner(io_context, host, protocol, timeout);
        int port_to_scan = 22;
        scanner.StartScan(port_to_scan);
        io_context.run();
        std::cout << "PORT\tSTATUS" << "\n";
        for (auto pair : scanner.PortInfo()) {
            using pstate = parasyte::network::NetScanner::port_status;
            static std::map<pstate, std::string> const pstr = {
                {pstate::OPEN, "open"}, {pstate::CLOSED, "closed"},
                {pstate::FILTERED, "filtered"}, {pstate::ABORTED, "aborted"}
            };
            std::cout << pair.first << '\t' << pstr.at(pair.second) << "\n";
        }
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n"; 
    }
    return 0;
}