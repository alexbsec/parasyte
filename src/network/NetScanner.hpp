#ifndef PARASYTE_NETWORK_NETSCANNER_HPP_
#define PARASYTE_NETWORK_NETSCANNER_HPP_

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
#include <vector>
#include <string>
#include <iostream>

/* CODE START */

namespace parasyte {
namespace network {
  // struct for storing host information
  struct NetworkHost {
  std::string ip_address;
  std::string mac_address;
  int port;
  std::string service_name;
  bool is_vulnerable;

  NetworkHost(std::string ip, int p, std::string service, bool vulnerable) 
  : ip_address(ip), port(p), service_name(service), is_vulnerable(vulnerable) {}
  };

  // Class declaration for the NetScanner
  class NetScanner {
  public:
    NetScanner();
    ~NetScanner();

    // Disallow copy and move constructors for safety
    NetScanner(const NetScanner&) = delete;
    NetScanner& operator=(const NetScanner&) = delete;

    // Retrieves the list of discovered hosts
    std::vector<NetworkHost> GetHosts() const;
    
  private:
    std::vector<NetworkHost> hosts_;
      
    // Private methods
    void ScanIPAddress(const std::string& ip_address);
    bool GetName(std::string name, std::string dest);
    bool GetMacAddress(std::string mac, std::string dest);

    // Utility methods
    bool IsPortOpen(const std::string& ip_address, int port);
  };
  
}
}


#endif // PARASYTE_NETWORK_NETSCANNER_HPP_