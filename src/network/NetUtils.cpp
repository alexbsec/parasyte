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

#include "NetUtils.hpp"
#include <iostream>
#include <arpa/inet.h> 

/* CODE START */

/**
 * Calculates the checksum of a buffer.
 * 
 * @param buffer The buffer containing the data to calculate the checksum for.
 * @param buffer_size The size of the buffer in bytes.
 * @return The calculated checksum value.
 */
uint16_t parasyte::network::utils::Checksum(std::uint16_t *buffer, size_t buffer_size) {
  unsigned long sum = 0; // Initialize the sum variable to 0
  while (buffer_size > 1) { // Iterate through the buffer in 16-bit chunks
    sum += *buffer++; // Add the value at the current buffer location to the sum
    buffer_size -= 2; // Decrease the buffer size by 2 bytes
  }
  
  if (buffer_size == 1) sum += *(unsigned char *)buffer; // If there is an odd byte remaining, add it to the sum
  sum = (sum & 0xFFFF) + (sum >> 16); // Add the carry bits to the sum
  sum = (sum & 0xFFFF) + (sum >> 16); // Add any remaining carry bits
  return static_cast<uint16_t>(~sum); // Return the one's complement of the sum as the checksum value
}

/**
 * Converts an IPv6 address to a string representation.
 * 
 * @param addr The IPv6 address to convert.
 * @return The string representation of the IPv6 address.
 */
std::string parasyte::network::utils::Inet6AddressToString(const struct in6_addr *addr) {
  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
  return std::string(str);
}

/**
 * Converts an IPv4 address to a string representation.
 * 
 * @param addr The IPv4 address to convert.
 * @return The string representation of the IPv4 address.
 */
std::string parasyte::network::utils::Inet4AddressToString(const struct in_addr *addr) {
  char str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, addr, str, INET_ADDRSTRLEN);
  return std::string(str);
}

/**
 * Retrieves the IPv4 address associated with a given network interface.
 * 
 * @param if_name The name of the network interface.
 * @return The IPv4 address associated with the network interface.
 */
boost::asio::ip::address_v4 parasyte::network::utils::GetIPv4Address(const std::string &if_name) {
  int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // Create a socket for communication
  struct ifreq ifr; // Create a structure to hold the network interface information
  ifr.ifr_addr.sa_family = AF_INET; // Set the address family to IPv4
  strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ-1); // Copy the network interface name to the structure
  ioctl(socket_fd, SIOCGIFADDR, &ifr); // Retrieve the network interface address using the ioctl system call
  close(socket_fd); // Close the socket
  return boost::asio::ip::address_v4(ntohl(((struct sockaddr_in *) &ifr.ifr_addr) -> sin_addr.s_addr)); // Convert the retrieved address to boost::asio::ip::address_v4 format and return it
}

/**
 * Retrieves the IPv6 address associated with a given network interface.
 * 
 * @param if_name The name of the network interface.
 * @return The IPv6 address associated with the network interface.
 */
boost::asio::ip::address_v6 parasyte::network::utils::GetIPv6Address(const std::string &if_name) {
  int socket_fd = socket(AF_INET6, SOCK_DGRAM, 0); // Create a socket for communication
  struct ifreq ifr; // Create a structure to hold the network interface information
  ifr.ifr_addr.sa_family = AF_INET6; // Set the address family to IPv6
  strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ-1); // Copy the network interface name to the structure
  ioctl(socket_fd, SIOCGIFADDR, &ifr); // Retrieve the network interface address using the ioctl system call
  close(socket_fd); // Close the socket
  std::string address_string = Inet6AddressToString(&((struct sockaddr_in6 *)&ifr.ifr_addr)->sin6_addr);
  return boost::asio::ip::make_address_v6(address_string); // Convert the retrieved address to boost::asio::ip::address_v6 format and return it
}

/**
 * Inserts colons into an IPv6 address string to format it properly.
 * 
 * @param str The IPv6 address string to format.
 * @return The formatted IPv6 address string.
 */
std::string parasyte::network::utils::ReadIPv6Address(std::string &str) {
  for (unsigned i = 4; i != str.size(); i += 5) {
    str.insert(i, ":");
  }
  return str;
}

/** Converts a string representation of an IPv6 address to a struct in6_addr.
* 
* @param address The string representation of the IPv6 address.
* @return The struct in6_addr representing the IPv6 address.
*/

#include <netinet/in.h> // Include the header file that defines the in6_addr structure

struct in6_addr parasyte::network::utils::StringToAddress(std::string address) {
  struct in6_addr addr;
  inet_pton(AF_INET6, address.c_str(), &(addr));
  return addr;
}

/* Classes implementation */

/**
 * Constructor for the RouteTableIPv4 class.
 * Reads the route information from the /proc/net/route file and initializes the route_info_list_ member variable.
 */
parasyte::network::utils::RouteTableIPv4::RouteTableIPv4() {
  std::ifstream route_table_ipv4_proc(proc_route_ipv4_);
  InitStream(route_table_ipv4_proc);
  for (RouteInfoIPv4 route_info_ipv4; ReadRouteInfo(route_table_ipv4_proc, route_info_ipv4);) {
    route_info_list_.push_back(route_info_ipv4);
  }
}

/**
 * Finds the default IPv4 route in the route table.
 * 
 * @return An iterator pointing to the default IPv4 route, or `route_info_list_.end()` if not found.
 */
std::vector<parasyte::network::utils::RouteInfoIPv4>::const_iterator parasyte::network::utils::RouteTableIPv4::DefaultIPv4Route() const {
  // Use std::find_if algorithm to search for the default IPv4 route in the route_info_list_
  return std::find_if(route_info_list_.begin(), route_info_list_.end(), [](RouteInfoIPv4 const& route_info){
    // The lambda function is the callback that is passed to std::find_if
    // It takes a RouteInfoIPv4 object as input and returns a boolean value
    // The lambda function checks if the destination address of the route_info object is equal to boost::asio::ip::address_v4()
    // If it is, it returns true and std::find_if stops the search and returns the iterator pointing to the current route_info object
    // If it is not, it returns false and std::find_if continues the search
    return route_info.dest == boost::asio::ip::address_v4();
  });
}

/**
 * Finds the route in the route table that matches the given target IPv4 address.
 * 
 * @param target The target IPv4 address to find in the route table.
 * @return An iterator pointing to the matching route, or `route_info_list_.end()` if not found.
 */
std::vector<parasyte::network::utils::RouteInfoIPv4>::const_iterator parasyte::network::utils::RouteTableIPv4::Find(boost::asio::ip::address_v4 target) const {
  std::vector<RouteInfoIPv4>::const_iterator default_route_table = DefaultIPv4Route(); // Get the iterator pointing to the default IPv4 route in the route table
  std::vector<RouteInfoIPv4>::const_iterator it = route_info_list_.begin(); // Initialize the iterator to the beginning of the route_info_list_

  for (; it != route_info_list_.end(); ++it) { // Iterate through each route in the route_info_list_
    if (it == default_route_table) continue; // Skip the default route
    if (boost::asio::ip::address_v4::broadcast(target, it -> netmask) == it -> dest) break; // Check if the broadcast address of the target matches the destination address of the current route
  }

  return (it == route_info_list_.end()) ? default_route_table : it; // Return the iterator pointing to the matching route, or the iterator pointing to the default route if no match is found
}

/**
 * @brief The std::istream class is a base class for input streams.
 * 
 * It provides a common interface for reading data from different sources, such as files, strings, or network connections.
 * InitStream is a virtual function that initializes the input stream by reading a line of text from the stream.
 * @param stream The input stream to initialize.
 * @return The initialized input stream.
 * @see https://en.cppreference.com/w/cpp/io/basic_istream
 */
std::istream &parasyte::network::utils::RouteTableIPv4::InitStream(std::istream &stream) {
  std::string line;
  return std::getline(stream, line);
}

/**
 * Reads the route information from the input stream and populates the RouteInfoIPv4 object.
 * 
 * @param stream The input stream to read from.
 * @param route_info The RouteInfoIPv4 object to populate.
 * @return The input stream after reading the route information.
 */
std::ifstream &parasyte::network::utils::RouteTableIPv4::ReadRouteInfo(std::ifstream &stream, RouteInfoIPv4 &route_info) {
  uint32_t dest, gateway, netmask;

  stream >> route_info.name >> std::hex >> dest >> gateway >> std::dec >> route_info.flags >> route_info.ref_count >> route_info.use >> route_info.metric >> std::hex >> netmask >> std::dec >> route_info.mtu >> route_info.window >> route_info.ip_route_table;
  route_info.dest = boost::asio::ip::address_v4(ntohl(dest));
  route_info.gateway = boost::asio::ip::address_v4(ntohl(gateway));
  route_info.netmask = boost::asio::ip::address_v4(ntohl(netmask));

  return stream;
}

/**
* @brief Constructor for the RouteTableIPv6 class.
* Reads the route information from the /proc/net/route file and initializes the route_info_list_ member variable.
*/ 
parasyte::network::utils::RouteTableIPv6::RouteTableIPv6() {
  std::ifstream route_table_ipv6_proc(proc_route_ipv6_); // Open the /proc/net/route file for reading
  InitStream(route_table_ipv6_proc); // Initialize the input stream by reading a line of text from the file
  for (RouteInfoIPv6 route_info; ReadRouteInfo(route_table_ipv6_proc, route_info);) {
    route_info_list_.push_back(route_info); // Add the read route information to the route_info_list_
    break; // Exit the loop after reading the first route information
  }
}

/**
 * @brief Returns an iterator pointing to the first occurrence of a default IPv6 route in the route_info_list_ vector.
 * 
 * @return std::vector<parasyte::network::utils::RouteInfoIPv6>::const_iterator An iterator pointing to the default IPv6 route, or the end iterator if not found.
 */
std::vector<parasyte::network::utils::RouteInfoIPv6>::const_iterator parasyte::network::utils::RouteTableIPv6::DefaultIPv6Route() const {
  return std::find_if(route_info_list_.begin(), route_info_list_.end(), [](RouteInfoIPv6 const &route_info) {
    return route_info.dest == boost::asio::ip::address_v6();
  });
}

/**
 * @brief Finds the iterator pointing to the first occurrence of a given target address in the route_info_list_ vector.
 * 
 * This function searches for the target address in the route_info_list_ vector and returns the iterator pointing to the first occurrence of the target address.
 * If the target address is not found, it returns the iterator pointing to the default_table_route.
 * 
 * @param target The target address to search for in the route_info_list_ vector.
 * @return std::vector<parasyte::network::utils::RouteInfoIPv6>::const_iterator The iterator pointing to the first occurrence of the target address, or the iterator pointing to the default_table_route if the target address is not found.
 */
std::vector<parasyte::network::utils::RouteInfoIPv6>::const_iterator parasyte::network::utils::RouteTableIPv6::Find(boost::asio::ip::address_v6 target) const {
  std::vector<RouteInfoIPv6>::const_iterator default_table_route = DefaultIPv6Route();
  std::vector<RouteInfoIPv6>::const_iterator it = route_info_list_.begin();

  for (; it != route_info_list_.end(); ++it) {
    if (it == default_table_route) continue;
    if (target == it -> dest) break;
  }
  return (it == route_info_list_.end()) ? default_table_route : it;
}

/**
 * Initializes the input stream by reading a line of text from the stream.
 * 
 * @param stream The input stream to initialize.
 * @return The initialized input stream.
 */
auto parasyte::network::utils::RouteTableIPv6::InitStream(std::istream &stream) -> decltype(stream) {
  std::string line;
  return std::getline(stream, line);
}

/**
 * Reads route information from the given input stream and populates the provided RouteInfoIPv6 object.
 *
 * @param stream The input stream to read from.
 * @param route_info The RouteInfoIPv6 object to populate with the read route information.
 * @return The input stream after reading the route information
 */
auto parasyte::network::utils::RouteTableIPv6::ReadRouteInfo(std::ifstream &stream, RouteInfoIPv6 &route_info) -> decltype(stream) {
  std::string dest, source, next_hop;
  stream >> dest >> route_info.dest_prefix >> source >> std::hex >> route_info.gateway_prefix >> next_hop >> std::hex >> route_info.metric >> std::dec >> route_info.ref_count >> route_info.use >> route_info.flags >> route_info.name;
  route_info.dest = boost::asio::ip::make_address_v6(ReadIPv6Address(dest));
  route_info.gateway = boost::asio::ip::make_address_v6(ReadIPv6Address(source));
  route_info.next_hop = boost::asio::ip::make_address_v6(ReadIPv6Address(next_hop));
  return stream;
}
