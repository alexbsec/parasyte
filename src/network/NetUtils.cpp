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

/* CODE START */

/**
 * Calculates the checksum of a buffer.
 * 
 * @param buffer The buffer containing the data to calculate the checksum for.
 * @param buffer_size The size of the buffer in bytes.
 * @return The calculated checksum value.
 */
/**
 * Calculates the checksum of a buffer.
 * 
 * @param buffer The buffer containing the data to calculate the checksum for.
 * @param buffer_size The size of the buffer in bytes.
 * @return The calculated checksum value.
 */
uint16_t parasyte::network::utils::Checksum(std::uint16_t *buffer, int buffer_size) {
  unsigned long sum = 0; // Initialize the sum variable to 0
  while (buffer_size > 1) { // Iterate through the buffer in 16-bit chunks
    sum += *buffer++; // Add the value at the current buffer location to the sum
    buffer_size -= 2; // Decrease the buffer size by 2 bytes
  }
  
  if (buffer_size == 1) sum += *(unsigned char *)buffer; // If there is an odd byte remaining, add it to the sum
  sum = (sum & 0xFFFF) + (sum >> 16); // Add the carry bits to the sum
  sum = (sum & 0xFFFF) + (sum >> 16); // Add any remaining carry bits
  return ~sum; // Return the one's complement of the sum as the checksum value
}

/**
 * Converts an IPv6 address to a string representation.
 * 
 * @param addr The IPv6 address to convert.
 * @return The string representation of the IPv6 address.
 */
std::string parasyte::network::utils::Inet6AddressToString(struct in6_addr *addr) {
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
std::string parasyte::network::utils::Inet4AddressToString(struct in_addr *addr) {
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
  std::string address_string = Inet6AddressToString(((struct sockaddr_in6 *) &ifr.ifr_addr) -> sin6_addr); // Convert the retrieved address to a string
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
struct in6_addr parasyte::network::utils::StringToAddress(std::string address) {
  struct in6_addr addr;
  inet_pton(AF_INET6, address.c_str(), &(addr));
  return addr;
}