#include <chrono>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/detail/config.hpp>
#include <boost/asio/detail/push_options.hpp>
#include <boost/asio/detail/socket_types.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/ip/basic_resolver_iterator.hpp>
#include <boost/asio/ip/basic_resolver_query.hpp>
#include <boost/asio/ip/tcp.hpp>

boost::asio::io_context io_context;
boost::asio::ip::tcp::socket control_socket(io_context);

const std::string& HOST = "192.168.0.203";
bool logged_in = false;
std::string res;

bool read_response() {
  try {
    boost::asio::streambuf response;
    boost::asio::read_until(control_socket, response, "\r\n");

    std::istream response_stream(&response);
    std::string res_line;
    std::getline(response_stream, res_line);
    res = res_line;
    std::cout << "Received response: " << res << std::endl;  // Debugging log
    return true;
  }
  catch (const std::exception& e) {
    std::cout << "Error reading response: " << e.what() << std::endl;
    return false;
  }
}

std::pair<boost::asio::ip::address_v4, uint16_t> parse_pasv_response(const std::string& response) {
  std::regex pasv_regex(R"(\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\))");
  std::smatch matches;

  if (std::regex_search(response, matches, pasv_regex) && matches.size() == 7) {
    std::string ip = matches[1].str() + "." + matches[2].str() + "." + matches[3].str() + "." + matches[4].str();
    uint16_t port = std::stoi(matches[5]) * 256 + std::stoi(matches[6]);
    return {boost::asio::ip::make_address_v4(ip), port};
  }
  return {};
}

void send_command(const std::string& command) {
  try {
    std::cout << "Sending command: " << command;  // Debugging log
    control_socket.write_some(boost::asio::buffer(command));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Adding delay
  }
  catch (const std::exception& e) {
    std::cout << "Failed to send command: " << e.what() << std::endl;
  }
}

bool attempt_login() {
  try {
    if (!read_response() || res.find("220") == std::string::npos) {
      std::cout << "Failed to receive initial 220 response. Got response: " << res << std::endl;
      return false;
    }

    send_command("USER anonymous\r\n");
    if (!read_response() || res.find("331") == std::string::npos) {
      std::cout << "Failed to send USER command. Got response: " << res << std::endl;
      return false;
    }

    send_command("PASS anonymous\r\n");
    if (!read_response() || res.find("230") == std::string::npos) {
      std::cout << "Failed to send PASS command. Got response: " << res << std::endl;
      return false;
    }

    logged_in = true;
    std::cout << "Logged in. Got response: " << res << std::endl;
    return true;
  }
  catch (const std::exception& e) {
    std::cout << "Failed to login: " << e.what() << std::endl;
    return false;
  }
}

bool connect() {
  try {
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(HOST, "ftp");
    boost::asio::connect(control_socket, endpoints);
    return attempt_login();
  }
  catch (const std::exception& e) {
    std::cout << "Failed to connect: " << e.what() << std::endl;
    return false;
  }
}

void send_file(const std::string& filename) {
  send_command("PASV\r\n");
  if (!read_response()) {
    std::cout << "Failed to enter passive mode." << std::endl;
    return;
  }

  auto [ip, port] = parse_pasv_response(res);
  if (ip.is_unspecified() || port == 0) {
    std::cout << "Failed to parse PASV response." << std::endl;
    std::cout << "Response: " << res << std::endl;
    return;
  }

  boost::asio::ip::tcp::endpoint endpoint(ip, port);
  boost::asio::ip::tcp::socket data_socket(io_context);
  data_socket.connect(endpoint);
  std::cout << "Checking file..\n";
  std::ifstream file(filename, std::ios::binary);
  if (!file) {
    std::cout << "Failed to open file." << std::endl;
    return;
  }

  send_command("STOR " + filename + "\r\n");
  if (!read_response()) {
    std::cout << "Failed to send STOR command." << std::endl;
    return;
  }

  boost::asio::streambuf buffer;
  while (file) {
    char data[67024];
    file.read(data, sizeof(data));
    std::size_t len = file.gcount();

    if (len > 0) {
      try {
        boost::asio::write(data_socket, boost::asio::buffer(data, len));
      }
      catch (const boost::system::system_error& e) {
        std::cout << "Failed to write data to socket: " << e.what() << std::endl;
        break;
      }
    }

    if (file.eof()) {
      break;
    } else if (file.fail() && !file.eof()) {
      std::cout << "Failed to read file." << std::endl;
      break;
    }
  }
  file.close();
  data_socket.close();
}

void execute() {
  if (!connect()) {
    std::cout << "Failed to connect and login." << std::endl;
    return;
  }

  send_command("TYPE I\r\n");
  if (!read_response()) {
    std::cout << "Failed to set type to binary." << std::endl;
    return;
  }

  send_file("test");
}

int main() {
  execute();
  return 0;
}
