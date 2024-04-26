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

#include <functional>
#include <iostream>
#include <regex>
#include <string>

#include "NetUtils.hpp"
#include "Services.hpp"

/* CODE START */

namespace parasyte {
namespace network {
  namespace services {

    ServiceDetector::ServiceDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port)
        : io_context_(io_context)
        , host_(host)
        , port_(port)
        , resolver_(io_context)
        , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR) {}

    void ServiceDetector::DetectService() {
      ResolveHost();
    }

    ServiceDetector::~ServiceDetector() {}

    /**
     * @brief A map that associates a string key with a resolver_results value.
     *
     * The key is of type std::string, and the value is of type IServiceDetector::resolver_results.
     * This map is used in the ServiceDetector class to store resolver results.
     */
    std::map<std::string, IServiceDetector::resolver_results> const& ServiceDetector::GetResolverResults() const {
      return resolver_results_;
    }

    /**
     * @brief Resolves the host name and port number asynchronously.
     *
     * This function performs an asynchronous resolution of the host name and port number
     * using the TCP resolver. It populates the `resolver_results_` map with the resolved
     * endpoint information.
     */
    void ServiceDetector::ResolveHost() {
      tcp_resolver::query query(host_, std::to_string(port_));
      resolver_.async_resolve(query, [this](const error_code& ec, tcp_resolver_results results) {
        if (ec) {
          error_handler_.HandleError(ec.message());
          return;
        }

        for (const auto& result : results) {
          auto endpoint = result.endpoint();
          resolver_results_[endpoint.address().to_string()] = resolver_results{
            result.host_name(), result.service_name(), endpoint.port(), std::to_string(endpoint.protocol().protocol())
          };
        }
      });
    }

    /**
     * Parses the FTP banner to extract the server and version information.
     *
     * @param banner The FTP banner to parse.
     * @param server [out] The extracted server information.
     * @param version [out] The extracted version information.
     * @return True if the parsing is successful, false otherwise.
     */
    bool vsFTPBannerParseStrategy::Parse(const std::string& banner, std::string& server, std::string& version) {
      std::cout << banner << std::endl;
      std::regex version_regex("vsFTPd ([0-9]+\\.[0-9]+\\.[0-9]+)");
      std::smatch match;
      if (std::regex_search(banner, match, version_regex)) {
        version = match[1];
        server = "vsftpd";
        return true;
      }
      return false;
    }

    /**
     * Parses the ProFTPD banner to extract the server and version information.
     *
     * @param banner The ProFTPD banner string.
     * @param server [out] The extracted server name.
     * @param version [out] The extracted version number.
     * @return `true` if the parsing is successful, `false` otherwise.
     */
    bool ProFTPBannerParseStrategy::Parse(const std::string& banner, std::string& server, std::string& version) {
      std::regex version_regex("ProFTPD ([0-9]+\\.[0-9]+\\.[0-9]+)");
      std::smatch match;
      if (std::regex_search(banner, match, version_regex)) {
        version = match[1];
        server = "ProFTPD";
        return true;
      }
      return false;
    }

    /**
     * Parses the given FTP banner to extract the server name and version.
     *
     * @param banner The FTP banner to parse.
     * @param server [out] The extracted server name.
     * @param version [out] The extracted server version.
     * @return True if the parsing was successful, false otherwise.
     */
    bool PureFTPBannerParseStrategy::Parse(const std::string& banner, std::string& server, std::string& version) {
      std::regex version_regex("Pure-FTPd ([0-9]+\\.[0-9]+\\.[0-9]+)");
      std::smatch match;
      if (std::regex_search(banner, match, version_regex)) {
        version = match[1];
        server = "Pure-FTPd";
        return true;
      }
      return false;
    }

    /**
     * Parses the FTP banner to extract the server and version information.
     *
     * @param banner The FTP banner to parse.
     * @param server [out] The extracted server information.
     * @param version [out] The extracted version information.
     * @return True if the banner matches the expected pattern, false otherwise.
     */
    bool MicrosoftFTPBannerParseStrategy::Parse(const std::string& banner, std::string& server, std::string& version) {
      std::regex version_regex("Microsoft FTP Service");
      std::smatch match;
      if (std::regex_search(banner, match, version_regex)) {
        version = "unkown";
        server = "Microsoft FTP Service";
        return true;
      }
      return false;
    }

    /**
     * @brief Constructs a new instance of the BannerParser class.
     *
     * This constructor initializes the server and version strings to empty values.
     * It also adds various banner parse strategies to the `strategies_` vector.
     *
     * @note The banner parse strategies are added in a specific order.
     *
     * @see vsFTPBannerParseStrategy
     * @see ProFTPBannerParseStrategy
     * @see PureFTPBannerParseStrategy
     * @see MicrosoftFTPBannerParseStrategy
     */
    BannerParser::BannerParser(const uint16_t& port_number)
        : server_("")
        , version_("")
        , port_number_(port_number)
        , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR) {}

    /**
     * Parses the given banner and extracts the server and version information.
     *
     * @param banner The banner string to be parsed.
     * @param server [out] The extracted server information.
     * @param version [out] The extracted version information.
     * @return `true` if the banner was successfully parsed, `false` otherwise.
     */
    bool BannerParser::ParseBanner(
      const std::string& banner,
      const std::string& protocol,
      std::string& server,
      std::string& version
    ) {
      SetStrategies(protocol);
      for (auto& strategy : strategies_) {
        if (strategy->Parse(banner, server, version)) {
          server_ = server;
          version_ = version;
          return true;
        }
      }
      return false;
    }

    void BannerParser::SetStrategies(const std::string& protocol) {
      if (protocol != "tcp" && protocol != "udp") {
        error_handler_.SetType(parasyte::error_handler::ErrorHandler::error_type::WARNING);
        error_handler_.HandleError("Invalid protocol. Aborting...");
        return;
      }
      std::string service = parasyte::network::utils::PortToService(port_number_, protocol);
      if (service == "ftp") {
        strategies_.push_back(std::make_unique<vsFTPBannerParseStrategy>());
        strategies_.push_back(std::make_unique<ProFTPBannerParseStrategy>());
        strategies_.push_back(std::make_unique<PureFTPBannerParseStrategy>());
        strategies_.push_back(std::make_unique<MicrosoftFTPBannerParseStrategy>());
      } else {
        error_handler_.SetType(parasyte::error_handler::ErrorHandler::error_type::WARNING);
        error_handler_.HandleError("Invalid service. Aborting...");
      }
    }

    FTPDetector::FTPDetector(boost::asio::io_context& io_context, const std::string& host, const uint16_t& port)
        : io_context_(io_context)
        , host_(host)
        , port_(port)
        , resolver_(io_context)
        , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR)
        , banner_("") {}

    FTPDetector::~FTPDetector() {}

    /**
     * @brief Grabs the banner from the FTP server.
     *
     * This function asynchronously resolves the host and port of the FTP server,
     * establishes a TCP connection, and reads the server's response until the first
     * occurrence of "\r\n". The response is then stored in the `banner_` member variable.
     *
     * @note This function is asynchronous and requires an active io_context.
     */
    void FTPDetector::GrabBanner() {
      try {
        tcp::socket socket(io_context_);
        tcp::resolver resolver(io_context_);
        tcp::resolver::results_type endpoints = resolver.resolve(host_, std::to_string(port_));

        // Synchronous connect
        boost::asio::connect(socket, endpoints);

        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        std::istream response_stream(&response);
        std::getline(response_stream, banner_);
        // std::cout << "Banner received: " << banner_ << std::endl;
      }
      catch (const std::exception& e) {
        error_handler_.HandleError(e.what());
      }
    }

    /**
     * @brief Detects the version of the FTP server.
     */
    void FTPDetector::DetectVersion() {
      GrabBanner();
      BannerParser parser = BannerParser(port_);
      std::string server = "", version = "";
      parser.ParseBanner(banner_, "tcp", server, version);
      server = server.empty() ? "unknown" : server;
      version = version.empty() ? "unknown" : version;
      server_info_ = {server, version, host_, port_};
    }

    /**
     * @brief Retrieves the server information.
     *
     * This function returns the server information stored in the `server_info_` member variable.
     *
     * @return The server information.
     */
    ServerInfo FTPDetector::GetServerInfo() const {
      return server_info_;
    }
  }
}
}