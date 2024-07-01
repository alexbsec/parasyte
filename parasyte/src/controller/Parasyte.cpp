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

#include "Parasyte.hpp"
#include "Cli.hpp"

/* CODE START */

namespace parasyte {
namespace controller {
  cli::ScanCommand::ScanCommand(
    parasyte::network::NetScanner& net_scanner,
    const parasyte::network::ScannerParams& params,
    std::vector<uint16_t> ports
  )
      : net_scanner_(net_scanner)
      , params_(params)
      , ports_(ports) {}

  /**
   * @brief Executes the scan command.
   *
   * This function performs a network scan based on the provided parameters. It checks if the scan is already complete,
   * and if not, prompts the user to run the scan again. If the `send_ping` flag is set, it sends a ping to find up hosts
   * and updates the list of up hosts. Then, it starts scanning the specified ports and detects the version of each open port.
   * Finally, it sets the output widget to indicate that the scan is complete.
   */
  void cli::ScanCommand::Execute() {
    if (net_scanner_.scanner->IsScanComplete()) {
      output_ = parasyte::utils::general::OutputWidget(1, "Scan already completed. Run again? [y/n]");
      std::string input;
      std::cin >> input;
      if (input != "y" && input != "Y") return;
    }

    if (params_.send_ping) {
      output_ = parasyte::utils::general::OutputWidget(3, "Sending ping to find up hosts...");
      net_scanner_.Ping();
      std::vector<boost::asio::ip::address_v4> up_hosts = net_scanner_.GetUpHosts();
      net_scanner_.SetUpHosts(up_hosts);
      size_t up_hosts_count = up_hosts.size();
      output_ =
        parasyte::utils::general::OutputWidget(3, "Ping complete. Found " + std::to_string(up_hosts_count) + " up hosts.");
    } else if (params_.host.empty()) {
      output_ = parasyte::utils::general::OutputWidget(2, "No host provided.");
      return;
    }

    if (ports_.empty()) {
      output_ = parasyte::utils::general::OutputWidget(2, "No ports provided.");
      return;
    }

    output_ = parasyte::utils::general::OutputWidget(3, "Starting scan...");
    for (auto port : ports_) {
      output_ = parasyte::utils::general::OutputWidget(3, "Scanning port " + std::to_string(port) + "...");
      net_scanner_.scanner->StartScan(port);
      net_scanner_.RunIoContext();
      std::map<std::pair<boost::asio::ip::address_v4, int>, parasyte::network::port_status> port_info =
        net_scanner_.scanner->port_info();
      for (const auto& entry : port_info) {
        const auto& key = entry.first;
        const auto& status = entry.second;
        net_scanner_.scanner->DetectVersion(key.first);
      }
    }

    output_ = parasyte::utils::general::OutputWidget(0, "Scan complete.");
  }

  void cli::TargetCommand::Execute() {}

  cli::MemoryCommand::MemoryCommand(parasyte::network::NetScanner& net_scanner) : net_scanner_(net_scanner) {}

  /**
   * @brief Executes the MemoryCommand.
   * 
   * This function is responsible for executing the MemoryCommand. It retrieves port information and server information
   * from the network scanner and stores them in the cache. It also generates an output widget for each line of information
   * and saves the information to the cache.
   */
  void cli::MemoryCommand::Execute() {
    std::map<std::pair<boost::asio::ip::address_v4, int>, parasyte::network::port_status> port_info_map =
      net_scanner_.scanner->port_info();
    std::vector<parasyte::network::services::ServerInfo> server_info = net_scanner_.scanner->GetAllServerInfo();
    bool is_scan_complete = net_scanner_.scanner->IsScanComplete();
    if (!is_scan_complete) {
      output_ = parasyte::utils::general::OutputWidget(1, "Scan yet to be completed.");
      return;
    }

    if (port_info_map.empty()) {
      output_ = parasyte::utils::general::OutputWidget(2, "Something went wrong as the scan completed with no output.");
      return;
    }

    cache_lines_.push_back("\n======== PORT SCAN INFO ========\n");

    for (const auto& entry : port_info_map) {
      const auto& key = entry.first;
      const auto& status = entry.second;
      std::string status_str;
      switch (status) {
        case parasyte::network::port_status::OPEN:
          status_str = "OPEN";
          break;
        case parasyte::network::port_status::CLOSED:
          status_str = "CLOSED";
          break;
        case parasyte::network::port_status::FILTERED:
          status_str = "FILTERED";
          break;
        default:
          status_str = "UNKNOWN";
          break;
      }
      cache_lines_.push_back(
        "Host: " + key.first.to_string() + " Port: " + std::to_string(key.second) + " Status: " + status_str + "\n"
      );
    }

    cache_lines_.push_back("======== SERVERS INFO ========\n");

    if (server_info.empty()) {
      cache_lines_.push_back("No servers found.\n");
    } else {
      std::string last_host = "";
      for (const auto& server : server_info) {
        if (server.server.empty() || server.host.empty()) continue;
        if (last_host != server.host) cache_lines_.push_back("Host: " + server.host + ":\n");
        last_host = server.host;
        cache_lines_.push_back(
          "\tServer:\t" + server.server + "\n\tVersion:\t" + server.version + "\n\tPort:\t" + std::to_string(server.port) +
          "\n"
        );
      }
    }

    std::ios::openmode mode = std::ios::out;
    bool is_first_line = true;
    for (const auto& line : cache_lines_) {
      if (!is_first_line) {
        mode = std::ios::app;
      } else {
        is_first_line = false;
      }
      output_ = parasyte::utils::general::OutputWidget(4, line);
      SaveToCache(line, mode);
    }

    cache_lines_.clear();
  }

  /**
   * @brief Saves the given line to the cache file.
   *
   * This function opens the cache file in the specified mode and writes the given line to it.
   * If the cache file fails to open, an error message is set in the output widget.
   *
   * @param line The line to be saved to the cache file.
   * @param mode The open mode for the cache file.
   */
  void cli::MemoryCommand::SaveToCache(const std::string& line, std::ios::openmode mode) {
    std::ofstream cache_file("./var/cache/cache.txt", mode);
    if (!cache_file.is_open()) {
      output_ = parasyte::utils::general::OutputWidget(2, "Failed to open cache file.");
      return;
    }
    cache_file << line << std::endl;
    cache_file.close();
  }

  /**
   * @brief Opens the cache file and returns its contents as a string.
   * 
   * @return The contents of the cache file as a string.
   */
  std::string cli::MemoryCommand::OpenCache() {
    std::ifstream cache_file("./var/cache/cache.txt");
    if (!cache_file.is_open()) {
      output_ = parasyte::utils::general::OutputWidget(2, "Failed to open cache file.");
      return "";
    }
    std::string line;
    std::string cache;
    while (std::getline(cache_file, line)) {
      cache += line;
    }
    cache_file.close();
    return cache;
  }

  cli::ListExploitsCommand::ListExploitsCommand(
    std::map<
      unsigned int,
      std::pair<parasyte::network::services::ServerInfo, std::shared_ptr<parasyte::exploits::ExploitBase>>> servers_map
  )
      : servers_map_(servers_map) {}

  /**
   * @brief Executes the ListExploitsCommand.
   *
   * This function lists the available exploits by iterating over the servers_map_ and
   * retrieving the server information and associated exploits. It populates the output_
   * with the list of exploits and their details.
   */
  void cli::ListExploitsCommand::Execute() {
    if (servers_map_.empty()) {
      output_ = parasyte::utils::general::OutputWidget(2, "No exploits found.");
      return;
    }

    output_ = parasyte::utils::general::OutputWidget(2, "Available exploits:\n");
    for (const auto& entry : servers_map_) {
      unsigned int id = entry.first;
      const parasyte::network::services::ServerInfo& server_info = entry.second.first;
      const std::shared_ptr<parasyte::exploits::ExploitBase>& exploit_base = entry.second.second;
      out_lines_.push_back(
        "ID: " + std::to_string(id) + ", Host: " + server_info.host + ", Port: " + std::to_string(server_info.port) +
        ", Server: " + server_info.server + ", Version: " + server_info.version + "\n"
      );

      for (const auto& exploiter : exploit_base->exploiters) {
        out_lines_.push_back("\tExploits available: " + exploiter->GetName() + "\n");
      }
    }

    for (const auto& line : out_lines_) {
      output_ = parasyte::utils::general::OutputWidget(4, line);
    }

    out_lines_.clear();
  }

  /**
   * @brief Constructs a CLI object.
   * 
   * This constructor initializes a CLI object with the given parameters.
   * 
   * @param net_scanner A reference to the NetScanner object.
   * @param params The ScannerParams object.
   * @param ports A vector of uint16_t representing the ports.
   */
  cli::CLI::CLI(
    parasyte::network::NetScanner& net_scanner,
    const parasyte::network::ScannerParams& params,
    std::vector<uint16_t> ports
  )
      : net_scanner_(net_scanner)
      , params_(params)
      , ports_(ports) {
    commands_["scan"] = std::make_shared<cli::ScanCommand>(net_scanner_, params_, ports_);
    commands_["memory"] = std::make_shared<cli::MemoryCommand>(net_scanner_);
  }

  cli::CLI::~CLI() {}

  /**
   * @brief Executes the specified command.
   *
   * This function executes the specified command by calling the corresponding command's Execute() function.
   * If the command is "memory" and the network scanner has completed the scan and the exploit command has not been created yet,
   * it creates exploit bases for each server found by the scanner and adds them to the servers_map_.
   * It also adds a "exploits" command to the commands_ map, which lists all the available exploits.
   *
   * @param cmd The command to be executed.
   */
  void cli::CLI::Run(const std::string& cmd) {
    if (commands_.find(cmd) != commands_.end()) {
      commands_[cmd]->Execute();
      if (cmd == "memory" && net_scanner_.scanner->IsScanComplete() && !is_exploit_command_created_) {
        std::vector<parasyte::network::services::ServerInfo> servers = net_scanner_.scanner->GetAllServerInfo();
        unsigned int id = 1;

        if (servers.empty()) {
          logger_.Log(parasyte::utils::logging::LogLevel::WARNING, "No servers found while creating exploits.");
        }
        
        for (const auto& server : servers) {
          std::shared_ptr<parasyte::exploits::ExploitBase> exploit_base = MakeExploit(server);
          if (server.host.empty()) {
              logger_.Log(parasyte::utils::logging::LogLevel::INFO, "Skipping server due to empty host: " + server.server);
              continue;
          }
          if (exploit_base->exploiters.empty()) {
              logger_.Log(parasyte::utils::logging::LogLevel::INFO, "Skipping server due to empty exploiters: " + server.host);
              continue;
          }
          logger_.Log(
              parasyte::utils::logging::LogLevel::INFO,
              "Creating exploit base for host: " + server.host + ", server: " + server.server
          );
          std::pair<parasyte::network::services::ServerInfo, std::shared_ptr<parasyte::exploits::ExploitBase>>
            available_exploits = std::make_pair(server, exploit_base);
          auto result = servers_map_.try_emplace(id, available_exploits);
          if (!result.second) {
            logger_.Log(parasyte::utils::logging::LogLevel::ERROR, "Failed to emplace exploit base for id: " + std::to_string(id));
          } else {
            logger_.Log(parasyte::utils::logging::LogLevel::INFO, "Successfully emplaced exploit base for id: " + std::to_string(id));
          }
          id++;
        }

        if (servers_map_.empty()) {
          logger_.Log(parasyte::utils::logging::LogLevel::WARNING, "Something went wrong while creating exploits as no servers were found.");
        }

        commands_["exploits"] = std::make_shared<cli::ListExploitsCommand>(servers_map_);
      }
    } else {
      parasyte::utils::general::OutputWidget(0, "Command not found.");
    }
  }

  /**
   * @brief Creates an exploit object based on the provided server information.
   * 
   * This function creates an exploit object using the provided server information and returns it as a shared pointer.
   * The exploit object is created with the IO context from the net_scanner_ member variable and the provided server information.
   * 
   * @param server_info The server information used to create the exploit object.
   * @return A shared pointer to the created exploit object.
   */
  std::shared_ptr<parasyte::exploits::ExploitBase> cli::CLI::MakeExploit(
    const parasyte::network::services::ServerInfo& server_info
  ) {
    auto exploit = std::make_shared<parasyte::exploits::ExploitBase>(net_scanner_.GetIoContext(), server_info, false);
    return exploit;
  }

  /**
   * @brief Constructs Parasyte object.
   * 
   * This constructor initializes Parasyte object with the given parameters.
   * 
   * @param io_context The boost::asio::io_context object to be used for asynchronous operations.
   * @param params The ScannerParams object containing the parameters for the network scanner.
   * @param ports A vector of uint16_t values representing the ports to be scanned.
   */
  Parasyte::Parasyte(boost::asio::io_context& io_context, const ScannerParams& params, std::vector<uint16_t> ports)
      : io_context_(io_context)
      , params_(params)
      , net_scanner_(io_context, params)
      , ports_(ports)
      , error_handler_(error_handler::ErrorHandler::error_type::ERROR) {
        logger_.Log(parasyte::utils::logging::LogLevel::INFO, "========= Parasyte initialized. =========");
      }

  Parasyte::~Parasyte() {}

  void Parasyte::Hail() {
    std::cout << "/* >>====================================================<< */" << std::endl;
    std::cout << "/* ||                                                    || */" << std::endl;
    std::cout << "/* ||    ____                                    __      || */" << std::endl;
    std::cout << "/* ||   / __ \\ ____ _ _____ ____ _ _____ __  __ / /_ ___ || */" << std::endl;
    std::cout << "/* ||  / /_/ // __ `// ___// __ `// ___// / / // __// _ \\|| */" << std::endl;
    std::cout << "/* || / ____// /_/ // /   / /_/ /(__  )/ /_/ // /_ /  __/|| */" << std::endl;
    std::cout << "/* ||/_/     \\__,_//_/    \\__,_//____/ \\__, / \\__/ \\___/ || */" << std::endl;
    std::cout << "/* ||                                 /____/             || */" << std::endl;
    std::cout << "/* ||                                                    || */" << std::endl;
    std::cout << "/* >>====================================================<< */" << std::endl;
    std::cout << "/* || Framework v.0.1                                    || */" << std::endl;
    std::cout << "/* >>====================================================<< */" << std::endl;
  }

  /**
   * @brief Initializes the Parasyte controller.
   * This function sets up the necessary components and enters a loop to process user input.
   * The loop continues until the user enters "exit".
   */
  void Parasyte::Init() {
    Hail();
    cli::CLI cli(net_scanner_, params_, ports_);

    std::string input;
    while (true) {
      std::cout << "parasyte >> ";
      std::cin >> input;
      if (input == "exit") {
        break;
      } else if (input == "\r") {
        continue;
      }
      cli.Run(input);
    }
  }

}
}