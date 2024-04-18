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

// Include Declarations

#include "Logger.hpp"
#include "../error_handler/ErrorHandler.hpp"

namespace parasyte {
namespace utils {
  namespace logging {
    Logger::Logger(const std::string& filename, unsigned int verbosity)
        : verbosity_(verbosity)
        , error_handler_(parasyte::error_handler::ErrorHandler::error_type::ERROR) {
      MakeLogDirectory(filename);
      log_file_.open(filename, std::ios::app);
      if (!log_file_.is_open()) {
        error_handler_.HandleError("Failed to open log file");
      }
    }

    Logger::~Logger() {
      log_file_.close();
    }

    /**
     * Logs a message with the specified log level.
     *
     * @param level The log level of the message.
     * @param message The message to be logged.
     */
    void Logger::Log(LogLevel level, const std::string& message) {
      time_point now = std::chrono::system_clock::now();
      time_t time_t_now = std::chrono::system_clock::to_time_t(now);
      std::ostringstream log_entry, timestamp;
      timestamp << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S");
      log_entry << "[" << timestamp.str() << "] " << LevelToString_(level) << ": " << message << std::endl;
      if (verbosity_ >= 1) {
        std::cout << log_entry.str();
      }

      if (log_file_.is_open()) {
        log_file_ << log_entry.str();
        log_file_.flush();
      }
    }

    /**
     * Creates a log directory at the specified base path.
     *
     * @param base_path The base path where the log directory will be created.
     */
    void Logger::MakeLogDirectory(const std::string& filename, const std::filesystem::path& base_path) {
      std::filesystem::path log_dir = base_path / "logs";

      try {
        if (!std::filesystem::exists(log_dir)) {
          std::filesystem::create_directories(log_dir);
          log_file_ = std::ofstream(log_dir / filename);
        }
      }
      catch (const std::filesystem::filesystem_error& e) {
        error_handler_.HandleError(e.what());
      }
    }
  }

}
}