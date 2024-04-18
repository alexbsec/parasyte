#ifndef PARASYTE_UTILS_LOGGER_HPP_
#define PARASYTE_UTILS_LOGGER_HPP_

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

#include <sys/stat.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

/* CODE START */

namespace parasyte {
namespace utils {
  namespace logging {
    enum LogLevel {
      NIL,
      ERROR,
      WARNING,
      INFO,
    };

    class Logger {
      public:
        using time_point = std::chrono::system_clock::time_point;
        Logger(const std::string& filename, unsigned int verbosity = 0);
        ~Logger();

        void Log(LogLevel level, const std::string& message);
        void MakeLogDirectory(
          const std::string& filename,
          const std::filesystem::path& base_path = std::filesystem::current_path()
        );

        void SetVerbosity(unsigned int verbosity) {
          verbosity_ = verbosity;
        }

      private:
        std::ofstream log_file_;  // File stream for logging
        unsigned int verbosity_;  // Verbosity level
        parasyte::error_handler::ErrorHandler error_handler_;
        std::string LevelToString_(LogLevel level) {
          switch (level) {
            case LogLevel::NIL:
              return "[NIL] ";
            case LogLevel::ERROR:
              return "[x] ";
            case LogLevel::WARNING:
              return "[!] ";
            case LogLevel::INFO:
              return "[*] ";
          }
        }
    };
  }
}
}

#endif  // PARASYTE_UTILS_LOGGER_HPP_