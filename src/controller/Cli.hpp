#ifndef PARASYTE_CONTROLLER_CLI_HPP_
#define PARASYTE_CONTROLLER_CLI_HPP_

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

#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "../error_handler/ErrorHandler.hpp"
#include "../exploits/ExploitBase.hpp"
#include "../network/NetScanner.hpp"
#include "../network/NetUtils.hpp"
#include "../network/Services.hpp"
#include "../utils/Logger.hpp"
#include "../utils/Utils.hpp"

namespace parasyte {
namespace controller {
  namespace cli {
    class Command {
      public:
        virtual ~Command() = default;
        virtual void Execute() = 0;
        virtual bool IsDependent() const {
          return false;
        }
    };

    class ScanCommand : public Command {
      public:
        ScanCommand(
          parasyte::network::NetScanner& net_scanner,
          const parasyte::network::ScannerParams& params,
          std::vector<uint16_t> ports
        );
        void Execute() override;

      private:
        parasyte::network::NetScanner& net_scanner_;
        parasyte::network::ScannerParams params_;
        std::vector<uint16_t> ports_;
        std::string output_;
    };

    using CommandPtr = std::shared_ptr<Command>;
    using CommandMap = std::unordered_map<std::string, CommandPtr>;

    class TargetCommand : public Command {
      public:
        void Execute();

      private:
        std::string output_;
    };

    class MemoryCommand : public Command {
      public:
        MemoryCommand(parasyte::network::NetScanner& net_scanner);
        void Execute() override;

      private:
        void SaveToCache(const std::string& line);
        std::string OpenCache();
        std::string output_;
        std::vector<std::string> cache_lines_;
        parasyte::network::NetScanner& net_scanner_;
    };

    class ListExploitsCommand : public Command {
      public:
        void Execute();
        bool IsDependent() const override {
          return true;
        }

      private:
        std::string output_;
    };

    class SetCredentialsCommand : public Command {
      public:
        void Execute();
        bool IsDependent() const override {
          return true;
        }

      private:
        std::string output_;
    };

    class RunExploitCommand : public Command {
      public:
        void Execute();
        bool IsDependent() const override {
          return true;
        }

      private:
        std::string output_;
    };

    class ExitCommand : public Command {
      public:
        void Execute();
    };

    class HelpCommand : public Command {
      public:
        void Execute();

      private:
        std::string output_;
    };

    class CLI {
      public:
        CLI(
          parasyte::network::NetScanner& net_scanner,
          const parasyte::network::ScannerParams& params,
          std::vector<uint16_t> ports
        );
        ~CLI();
        void Run(const std::string& cmd);

      private:
        CommandMap commands_;
        CommandMap dependent_commands_;
        bool is_scan_complete_;
        parasyte::network::NetScanner& net_scanner_;
        parasyte::network::ScannerParams params_;
        std::vector<uint16_t> ports_;
    };

  }
}
}

#endif  // PARASYTE_CONTROLLER_CLI_HPP_