#ifndef PARASYTE_ERROR_HANDLER_ERRORHANDLER_HPP_
#define PARASYTE_ERROR_HANDLER_ERRORHANDLER_HPP_

#include <string>
#include <iostream>
#include <sstream>

namespace parasyte {
namespace error_handler {
  class ErrorHandler {
    public:
      enum error_type {
        NIL,
        ERROR,
        WARNING,
        INFO
      };

      // Fix constructor initialization list
      ErrorHandler(error_type type) : error_type_(type) {
      }

      ~ErrorHandler() = default;

      void HandleError(const std::string &error_message) {
        std::stringstream formatted_message;
        // Prefix message based on error type
        switch (error_type_) {
          case ERROR:
            formatted_message << "[x] ";
            break;
          case WARNING:
            formatted_message << "[!] ";
            break;
          case INFO:
            formatted_message << "[*] ";
            break;
        }
        formatted_message << error_message;

        // Print to appropriate output stream
        if (error_type_ == INFO) {
          std::cout << formatted_message.str() << std::endl;
        } else {
          std::cerr << formatted_message.str() << std::endl;
        }
      }

    private:
      error_type error_type_;
  };
}
}

#endif // PARASYTE_ERROR_HANDLER_ERRORHANDLER_HPP_
