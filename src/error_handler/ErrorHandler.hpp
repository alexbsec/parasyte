#ifndef PARASYTE_ERROR_HANDLER_ERRORHANDLER_HPP_
#define PARASYTE_ERROR_HANDLER_ERRORHANDLER_HPP_

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
#include <string>
#include <iostream>
#include <sstream>

/* CODE START */

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
            case NIL:
                formatted_message << "[NIL] ";
                break;
          case ERROR:
            formatted_message << "[x] ";
            break;
          case WARNING:
            formatted_message << "[!] ";
            break;
          case INFO:
            formatted_message << "[*] ";
            break;
          case NIL:
            formatted_message << "";
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
