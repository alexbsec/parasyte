#ifndef PARASYTE_UTILS_UTILS_HPP_
#define PARASYTE_UTILS_UTILS_HPP_

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

#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include "../error_handler/ErrorHandler.hpp"

/* CODE START */

namespace parasyte {
namespace utils {
  namespace general {
    static size_t WriteCallBack(void* contents, size_t size, size_t nmemb, void* userp);
    std::string DownloadFile(const std::string& url);
    std::vector<std::string> ParselineDownloadedFile(const std::string& file);
    std::string OutputWidget(unsigned int type, std::string message);
  }
}
}

#endif  // PARASYTE_UTILS_UTILS_HPP_