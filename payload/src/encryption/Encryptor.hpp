#ifndef PARASYTE_PAYLOAD_ENCRYPTION_ENCRYPTOR_HPP_
#define PARASYTE_PAYLOAD_ENCRYPTION_ENCRYPTOR_HPP_

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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/ptrace.h>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

/* CODE START */

namespace parasyte {
namespace payload {
  namespace encryption {
    void GenerateKey(std::vector<unsigned char>& key);
    void GenerateIV(std::vector<unsigned char>& iv);
    static bool CheckDebbuger();

    void HandleOpenSSLErrors();

    class Encryptor {
      public:
        Encryptor();
        ~Encryptor();

        std::string ToHexString(const std::vector<unsigned char>& data);
        std::vector<unsigned char> FromHexString(const std::string& hex_string);
        std::vector<unsigned char> Encrypt(const std::string& plaintext, const std::string& iv);
        std::string Decrypt(const std::vector<unsigned char>& ciphertext, const std::string& iv);
        void SetKey(const std::string& key) {
          key_ = key;
        };

      private:
        std::string key_;
    };
  }
}
}

#endif  // PARASYTE_PAYLOAD_ENCRYPTION_ENCRYPTOR_HPP_
