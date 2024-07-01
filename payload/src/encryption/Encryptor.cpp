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

#include "Encryptor.hpp"

/* CODE START */

namespace parasyte {
namespace payload {
  namespace encryption {

    /**
     * @brief Generates a random key.
     *
     * This function generates a random key and stores it in the provided vector.
     *
     * @param key The vector to store the generated key.
     */
    void GenerateKey(std::vector<unsigned char>& key) {
      if (!RAND_bytes(key.data(), key.size())) parasyte::payload::encryption::HandleOpenSSLErrors();
    }

    /**
     * @brief Generates a random initialization vector (IV).
     *
     * This function generates a random initialization vector (IV) and stores it in the provided vector.
     *
     * @param iv The vector to store the generated IV.
     */
    void GenerateIV(std::vector<unsigned char>& iv) {
      if (!RAND_bytes(iv.data(), iv.size())) parasyte::payload::encryption::HandleOpenSSLErrors();
    }

    /**
     * @brief Checks if a debugger is attached to the current process.
     *
     * @return If true, then exit the program.
     */
    static void CheckDebugger() {
      if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        exit(0);
      }
    }

    /**
     * @brief Handles and prints OpenSSL errors.
     *
     * This function handles and prints OpenSSL errors to the standard error stream and aborts the program.
     */
    void HandleOpenSSLErrors() {
      ERR_print_errors_fp(stderr);
      abort();
    }

    /**
     * @brief Constructs an Encryptor object with the specified key.
     *
     * This constructor initializes an Encryptor object with the provided key.
     *
     * @param key The encryption key.
     */
    Encryptor::Encryptor() {}

    /**
     * @brief Destroys the Encryptor object.
     *
     * This destructor cleans up any resources used by the Encryptor object.
     */
    Encryptor::~Encryptor() {}

    /**
     * @brief Converts a vector of unsigned characters to a hexadecimal string representation.
     *
     * This function takes a vector of unsigned characters and converts it to a hexadecimal string representation.
     *
     * @param data The vector of unsigned characters to be converted.
     * @return The hexadecimal string representation of the input data.
     */
    std::string Encryptor::ToHexString(const std::vector<unsigned char>& data) {
      std::ostringstream oss;
      for (auto byte : data) {
        oss << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
      }
      return oss.str();
    }

    /**
     * @brief Converts a hexadecimal string to a vector of bytes.
     *
     * This function takes a hexadecimal string as input and converts it to a vector of bytes.
     * Each pair of characters in the input string represents a byte in the output vector.
     *
     * @param hex_string The hexadecimal string to convert.
     * @return A vector of bytes representing the converted hexadecimal string.
     */
    std::vector<unsigned char> Encryptor::FromHexString(const std::string& hex_string) {
      std::vector<unsigned char> bytes;
      for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byte_string.c_str(), nullptr, 16);
        bytes.push_back(byte);
      }
      return bytes;
    }

    /**
     * @brief Encrypts the given plaintext using AES-256 CBC encryption.
     *
     * This function encrypts the provided plaintext using AES-256 CBC encryption.
     * It requires the plaintext and the initialization vector (IV) as input.
     *
     * @param plaintext The plaintext to be encrypted.
     * @param iv The initialization vector (IV) used for encryption.
     * @return The ciphertext generated from the encryption process.
     */
    std::vector<unsigned char> Encryptor::Encrypt(const std::string& plaintext, const std::string& iv) {
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (!ctx) parasyte::payload::encryption::HandleOpenSSLErrors();

      bool fail = 1 != EVP_EncryptInit_ex(
                         ctx,
                         EVP_aes_256_cbc(),
                         NULL,
                         reinterpret_cast<const unsigned char*>(key_.data()),
                         reinterpret_cast<const unsigned char*>(iv.data())
                       );
      if (fail) parasyte::payload::encryption::HandleOpenSSLErrors();

      std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
      int len;
      fail = 1 != EVP_EncryptUpdate(
                    ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()
                  );
      if (fail) parasyte::payload::encryption::HandleOpenSSLErrors();

      int ciphertext_len = len;

      fail = 1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
      if (fail) parasyte::payload::encryption::HandleOpenSSLErrors();

      ciphertext_len += len;
      ciphertext.resize(ciphertext_len);

      EVP_CIPHER_CTX_free(ctx);

      return ciphertext;
    }

    /**
     * @brief Decrypts the given ciphertext using AES-256 CBC mode.
     *
     * This function decrypts the provided ciphertext using the AES-256 CBC encryption mode.
     * It requires the ciphertext and the initialization vector (IV) as input.
     *
     * @param ciphertext The ciphertext to be decrypted.
     * @param iv The initialization vector (IV) used for decryption.
     * @return The decrypted plaintext.
     */
    std::string Encryptor::Decrypt(const std::vector<unsigned char>& ciphertext, const std::string& iv) {
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (!ctx) parasyte::payload::encryption::HandleOpenSSLErrors();

      bool fail = 1 != EVP_DecryptInit_ex(
                         ctx,
                         EVP_aes_256_cbc(),
                         NULL,
                         reinterpret_cast<const unsigned char*>(key_.data()),
                         reinterpret_cast<const unsigned char*>(iv.data())
                       );
      if (fail) parasyte::payload::encryption::HandleOpenSSLErrors();

      std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
      int len;

      fail = 1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
      if (fail) parasyte::payload::encryption::HandleOpenSSLErrors();

      int plaintext_len = len;

      fail = 1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
      if (fail) parasyte::payload::encryption::HandleOpenSSLErrors();

      plaintext_len += len;
      plaintext.resize(plaintext_len);

      EVP_CIPHER_CTX_free(ctx);

      return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }
  }
}
}