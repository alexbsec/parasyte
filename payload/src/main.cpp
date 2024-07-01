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

#include <iostream>
#include "encryption/Encryptor.hpp"

int main() {
  parasyte::payload::encryption::CheckDebbuger();
  std::vector<unsigned char> key(32);
  std::vector<unsigned char> iv(16);
  parasyte::payload::encryption::GenerateKey(key);
  parasyte::payload::encryption::GenerateIV(iv);

  std::string iv_hex = parasyte::payload::encryption::Encryptor().ToHexString(iv);
  std::string key_hex = parasyte::payload::encryption::Encryptor().ToHexString(key);

  parasyte::payload::encryption::Encryptor encryptor;
  std::string plain = "Hello, World!";
  encryptor.SetKey(key_hex);
  std::vector<unsigned char> encrypted = encryptor.Encrypt(plain, iv_hex);
  std::string encrypted_hex = encryptor.ToHexString(encrypted);

  std::cout << "Encrypted: " << encrypted_hex << std::endl;

  std::vector<unsigned char> encrypted_bytes = encryptor.FromHexString(encrypted_hex);
  std::string decrypted = encryptor.Decrypt(encrypted_bytes, iv_hex);

  std::cout << "Decrypted: " << decrypted << std::endl;
  return 0;
}