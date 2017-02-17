/*
 * Chrome Token Signing Native Host
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#pragma once

#include "jsonxx.h"
#include "Logger.h"

#define BINARY_SHA1_LENGTH 20
#define BINARY_SHA224_LENGTH 28
#define BINARY_SHA256_LENGTH 32
#define BINARY_SHA384_LENGTH 48
#define BINARY_SHA512_LENGTH 64

using namespace std;

class Signer {
public:
	static Signer * createSigner(const jsonxx::Object &jsonRequest);

	Signer(const string &_hash, const string &_certInHex) : hash(_hash), certInHex(_certInHex) {}
	virtual ~Signer() = default;
	virtual string sign() = 0;
	
	string  getHash() const {
		return hash;
	}

  // set the current hash
  void setHash(string _hash) {
    hash = _hash;
  }

  // check if we have a hash
  bool hasHash() {
    return (hash != "");
  }

	string getCertInHex() {
		return certInHex;
	}

  // set pin
  void setPin(std::string _pin) {
    pin = _pin;
  }

  // get pin
  string& getPin() {
    return pin;
  }

  // check if we have a pin
  bool hasPin() {
    return (pin != "");
  }

protected:
  string getNextHash(std::string allHashes, int& position, char* separator=",")
  {
    std::string result("");
    bool found = false;

    // initialize search
    const char* str = allHashes.c_str();
    str += position;

    // skip separator in the beginning of search
    if (*str == *separator)
    {
      str++;
      position++;
    }

    // store the current position (beginning of substring)
    const char *begin = str;

    // while separator not found and not at end of string..
    while (*str != *separator && *str)
    {
      // ..go forward in the string.
      str++;
      position++;
    }

    // return what we've got, which is either empty string or a hash string
    result = std::string(begin, str);
    return result;
  }

private:
  string pin;
  string hash;
	string certInHex;
};