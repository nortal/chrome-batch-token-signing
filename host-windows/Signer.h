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

#include <string>
#include <vector>

#define BINARY_SHA1_LENGTH 20
#define BINARY_SHA224_LENGTH 28
#define BINARY_SHA256_LENGTH 32
#define BINARY_SHA384_LENGTH 48
#define BINARY_SHA512_LENGTH 64

class Signer {
public:
	virtual ~Signer() = default;

	static Signer* createSigner(const std::string &cert);
	std::string getCertInHex() const { return certInHex; }
	bool showInfo(const std::string &msg);
	virtual std::vector<unsigned char> sign(const std::vector<unsigned char> &digest) = 0;

protected:
	Signer(const std::string &_certInHex): certInHex(_certInHex) {}

public:
	std::vector<unsigned char>  getHash() const {
		return hash;
	}

	// set the current hash
	void setHash(std::vector<unsigned char> _hash) {
    hash = _hash;
  }

  // check if we have a hash
  bool hasHash() {
    return (hash.size() != 0);
  }

	std::string getCertInHex() {
		return certInHex;
	}

  // set pin
  void setPin(std::string _pin) {
    pin = _pin;
  }

  // get pin
  std::string& getPin() {
    return pin;
  }

  // check if we have a pin
  bool hasPin() {
    return (pin != "");
  }

protected:
  std::string getNextHash(std::string allHashes, int& position, char* separator=",")
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
  std::string pin;
  std::vector<unsigned char> hash;
	std::string certInHex;
};
