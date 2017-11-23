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

#include <list>
#include "Signer.h"
#include "DialogManager.h"

class CngCapiSigner : public Signer {
public:
	CngCapiSigner(const std::string &certInHex) : Signer(certInHex){
    pinTriesLeft = 3;
  }
	std::vector<unsigned char> sign(const std::vector<unsigned char> &digest) override;

  /*
  // get the current hash or NULL
  string * getHash() {
    if (hashes.size() > 0)
      return &(*hashes.begin());
    else
      return NULL;
  }

  // get the next hash or NULL
  string * nextHash() {
    if (hashes.size() > 0)
      hashes.pop_front();
    string* pHash = getHash();
    if (pHash)
      setHash(*pHash);
    return pHash;
  }
  */

private:
  std::list<std::string>  hashes; // to be used later
  int           pinTriesLeft;
  DialogManager pinDialog;

  void    setHashes(std::string allHashes);
  std::vector<unsigned char> doSign(const std::vector<unsigned char> &digest);
  std::string  askPin(int pinLength);
  bool    checkPin();
};