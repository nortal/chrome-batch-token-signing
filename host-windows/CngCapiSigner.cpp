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

#include "CngCapiSigner.h"
#include "BinaryUtils.h"
#include "HostExceptions.h"
#include <Windows.h>
#include <ncrypt.h>
#include <WinCrypt.h>
#include <cryptuiapi.h>
#include "Logger.h"
#include "ProgressBar.h"
#include <time.h>

using namespace std;

extern bool cancelSigning;          // can be modified in progress bar dialog
extern CProgressBarDialog* progressBarDlg; // may need to be accesses in request handler
static time_t startTime;            // for performance logging

// local functions are used to avoid adding more include dependencies CngCapiSigner.h
SECURITY_STATUS setPinForSigningCNG(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key, string& pin);
DWORD           setPinForSigningCSP(HCRYPTPROV key, string& pin);

int getHashCount(const char* allHashes) {
  // calculate the number of hashes in the given hash string
  int len = 0;
  int count = 0;
  if (allHashes) {
    while (allHashes[len]) {
      if (allHashes[len] == ',') {
        count++;
      }
      len++;
    }
    count++;
  }
  return count;
}

void processMessages() {
  //int cnt = 0;
  MSG msg;
  while (::PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))// && cnt++ < 10)
  {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }
}

void CngCapiSigner::setHashes(string allHashes) {
  int hashPos = 0;
  string hash = getNextHash(allHashes, hashPos);
  while (hash != "") {
    hashes.push_back(hash);
    hash = getNextHash(allHashes, hashPos);
  }
}

string CngCapiSigner::doSign() {

  BCRYPT_PKCS1_PADDING_INFO padInfo;
	DWORD obtainKeyStrategy = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG;
	vector<unsigned char> digest = BinaryUtils::hex2bin(getHash());

	ALG_ID alg = 0;
	
	switch (digest.size())
	{
	case BINARY_SHA1_LENGTH:
		padInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
		alg = CALG_SHA1;
		break;
	case BINARY_SHA224_LENGTH:
		padInfo.pszAlgId = L"SHA224";
		obtainKeyStrategy = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
		break;
	case BINARY_SHA256_LENGTH:
		padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
		alg = CALG_SHA_256;
		break;
	case BINARY_SHA384_LENGTH:
		padInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM;
		alg = CALG_SHA_384;
		break;
	case BINARY_SHA512_LENGTH:
		padInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM;
		alg = CALG_SHA_512;
		break;
	default:
    _log("sign(): Invalid hash size, length: %d, hexLength: %d, hash: '%s'.", 
      getHash().length(), digest.size(), getHash());
		throw InvalidHashException();
	}
	
	SECURITY_STATUS err = 0;
	DWORD size = 256;
	vector<unsigned char> signature(size, 0);

  _log("sign(): Getting certficate...");

	HCERTSTORE store = CertOpenSystemStore(0, L"MY");
	if (!store) {
		throw TechnicalException("Failed to open Cert Store");
	}
	
	vector<unsigned char> certInBinary = BinaryUtils::hex2bin(getCertInHex());
	
	PCCERT_CONTEXT certFromBinary = CertCreateCertificateContext(X509_ASN_ENCODING, &certInBinary[0], certInBinary.size());
	PCCERT_CONTEXT certInStore = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, certFromBinary, 0);
	CertFreeCertificateContext(certFromBinary);

	if (!certInStore)
	{
		CertCloseStore(store, 0);
		throw NoCertificatesException();
	}

  _log("sign(): Getting key...");

	DWORD flags = obtainKeyStrategy | CRYPT_ACQUIRE_COMPARE_KEY_FLAG;
	DWORD spec = 0;
	BOOL freeKeyHandle = false;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = NULL;
	BOOL gotKey = true;
  gotKey = CryptAcquireCertificatePrivateKey(certInStore, flags, 0, &key, &spec, &freeKeyHandle);
	CertFreeCertificateContext(certInStore);
	CertCloseStore(store, 0);

	switch (spec) 
	{
	case CERT_NCRYPT_KEY_SPEC:
	{
    _log("sign(): spec=CERT_NCRYPT_KEY_SPEC");
    _log("sign(): Calling NCryptSignHash with hash='%s'.", getHash());

    if (hasPin()) {
      setPinForSigningCNG(key, getPin());
    }

		err = NCryptSignHash(key, &padInfo, PBYTE(&digest[0]), DWORD(digest.size()),
      &signature[0], DWORD(signature.size()), (DWORD*)&size, BCRYPT_PAD_PKCS1);
    _log("sign(): NCryptSignHash called.");

		if (freeKeyHandle) {
			NCryptFreeObject(key);
		}
		break;
	}
	case AT_SIGNATURE:
	{
    _log("sign(): spec=AT_SIGNATURE");
		HCRYPTHASH hash = 0;
		if (!CryptCreateHash(key, alg, 0, 0, &hash)) {
			if (freeKeyHandle) {
				CryptReleaseContext(key, 0);
			}
			throw TechnicalException("CreateHash failed");
		}

		if (!CryptSetHashParam(hash, HP_HASHVAL, digest.data(), 0))	{
			if (freeKeyHandle) {
				CryptReleaseContext(key, 0);
			}
			CryptDestroyHash(hash);
			throw TechnicalException("SetHashParam failed");
		}

    if (hasPin()) {
      _log("Setting PIN for CryptSignHashW()...");
      setPinForSigningCSP(key, getPin());
    }

		INT retCode = CryptSignHashW(hash, AT_SIGNATURE, 0, 0, LPBYTE(signature.data()), &size);
		err = retCode ? ERROR_SUCCESS : GetLastError();
		_log("CryptSignHash() return code: %u (%s) %x", retCode, retCode ? "SUCCESS" : "FAILURE", err);
		if (freeKeyHandle) {
			CryptReleaseContext(key, 0);
		}
		CryptDestroyHash(hash);
		signature.resize(size);
		reverse(signature.begin(), signature.end());
		break;
	}
	default:
		throw TechnicalException("Incompatible key");
	}

	switch (err)
	{
	case ERROR_SUCCESS:
		break;
	case SCARD_W_CANCELLED_BY_USER: case ERROR_CANCELLED:
		throw UserCancelledException("Signing was cancelled");
	case SCARD_W_CHV_BLOCKED:
		throw PinBlockedException();
	case NTE_INVALID_HANDLE:
		throw TechnicalException("The supplied handle is invalid");
	default:
		throw TechnicalException("Signing failed");
	}
	signature.resize(size);
	return BinaryUtils::bin2hex(signature);
}

string CngCapiSigner::sign() {

  // sign all hashes
  std::string signatures("");         // for returned signatures
  std::string allHashes(getHash());  // all hashes
  int hashPos = 0;                    // search position in the complete hash string

  int currentHash = 0;
  HWND hWndPB = NULL;

#if FALSE // TESTING
  allHashes =
    //"cf83638fc7d64d14d3a2ad94799c59bb29501b18d2b1c796d0377a69ca4b4216,"
    //"680f4f1a2adb87f8e181d155bf0379c0b92bbca235b336dec8f01e7f2b73c030,"
    //"b1ce7a7c9b2c93064cbd191e2d8a933e823179a1f0226685b4baf07162b6d4b0,"
    //"cf83638fc7d64d14d3a2ad94799c59bb29501b18d2b1c796d0377a69ca4b4216,"
    //"680f4f1a2adb87f8e181d155bf0379c0b92bbca235b336dec8f01e7f2b73c030,"
    //"b1ce7a7c9b2c93064cbd191e2d8a933e823179a1f0226685b4baf07162b6d4b0,"
    //"cf83638fc7d64d14d3a2ad94799c59bb29501b18d2b1c796d0377a69ca4b4216,"
    //"680f4f1a2adb87f8e181d155bf0379c0b92bbca235b336dec8f01e7f2b73c030,"
    //"b1ce7a7c9b2c93064cbd191e2d8a933e823179a1f0226685b4baf07162b6d4b0,"
    //"cf83638fc7d64d14d3a2ad94799c59bb29501b18d2b1c796d0377a69ca4b4216,"
    "680f4f1a2adb87f8e181d155bf0379c0b92bbca235b336dec8f01e7f2b73c030,"
    "b1ce7a7c9b2c93064cbd191e2d8a933e823179a1f0226685b4baf07162b6d4b0,"
    "cf83638fc7d64d14d3a2ad94799c59bb29501b18d2b1c796d0377a69ca4b4216,"
    "680f4f1a2adb87f8e181d155bf0379c0b92bbca235b336dec8f01e7f2b73c030,"
    "b1ce7a7c9b2c93064cbd191e2d8a933e823179a1f0226685b4baf07162b6d4b0,"
    "cf83638fc7d64d14d3a2ad94799c59bb29501b18d2b1c796d0377a69ca4b4216,"
    "680f4f1a2adb87f8e181d155bf0379c0b92bbca235b336dec8f01e7f2b73c030,"
    "b1ce7a7c9b2c93064cbd191e2d8a933e823179a1f0226685b4baf07162b6d4b0,"
    "cf83638fc7d64d14d3a2ad94799c59bb29501b18d2b1c796d0377a69ca4b4216,"
    "680f4f1a2adb87f8e181d155bf0379c0b92bbca235b336dec8f01e7f2b73c030";
#endif //TESTING

  setHashes(allHashes);

  // check if we are signing multiple hashes
  bool isMassSigning = (allHashes.find(",") != string::npos);
  int hashCount = getHashCount(allHashes.c_str());

  // get the first hash from the comma separated list
  setHash(getNextHash(allHashes, hashPos));

  // While we have a hash string...
  cancelSigning = false;
  while (hasHash() && !cancelSigning) {

    // check the stored pin
    if (isMassSigning && !hasPin()) {
      bool pinOk;
      do {
        setPin(askPin(5));
        // checkPin() throws if card is blocked!
        pinOk = checkPin(); 
      } while (!pinOk);
    }

    if (hashCount > 2 && !progressBarDlg) {
      progressBarDlg = new CProgressBarDialog(hashCount);
      hWndPB = progressBarDlg->Create(::GetActiveWindow(), 0);
      progressBarDlg->ShowWindow(SW_SHOWNORMAL);
      SendNotifyMessage(hWndPB, WM_UPDATE_PROGRESS, -1, 0);
    }

    currentHash++;
    if (startTime == 0) {
      time(&startTime);
    }

    // create a signature for the given hash
    std::string result = doSign();

    // append the signature to comma separated signature list
    _log("Appending signature '%s'.", result.c_str());
    signatures += (signatures.length() ? "," + result : result);

    // get the next hash string (or "" if nothing is left).
    setHash(getNextHash(allHashes, hashPos));

    // update progress bar
    if (progressBarDlg && hWndPB && !cancelSigning) {
      SendNotifyMessage(hWndPB, WM_UPDATE_PROGRESS, 0, 0);
    }
    // process pending Windows messages
    processMessages();
  }
  
  setPin("");
  
  if (cancelSigning) {
    _log("CNG mass signing failed, user canceled while signing hash %d of %d.", currentHash, hashCount);
    throw UserCancelledException("Signing was cancelled");
  }

  _log("%d hashes signed in %d seconds.", currentHash, (int)difftime(time(NULL), startTime));
  if (progressBarDlg) {
    if (progressBarDlg->IsWindow())
      progressBarDlg->DestroyWindow();
    delete progressBarDlg;
    progressBarDlg = NULL;
  }

  return signatures;
}

string CngCapiSigner::askPin(int pinLength) {
  //_log("ASKING PIN!!!");
  char* signingPin = pinDialog.getPin();
  return signingPin;
}

bool CngCapiSigner::checkPin() {
  bool result = false;
  _log("sign(): Checking PIN...");

  // *** get the key, copied from the beginning of doSign() ***
  BCRYPT_PKCS1_PADDING_INFO padInfo;
  DWORD obtainKeyStrategy = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG;
  vector<unsigned char> digest = BinaryUtils::hex2bin(getHash());
  ALG_ID alg = 0;
  switch (digest.size())
  {
  case BINARY_SHA1_LENGTH:
    padInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
    alg = CALG_SHA1;
    break;
  case BINARY_SHA224_LENGTH:
    padInfo.pszAlgId = L"SHA224";
    obtainKeyStrategy = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
    break;
  case BINARY_SHA256_LENGTH:
    padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
    alg = CALG_SHA_256;
    break;
  case BINARY_SHA384_LENGTH:
    padInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM;
    alg = CALG_SHA_384;
    break;
  case BINARY_SHA512_LENGTH:
    padInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM;
    alg = CALG_SHA_512;
    break;
  default:
    _log("sign(): Invalid hash size, length: %d, hexLength: %d, hash: '%s'.",
      getHash().length(), digest.size(), getHash());
    throw InvalidHashException();
  }
  HCERTSTORE store = CertOpenSystemStore(0, L"MY");
  if (!store) {
    throw TechnicalException("Failed to open Cert Store");
  }
  vector<unsigned char> certInBinary = BinaryUtils::hex2bin(getCertInHex());
  PCCERT_CONTEXT certFromBinary = CertCreateCertificateContext(X509_ASN_ENCODING, &certInBinary[0], certInBinary.size());
  PCCERT_CONTEXT certInStore = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, certFromBinary, 0);
  CertFreeCertificateContext(certFromBinary);
  if (!certInStore)
  {
    CertCloseStore(store, 0);
    throw NoCertificatesException();
  }

  DWORD flags = obtainKeyStrategy | CRYPT_ACQUIRE_COMPARE_KEY_FLAG;
  DWORD spec = 0;
  BOOL freeKeyHandle = false;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = NULL;
  BOOL gotKey = true;
  gotKey = CryptAcquireCertificatePrivateKey(certInStore, flags, 0, &key, &spec, &freeKeyHandle);
  CertFreeCertificateContext(certInStore);
  CertCloseStore(store, 0);

  // *** try to set the PIN ***
  SECURITY_STATUS st = setPinForSigningCNG(key, getPin());
  if (freeKeyHandle) {
    NCryptFreeObject(key);
  }

  if (st == ERROR_SUCCESS) {
    _log("sign(): PIN OK.");
    result = true;
  }
  else if (st == SCARD_W_WRONG_CHV){
    DialogManager mgr;
    mgr.showWrongPinError(-1);
    result = false;
  }
  else if (st == SCARD_W_CHV_BLOCKED) {
    DialogManager mgr;
    mgr.showPinBlocked();
    throw PinBlockedException();
  }
  else {
    throw TechnicalException("ERROR: Failed to check PIN.");
  }

  return result;
}

SECURITY_STATUS setPinForSigningCNG(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key, string& pin) {
  SECURITY_STATUS st = ERROR_SUCCESS;

  _log("Setting PIN for NCryptSignHash()...");

  WCHAR Pin[10] = { 0 };
  int pinLen = pin.length();
  MultiByteToWideChar(CP_ACP, 0, pin.c_str(), -1, (LPWSTR)Pin, pinLen);
  st = NCryptSetProperty(key, NCRYPT_PIN_PROPERTY, (PBYTE)Pin, (ULONG)wcslen(Pin)*sizeof(WCHAR), 0);
  switch (st) {
  case ERROR_SUCCESS:
    break;
    
  case SCARD_W_WRONG_CHV:
    // Wrong PIN entered with the custom dialog.
    _log("**** Error: Wrong PIN given to NCryptSetProperty(NCRYPT_PIN_PROPERTY)!\n");
    break;
    
  case SCARD_W_CHV_BLOCKED:
    _log("**** Error: Card blocked error returned by NCryptSetProperty(NCRYPT_PIN_PROPERTY)!\n");
    break;

  default:
    // Reset the stored PIN also on other errors.
    _log("**** Error 0x%x returned by NCryptSetProperty(NCRYPT_PIN_PROPERTY)\n", st);
    break;
  }

  return st;
}

DWORD setPinForSigningCSP(HCRYPTPROV key, string& pin) {
  DWORD result = ERROR_SUCCESS;

  if (pin != "") {
    if (!CryptSetProvParam(key, PP_KEYEXCHANGE_PIN, (PBYTE)pin.c_str(), 0))
    {
      result = GetLastError();
      _log("CryptSetProvParam() ended with ERROR 0x%08X", result);
    }
  }

  return result;
}
