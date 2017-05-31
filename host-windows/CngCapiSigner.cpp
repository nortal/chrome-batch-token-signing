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

// local functions are used to avoid adding more include dependencies CngCapiSigner.h
SECURITY_STATUS setPinForSigningCNG(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key, string& pin);
DWORD           setPinForSigningCSP(HCRYPTPROV key, string& pin);

vector<unsigned char> CngCapiSigner::sign(const vector<unsigned char> &digest)
{
	BCRYPT_PKCS1_PADDING_INFO padInfo;
	DWORD obtainKeyStrategy = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG;

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
		string hexDigest = BinaryUtils::bin2hex(digest);
		_log("sign(): Invalid hash size, length: %d, hexLength: %d, hash: '%s'.",
			digest.size(), hexDigest.length(), hexDigest);
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
	
	PCCERT_CONTEXT certFromBinary = CertCreateCertificateContext(X509_ASN_ENCODING, certInBinary.data(), certInBinary.size());
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
    if (hasPin()) {
      setPinForSigningCNG(key, getPin());
    }

		err = NCryptSignHash(key, &padInfo, PBYTE(digest.data()), DWORD(digest.size()),
			signature.data(), DWORD(signature.size()), (DWORD*)&size, BCRYPT_PAD_PKCS1);
    _log("sign(): NCryptSignHash called.");

		if (freeKeyHandle) {
			NCryptFreeObject(key);
		}
		signature.resize(size);
		break;
	}
	case AT_KEYEXCHANGE:
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
		INT retCode = CryptSignHashW(hash, spec, 0, 0, LPBYTE(signature.data()), &size);
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
		return signature;
	case SCARD_W_CANCELLED_BY_USER:
	case ERROR_CANCELLED:
		throw UserCancelledException("Signing was cancelled");
	case SCARD_W_CHV_BLOCKED:
		throw PinBlockedException();
	case NTE_INVALID_HANDLE:
		throw TechnicalException("The supplied handle is invalid");
	default:
		throw TechnicalException("Signing failed");
	}
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
