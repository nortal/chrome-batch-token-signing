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

#include "RequestHandler.h"
#include "Labels.h"
#include "Logger.h"
#include "VersionInfo.h"
#include "CertificateSelector.h"
#include "ContextMaintainer.h"
#include "Signer.h"
#include "BinaryUtils.h"
#include "PinDialog.h"
#include "ProgressBar.h"

#include <memory>

#ifndef PIN2_LENGTH          
#define PIN2_LENGTH          5
#endif

using namespace std;

extern bool cancelSigning;          // can be modified in progress bar dialog
CProgressBarDialog* progressBarDlg = NULL;
static time_t startTime;            // for performance logging

string getNextHash(string allHashes, int& position, char* separator = ",")
{
	string result("");
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


void validateHash(const vector<unsigned char>& hash) {
	switch (hash.size())
	{
	case BINARY_SHA1_LENGTH:
	case BINARY_SHA224_LENGTH:
	case BINARY_SHA256_LENGTH:
	case BINARY_SHA384_LENGTH:
	case BINARY_SHA512_LENGTH:
		break;
	default:
		_log("Hash length %i is invalid", hash.size());
		throw InvalidHashException();
	}
}

vector<vector<unsigned char>> getHashes(string allHashes) {
	vector<vector<unsigned char>> hashes;
	int hashPos = 0;

	string hashString = getNextHash(allHashes, hashPos);
	while (hashString != "") {
		_log("Received hash: %s", hashString.c_str());
		vector<unsigned char> hash = BinaryUtils::hex2bin(hashString);
		validateHash(hash);
		hashes.push_back(hash);
		hashString = getNextHash(allHashes, hashPos);
	}

	return hashes;
}

void initializeMFC() {
	HMODULE hModule = ::GetModuleHandle(NULL);
	if (hModule == NULL) {
		_log("MFC initialization failed. Module handle is null");
		throw TechnicalException("MFC initialization failed. Module handle is null");
	}
	// initialize MFC
	if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0)) {
		_log("MFC initialization failed");
		throw TechnicalException("MFC initialization failed");
	}
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

jsonxx::Object RequestHandler::handleRequest() {
	try {
		if (jsonRequest.parse(request)) {
			if (!hasGloballyRequiredArguments()) {
				throw InvalidArgumentException("Invalid argument");
			}

			validateOrigin(jsonRequest.get<string>("origin"));

			if (jsonRequest.has<string>("lang"))
				Labels::l10n.setLanguage(jsonRequest.get<string>("lang"));

			string type = jsonRequest.get<string>("type");
			if (type == "VERSION") {
				handleVersionRequest();
			}
			else if (type == "CERT") {
				handleCertRequest(!jsonRequest.has<string>("filter") || jsonRequest.get<string>("filter") != "AUTH");
			}
			else if (type == "SIGN" && hasSignRequestArguments()) {
				handleSignRequest();
			}
			else {
				throw InvalidArgumentException("Invalid argument for message type " + type);
			}
		}
		else {
			throw InvalidArgumentException("Failed to parse request JSON");
		}
	}
	catch (const InvalidArgumentException &) {
		throw;
	}
	catch (const BaseException &e) {
		handleException(e);
	}

	if (progressBarDlg) {
		if (progressBarDlg->IsWindow())
			progressBarDlg->DestroyWindow();
		delete progressBarDlg;
		progressBarDlg = NULL;
	}

	completeResponse();
	return jsonResponse;
}

bool RequestHandler::hasGloballyRequiredArguments() {
	return jsonRequest.has<string>("type") && jsonRequest.has<string>("nonce") && jsonRequest.has<string>("origin");
}

bool RequestHandler::hasSignRequestArguments() {
	return jsonRequest.has<string>("cert") && jsonRequest.has<string>("hash");
}

void RequestHandler::validateSecureOrigin() {
	if (!jsonRequest.has<string>("origin")) {
		throw NotAllowedException("Origin is not given");
	}
	string https("https:");
	string origin = jsonRequest.get<string>("origin");
	if (origin.compare(0, https.size(), https)) {
		throw NotAllowedException("Origin doesn't contain https");
	}
}

void RequestHandler::validateContext(const string &signingCertificate) {
	if (!ContextMaintainer::isSelectedCertificate(signingCertificate)) {
		throw NotSelectedCertificateException();
	}
}

void RequestHandler::validateOrigin(const string &origin) {
	if (!ContextMaintainer::isSameOrigin(origin)) {
		throw InconsistentOriginException();
	}
}

void RequestHandler::completeResponse() {
	if (jsonRequest.has<string>("nonce")) {
		//echo nonce
		jsonResponse << "nonce" << jsonRequest.get<string>("nonce");
	}
	// check for error
	if (!jsonResponse.has<string>("result")) {
		jsonResponse << "result" << "ok";
	}
	// add API version
	jsonResponse << "api" << API;
}

void RequestHandler::handleVersionRequest() {
	jsonResponse << "version" << VERSION;
}

void RequestHandler::handleCertRequest(bool forSigning) {
	validateSecureOrigin();
	unique_ptr<CertificateSelector> certificateSelector(CertificateSelector::createCertificateSelector());
	string selectedCert = BinaryUtils::bin2hex(certificateSelector->getCert(forSigning));
	ContextMaintainer::saveCertificate(selectedCert);
	jsonResponse << "cert" << selectedCert;
}

void RequestHandler::handleSignRequest() {
	validateSecureOrigin();

	string certInHex = jsonRequest.get<string>("cert");
	_log("Signing with cert: %s", certInHex.c_str());
	vector<unsigned char> certBin = BinaryUtils::hex2bin(certInHex);

	string hashesList = jsonRequest.get<string>("hash");
	vector<vector<unsigned char>> hashes = getHashes(hashesList);
	bool isMassSigning = hashes.size() > 1;

	std::string signatures("");  // for returned signatures

	int currentHash = 0;
	HWND hWndPB = NULL;
	string pin = "";

	vector<vector<unsigned char>>::iterator hash = hashes.begin();
	
	cancelSigning = false;
	while (hash != hashes.end() && !cancelSigning) {

		unique_ptr<Signer> signer(Signer::createSigner(certBin));

		// check the stored pin
		if (isMassSigning && pin == "") {
			_log("Asking PIN...");
			pin = askPin(*signer.get(), *hash);
		}

		_log("Setting PIN to signer...");
		signer->setPin(pin);

		if (hashes.size() > 2 && !progressBarDlg) {
			progressBarDlg = new CProgressBarDialog(hashes.size());
			hWndPB = progressBarDlg->Create(::GetActiveWindow(), 0);
			progressBarDlg->ShowWindow(SW_SHOWNORMAL);
			SendNotifyMessage(hWndPB, WM_UPDATE_PROGRESS, -1, 0);
		}

		currentHash++;
		if (startTime == 0) {
			time(&startTime);
		}

		if (!signer->showInfo(jsonRequest.get<string>("info", string())))
			throw UserCancelledException();

		_log("Signing hash %d of %d", currentHash, hashes.size());
		validateContext(certInHex);
		string signature = BinaryUtils::bin2hex(signer->sign(*hash));

		// append the signature to comma separated signature list
		_log("Appending signature '%s'.", signature.c_str());
		signatures += (signatures.length() ? "," + signature : signature);

		hash = next(hash);

		// update progress bar
		if (progressBarDlg && hWndPB && !cancelSigning) {
			SendNotifyMessage(hWndPB, WM_UPDATE_PROGRESS, 0, 0);
		}

		// process pending Windows messages
		processMessages();
	}

	pin = "";

	if (cancelSigning) {
		_log("CNG mass signing failed, user canceled while signing hash %d of %d.", currentHash, hashes.size());
		throw UserCancelledException("Signing was cancelled");
	}

	_log("%d hashes signed in %d seconds.", currentHash, (int)difftime(time(NULL), startTime));
	if (progressBarDlg) {
		if (progressBarDlg->IsWindow())
			progressBarDlg->DestroyWindow();
		delete progressBarDlg;
		progressBarDlg = NULL;
	}

	_log("All signatures: %s", signatures.c_str());

	_log("Signing ended");
	jsonResponse << "signature" << signatures;
}

void RequestHandler::handleException(const BaseException &e) {
	jsonxx::Object exceptionalJson;
	exceptionalJson << "result" << e.getErrorCode() << "message" << e.what();
	jsonResponse = exceptionalJson;
}

std::wstring getSignPinLabel() {
	std::wstring label = Labels::l10n.get("sign PIN");
	size_t start_pos = 0;
	while ((start_pos = label.find(L"@PIN@", start_pos)) != std::string::npos) {
		label.replace(start_pos, 5, L"PIN2");
		start_pos += 3;
	}
	return label;
}

int setAndCheckPIN(string pin, NCRYPT_KEY_HANDLE key) {
	/* Return values:
	*   ERROR_SUCCESS         Valid PIN (or PIN not checked)
	*   SCARD_W_WRONG_CHV     Wrong PIN.
	*   SCARD_W_CHV_BLOCKED   Card is blocked.
	*   Other                 Other error (should be handled as fatal).
	*/
	int status;

	if (key) {
		// convert the PIN to Unicode
		WCHAR Pin[PIN2_LENGTH * 2] = { 0 };
		int pinLen = pin.length();
		MultiByteToWideChar(CP_ACP, 0, pin.c_str(), -1, (LPWSTR)Pin, pinLen);

		// pass the PIN to CNG
		status = NCryptSetProperty(key, NCRYPT_PIN_PROPERTY, (PBYTE)Pin, (ULONG)wcslen(Pin)*sizeof(WCHAR), 0);

		// check the result
		if (status == SCARD_W_WRONG_CHV) {
			// 0x8010006b: wrong pin
			_log("**** Error 0x%x returned by NCryptSetProperty(NCRYPT_PIN_PROPERTY): Wrong PIN.\n", status);
		}
		else if (status == SCARD_W_CHV_BLOCKED) {
			// 0x8010006c: card is blocked
			_log("**** Error 0x%x returned by NCryptSetProperty(NCRYPT_PIN_PROPERTY): Card blocked.\n", status);
		}
		else if (status != ERROR_SUCCESS)
		{
			// other error
			_log("**** Error 0x%x returned by NCryptSetProperty(NCRYPT_PIN_PROPERTY).\n", status);
		}
	}
	else {
		// PIN not checked, signing may ask PIN with the default dialog.
		status = ERROR_SUCCESS;
	}

	return status;
}

wstring getWrongPinErrorMessage(int triesLeft) {
	if (triesLeft == 1) {
		wstring msg = Labels::l10n.get("incorrect PIN2") + L" " + Labels::l10n.get("one try left");
		return msg;
	}
	if (triesLeft > 1) {
		wstring msg = Labels::l10n.get("incorrect PIN2") + L" " + Labels::l10n.get("tries left") + L" " + to_wstring(triesLeft);
		return msg;
	}
	else {
		// Number of retries left should be read from the card...
		return L"Sisestati vale PIN.";
	}
}

void showWrongPinError(int triesLeft) {
	_log("Showing incorrect pin error dialog, %i tries left", triesLeft);
	wstring msg = getWrongPinErrorMessage(triesLeft);
	MessageBox(NULL, msg.c_str(), Labels::l10n.get("incorrect PIN2").c_str(), MB_OK | MB_ICONERROR);
}

void showPinBlocked() {
	_log("Showing pin blocked dialog");
	MessageBox(NULL, L"Vale PIN sisestati liiga palju kordi. PIN blokeeritud.", L"PIN blokeeritud!", MB_OK | MB_ICONERROR);
}

string RequestHandler::askPin(Signer& signer, const vector<unsigned char>& hash) {
	_log("Showing pin entry dialog");
	initializeMFC();

	int attemptsRemaining = 3;
	do {
		PinDialog dialog(getSignPinLabel());
		INT_PTR nResponse = dialog.DoModal();
		dialog.NextDlgCtrl();

		if (nResponse != IDOK) {
			_log("User cancelled");
			throw UserCancelledException();
		}

		string pin = dialog.getPin();
		if (pin.length() != PIN2_LENGTH) {
			// Wrong PIN length does not count as a try
			showWrongPinError(-1);
			continue;
		}

		BOOL freeKeyHandle = false;
		NCRYPT_KEY_HANDLE key = signer.getCertificatePrivateKey(hash, &freeKeyHandle);

		int status = setAndCheckPIN(pin, key);
		attemptsRemaining--;

		if (freeKeyHandle) NCryptFreeObject(key);

		if (status == SCARD_W_WRONG_CHV) {
			showWrongPinError(attemptsRemaining);
			continue;
		} else if (status == SCARD_W_CHV_BLOCKED) {
			showPinBlocked();
			throw PinBlockedException();
		}
		else if (status == SCARD_W_CANCELLED_BY_USER) {
			throw UserCancelledException();
		}
		else if (status != ERROR_SUCCESS) {
			throw TechnicalException("Signing failed: PIN/card error.");
		}
		return pin;
	} while (true);
}
