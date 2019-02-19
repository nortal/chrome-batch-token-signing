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

#include "BinaryUtils.h"
#include "CertificateSelector.h"
#include "Exceptions.h"
#include "HashListParser.h"
#include "jsonxx.h"
#include "Labels.h"
#include "Logger.h"
#include "Signer.h"
#include "SigningPinDialog.h"
#include "VersionInfo.h"

#include <fcntl.h>
#include <io.h>
#include <memory>

using namespace std;
using namespace jsonxx;

string readMessage()
{
	uint32_t messageLength = 0;
	cin.read((char*)&messageLength, sizeof(messageLength));
	if (messageLength > 1024 * 8)
		throw InvalidArgumentException("Invalid message length " + to_string(messageLength));
	string message(messageLength, 0);
	cin.read(&message[0], messageLength);
	_log("Request(%i): %s ", messageLength, message.c_str());
	return message;
}

void sendMessage(const string &message)
{
	uint32_t messageLength = message.length();
	cout.write((char *)&messageLength, sizeof(messageLength));
	_log("Response(%i) %s ", messageLength, message.c_str());
	cout << message;
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
		WCHAR Pin[PIN2_LENGTH + 1] = { 0 };

		MultiByteToWideChar(CP_ACP, 0, pin.c_str(), -1, (LPWSTR)Pin, PIN2_LENGTH + 1);

		status = NCryptSetProperty(key, NCRYPT_PIN_PROPERTY, (PBYTE)Pin, (ULONG)wcslen(Pin) * sizeof(WCHAR), 0);

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
		else
		{
			_log("Successfully set NCRYPT_PIN_PROPERTY.", status);
		}
	}
	else {
		_log("PIN not checked, signing may ask PIN with the default dialog.");
		status = ERROR_SUCCESS;
	}
	return status;
}

string askPin(Signer& signer, const vector<unsigned char>& hash) {
	_log("Showing pin entry dialog");

	wstring label = Labels::l10n.get("sign PIN");
	size_t start_pos = 0;
	while ((start_pos = label.find(L"@PIN@", start_pos)) != std::string::npos) {
		label.replace(start_pos, 5, L"PIN");
		start_pos += 3;
	}

	bool isInitialCheck = true;
	int attemptsRemaining = 3;
	do {
		wstring msg;
		if (attemptsRemaining < 3)
		{
			if (!isInitialCheck)
				msg = Labels::l10n.get("incorrect PIN2");
			msg += Labels::l10n.get("tries left") + L" " + to_wstring(attemptsRemaining);
		}

		string pin = SigningPinDialog::getPin(label, msg);
		if (pin.empty()) {
			_log("User cancelled");
			throw UserCancelledException();
		}

		signer.setPin(pin);

		BOOL freeKeyHandle = false;
		NCRYPT_KEY_HANDLE key = signer.getCertificatePrivateKey(hash, &freeKeyHandle);
		int status = setAndCheckPIN(pin, key);
		if (freeKeyHandle) NCryptFreeObject(key);

		if (status == ERROR_SUCCESS) {
			return pin;
		}

		if (status == SCARD_W_WRONG_CHV) {
			_log("Wrong PIN2");
			attemptsRemaining--;
			isInitialCheck = false;
			continue;
		}
		if (status == SCARD_W_CHV_BLOCKED) {
			MessageBox(nullptr, Labels::l10n.get("PIN2 blocked").c_str(), L"PIN Blocked", MB_OK | MB_ICONERROR);
			_log("PIN2 blocked");
			throw PinBlockedException();
		}
		if (status == SCARD_W_CANCELLED_BY_USER) {
			_log("User cancelled");
			throw UserCancelledException();
		}
		throw TechnicalException("Signing failed: PIN/card error.");
	} while (true);
}

void massSign(vector<unsigned char>& selectedCert, jsonxx::Object& jsonRequest, jsonxx::Object& jsonResponse)
{
	if (!jsonRequest.has<string>("cert") || !jsonRequest.has<string>("hash"))
		throw InvalidArgumentException();

	vector<unsigned char> cert = BinaryUtils::hex2bin(jsonRequest.get<string>("cert"));
	_log("signing with certId: %s", jsonRequest.get<string>("cert").c_str());
	if (cert != selectedCert)
		throw NotSelectedCertificateException();

	string hashesList = jsonRequest.get<string>("hash");
	vector<vector<unsigned char>> hashes = HashListParser::parse(hashesList);

	int hashIndex = 0;
	size_t hashLength = 0;
	string pin = "";
	string signatures;

	vector<vector<unsigned char>>::iterator hash = hashes.begin();
	while (hash != hashes.end()) {
		hashIndex++;
		_log("Signing hash %d of %d", hashIndex, hashes.size());

		unique_ptr<Signer> signer(Signer::createSigner(cert));

		if (!signer->showInfo(jsonRequest.get<string>("info", string())))
			throw UserCancelledException();

		if (hashIndex == 1)
		{
			hashLength = hash->size();
			pin = askPin(*signer, *hash);
		}
		else if (hash->size() != hashLength)
		{
			_log("All hashes must have the same size for mass signing.");
			throw InvalidHashException();
		}

		_log("Setting PIN to signer...");
		signer->setPin(pin);

		string signature = BinaryUtils::bin2hex(signer->sign(*hash));

		// append the signature to comma separated signature list
		_log("Appending signature '%s'.", signature.c_str());
		signatures += (signatures.length() ? "," + signature : signature);

		hash = next(hash);
	}

	jsonResponse << "signature" << signatures;
}

int main(int argc, char **argv)
{
	//Necessary for sending correct message length to stout (in Windows)
	_setmode(_fileno(stdin), O_BINARY);
	_setmode(_fileno(stdout), O_BINARY);
	vector<unsigned char> selectedCert;
	while (true)
	{
		_log("Parsing input...");
		jsonxx::Object jsonRequest, jsonResponse;
		try {
			if (!jsonRequest.parse(readMessage()))
				throw InvalidArgumentException();

			if (!jsonRequest.has<string>("type") || !jsonRequest.has<string>("nonce") || !jsonRequest.has<string>("origin"))
				throw InvalidArgumentException();

			static const string origin = jsonRequest.get<string>("origin");
			if (jsonRequest.get<string>("origin") != origin)
				throw InconsistentOriginException();

			if (jsonRequest.has<string>("lang"))
				Labels::l10n.setLanguage(jsonRequest.get<string>("lang"));

			string type = jsonRequest.get<string>("type");
			if (type == "VERSION")
				jsonResponse << "version" << VERSION;
			else if (jsonRequest.get<string>("origin").compare(0, 6, "https:"))
				throw NotAllowedException("Origin doesn't contain https");
			else if (type == "CERT")
			{
				unique_ptr<CertificateSelector> certificateSelector(CertificateSelector::createCertificateSelector());
				selectedCert = certificateSelector->getCert(!jsonRequest.has<string>("filter") || jsonRequest.get<string>("filter") != "AUTH");
				jsonResponse << "cert" << BinaryUtils::bin2hex(selectedCert);
			}
			else if (type == "SIGN")
			{
				massSign(selectedCert, jsonRequest, jsonResponse);
			}
			else
				throw InvalidArgumentException();
		}
		// Only catch terminating exceptions here
		catch (const InvalidArgumentException &e)
		{
			_log("Handling exception: %s", e.getErrorCode());
			sendMessage((Object() << "result" << e.getErrorCode() << "message" << e.what()).json());
			return EXIT_FAILURE;
		}
		catch (const BaseException &e) {
			jsonResponse << "result" << e.getErrorCode() << "message" << e.what();
		}

		if (jsonRequest.has<string>("nonce"))
			jsonResponse << "nonce" << jsonRequest.get<string>("nonce");
		if (!jsonResponse.has<string>("result"))
			jsonResponse << "result" << "ok";
		jsonResponse << "api" << API;
		sendMessage(jsonResponse.json());
	}
	return EXIT_SUCCESS;
}
