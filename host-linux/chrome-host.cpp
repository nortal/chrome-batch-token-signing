/* Chrome Linux plugin
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

#include <iostream>
#include <iomanip>
#include <gtkmm.h>
#include "BinaryUtils.h"
#include "jsonxx.h"
#include "InputParser.h"
#include "Logger.h"
#include "Signer.h"
#include "CertificateSelection.h"
#include "VersionInfo.h"
#include "Labels.h"

using namespace std;
using namespace BinaryUtils;
using namespace jsonxx;

int readMessageLengthFromCin();

int main(int argc, char **argv) {

  Gtk::Main kit(argc, argv);

  InputParser parser(cin);
  _log("Parsing input...");
  Object json = parser.readBody();

  if (json.has<string>("lang")) {
    l10nLabels.setLanguage(json.get<string>("lang"));
  }

  Object resp;
  if (!json.has<string>("protocol") || json.get<string>("protocol") != "https:") {
    resp << "result" << "not_allowed";
  } else if(!json.has<string>("type")) {
    resp << "result" << "invalid_argument";
  } else {
    string type = json.get<string>("type");

    if (type == "SIGN") {
      string hashFromStdIn = json.get<String>("hash");
      string cert = json.get<String>("cert");
      _log("signing hash: %s, with cert: %s", hashFromStdIn.c_str(), cert.c_str());
      Signer signer(hashFromStdIn, cert);
      resp = signer.sign();
    } else if (type == "CERT") {
      CertificateSelection cert;
      resp = cert.getCert();
    } else if (type == "VERSION") {
      VersionInfo version;
      resp = version.getVersion();
    } else {
      resp << "result" << "invalid_argument";
    }
  }

  if (json.has<string>("nonce")) {
    resp << "nonce" << json.get<string>("nonce");
  }

  string response = resp.json();
  int responseLength = response.size();
  unsigned char *responseLengthAsBytes = intToBytesLittleEndian(responseLength);
  cout.write((char *) responseLengthAsBytes, 4);
  _log("Response(%i) %s ", responseLength, response.c_str());
  cout << response << endl;
  free(responseLengthAsBytes);
  return EXIT_SUCCESS;
}
