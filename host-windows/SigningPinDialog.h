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

#include "stdafx.h"
#include <string>

#define PIN2_LENGTH 5

// SigningPinDialog is equivalent to PinDialog, but allows 5-digit PIN2 codes to be entered
// and focuses itself when shown.
class SigningPinDialog
{
public:
	static std::string getPin(const std::wstring &label, const std::wstring &message, HWND pParent = NULL);

private:
	SigningPinDialog() {}
	static INT_PTR CALLBACK DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	std::wstring label, message;
	std::string pin;
};
