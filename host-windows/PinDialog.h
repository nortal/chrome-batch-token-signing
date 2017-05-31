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

#include "resource.h"
#include <string>

#include <afxcmn.h>
#include <string>

class PinDialog : public CDialog
{
	DECLARE_DYNAMIC(PinDialog)

public:
	PinDialog(const std::wstring &_label, CWnd* pParent = NULL) : CDialog(PinDialog::IDD, pParent), label(_label) {
        HWND hCurWnd = ::GetForegroundWindow();
        DWORD dwMyID = ::GetCurrentThreadId();
        DWORD dwCurID = ::GetWindowThreadProcessId(hCurWnd, NULL);
        ::AttachThreadInput(dwCurID, dwMyID, TRUE);
        ::SetWindowPos(m_hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
        ::SetWindowPos(m_hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
        ::SetForegroundWindow(m_hWnd);
        ::AttachThreadInput(dwCurID, dwMyID, FALSE);
        ::SetFocus(m_hWnd);
        ::SetActiveWindow(m_hWnd);
    }
	char* getPin();
	afx_msg void OnBnClickedOk();

	// Dialog Data
	enum { IDD = IDD_PIN_DIALOG };

protected:
	DECLARE_MESSAGE_MAP()
	virtual BOOL OnInitDialog() override;

private:
	char* pin;
	std::wstring label;
};
