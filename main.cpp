#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <time.h>
#include <sddl.h>
#include <wchar.h>
#include <mswsock.h>
#include <aclapi.h>
#include <lmcons.h>
#include <vector>
#include <chrono>
#include <tchar.h>
#include <locale>
#include <codecvt>
#include <sstream>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib") 
#pragma comment(lib, "mswsock.lib")
#pragma warning(disable: 4996)

#define MAX_CLIENTS (100)
#define CLIENT_TIME 180
#define WIN32_LEAN_AND_MEAN

#define MAX_CLIENTS (100)
#define WIN32_LEAN_AND_MEAN

#define KEY_BUF_SIZE 256

void handle_client_request(DWORD idx, const std::string& request);

HCRYPTPROV hCryptProv = NULL;  // ����� ����������������

//void initCrypto()
//{
//	// ������������� ����������������
//	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
//	{
//		std::cerr << "Error initializing CryptoAPI: " << GetLastError() << std::endl;
//		exit(EXIT_FAILURE);
//	}
//}
//
//void cleanupCrypto()
//{
//	// ������������ �������� ����������������
//	if (hCryptProv)
//	{
//		CryptReleaseContext(hCryptProv, 0);
//		hCryptProv = NULL;
//	}
//}
//
//void encryptData(const BYTE* pData, DWORD dataSize, BYTE** ppEncryptedData, DWORD* pEncryptedSize)
//{
//	HCRYPTKEY hSessionKey = NULL;
//
//	// ��������� ���������� �����
//	if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hSessionKey))
//	{
//		std::cerr << "Error generating session key: " << GetLastError() << std::endl;
//		return;
//	}
//
//	// ���������� ������
//	if (!CryptEncrypt(hSessionKey, 0, TRUE, 0, NULL, &dataSize, 0))
//	{
//		std::cerr << "Error encrypting data (size determination): " << GetLastError() << std::endl;
//		CryptDestroyKey(hSessionKey);
//		return;
//	}
//
//	*ppEncryptedData = new BYTE[dataSize];
//	*pEncryptedSize = dataSize;
//
//	memcpy(*ppEncryptedData, pData, dataSize);
//
//	CryptDestroyKey(hSessionKey);
//}
//
//void decryptData(const BYTE* pEncryptedData, DWORD encryptedSize, BYTE** ppDecryptedData, DWORD* pDecryptedSize)
//{
//	HCRYPTKEY hSessionKey = NULL;
//
//	// ��������� ���������� �����
//	if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hSessionKey))
//	{
//		std::cerr << "Error generating session key: " << GetLastError() << std::endl;
//		return;
//	}
//
//	*ppDecryptedData = new BYTE[encryptedSize];
//	*pDecryptedSize = encryptedSize;
//
//	memcpy(*ppDecryptedData, pEncryptedData, encryptedSize);
//
//	// ����������� ������
//	if (!CryptDecrypt(hSessionKey, 0, TRUE, 0, *ppDecryptedData, pDecryptedSize))
//	{
//		std::cerr << "Error decrypting data: " << GetLastError() << std::endl;
//		CryptDestroyKey(hSessionKey);
//		return;
//	}
//
//	CryptDestroyKey(hSessionKey);
//}

struct client_ctx
{
	int socket;
	CHAR buf_recv[512]; // ����� ������ 
	CHAR buf_send[512]; // ����� �������� 
	unsigned int sz_recv; // ������� ������
	unsigned int sz_send_total; // ������ � ������ ��������
	unsigned int sz_send; // ������ ����������

	 // ��������� OVERLAPPED ��� ����������� � ����������
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // ����� ��� WSARecv. WSARecv - ������� ��� ������ ������
	bool closeConnection;

	//HCRYPTPROV DescCSP;
	//HCRYPTKEY hPublicKey;
	//HCRYPTKEY hPrivateKey;

	HCRYPTPROV DescCSP = 0;
	HCRYPTKEY DescKey = 0;
	HCRYPTKEY DescKey_open = 0;
};

// OVERLAPPED - ���������, �������� ��������� ������, ����������� ���
// ���������� �����-������ ��. ��� ������ ������� ������ ��������� ������ ����
// ��������� ������.��� ���������� �������� �����-������ ������� �������� ���������
// �� ���������� � ������ �������� ��������� OVERLAPPED. ������ ��� ���������
// ����������, ����� ������ �������� ���� ���������.

// �������������� ����� � ��� ������ ����������� ��������
// � ������� �������� (������ � overlapped � ��������) 
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

void crypt_keys(int idx)
{
	// ��� �������� ���������� ������ � ������������ CSP
	/*phProv � ��������� � ���������� CSP.
	  pszContainer � ��� ���������� ������.
	  pszProvider � ��� CSP.
	  dwProvType � ��� CSP.
	  dwFlags � �����.*/
	if (!CryptAcquireContextW(&g_ctxs[idx].DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL))
	{
		if (!CryptAcquireContextW(&g_ctxs[idx].DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, (CRYPT_NEWKEYSET)))
			printf("ERROR!, %x", GetLastError());
	}

	//������ ������� ������������� ��� ��������� ���������� �����, � ����� ���\
	��������� ��� ������ ��� ������ � �������� �������
	/*
	hProv� ���������� CSP.
	Algid � ������������� ���������.
	dwFlags � �����.
	phKey � ��������� �� ���������� �����.
	*/
	if (CryptGenKey(g_ctxs[idx].DescCSP, CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), &g_ctxs[idx].DescKey) == 0)
		printf("ERROR!!, %x", GetLastError());

	//������ �������� ��������� ���� �������
	//������� ������ ����� �����
	/*
	hProv � ���������� CSP.
	pbData � ������������� ���� �������������� � ���� ������� ����.
	dwDataLen ������ ������ � pbData.
	hPubKey - ���������� �����, ������� ���������� ���� ������������ � pbData.
	dwFlags - �����.
	phKey � ��������� �� ���������� �����. ����� ��������� �� ��������������� ����
	*/
	int i = 255;
	for (; i >= 0 && g_ctxs[idx].buf_recv[i] == 0;)	i--;
	unsigned int len = (unsigned char)g_ctxs[idx].buf_recv[i];
	g_ctxs[idx].buf_recv[i] = 0;
	if (!CryptImportKey(g_ctxs[idx].DescCSP, (BYTE*)g_ctxs[idx].buf_recv, len, 0, 0, &g_ctxs[idx].DescKey_open))//�������� �������� ����
		printf("ERROR!!!, %x", GetLastError());

	//CryptExportKey - ������� �������� ����� ��� ��� �������� �� ������� ����������.\
	�������� ��������� �������� �������� �����, ������� �������� ���������� �����,\
	���� ������, � ����� �������� ���������� ��� ���������� �����.
	//������ ������� ��������� ���� ��������� ������ ������� � ����������
	//������������ ������������� ��������� �������
	/*
	hKey � ���������� ��������������� �����.
	hExpKey � ����, � ������� �������� ����� ���������� hKey ��� ��������.
	dwBlobType � ��� ��������.
	dwFlags � �����.
	pbData � ����� ��� ��������. ����� ��������� ������������� hKey � �������
	hExpKey.
	pdwDataLen � ����� ������ �� ����. �� ������ � ���������� �������� ����
	*/
	DWORD lenExp = 256;
	if (!CryptExportKey(g_ctxs[idx].DescKey, g_ctxs[idx].DescKey_open, SIMPLEBLOB, NULL, (BYTE*)g_ctxs[idx].buf_send, &lenExp))//������� ��������� ���� ��������
		printf("ERROR!!!!, %x", GetLastError());
	g_ctxs[idx].buf_send[lenExp] = lenExp;
	g_ctxs[idx].sz_send_total = lenExp + 1;
}

// ������� �������� �������� ������ �� ������
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	// WSARecv - ������� ��� ������ ������
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// ������� �������� �������� �������� �������������� ������ � �����
void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	// WSASend - ������� ��� �������� ������
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// ������� ��������� ����� �������� ����������� �������
void add_accepted_connection()
{
	DWORD i;
	// ����� ����� � ������� g_ctxs ��� ������� ������ �����������
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, * remote_addr = 0;
			int local_addr_sz, remote_addr_sz;

			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
				sizeof(struct sockaddr_in) + 16, (struct sockaddr**)&local_addr, &local_addr_sz, (struct sockaddr**)&remote_addr,
				&remote_addr_sz);

			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);

			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);

			g_ctxs[i].socket = g_accepted_socket;

			// ����� ������ � ������ IOCP, � �������� key ������������ ������ �������
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0)) // CreateIoCompletionPort - ����� ������ � ������
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			
			// �������� ������ �� ������
			schedule_read(i);
			return;
		}
	}
	// ����� �� ������� => ��� �������� ��� �������� ����������
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

// ������� �������� �������� ������ ����������
void schedule_accept()
{
	// �������� ������ ��� �������� ����������� (AcceptEx �� ������� �������) 
	// WSASocket - ������� ��� �������� ������
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// �������� �����������.
	// ��� ������ �������� ����� ��������� - ���� ���������� ������� �����������.
	// ������� ������� ������ ���� �� 16 ���� ������ ������� ������ �������� ������������ ������������ ��
	// AcceptEx - ������� ��� �������� �����������
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{
		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	return 0;
}

std::wstring GetOSInfo() {
	std::wstring osInfo;

	HKEY hKey;
	TCHAR szProductType[1024];
	DWORD dwBufLen = sizeof(szProductType) / sizeof(szProductType[0]);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
		TCHAR szProduct[1024];
		dwBufLen = sizeof(szProduct);
		if (RegQueryValueEx(hKey, _T("ProductName"), NULL, NULL, (LPBYTE)szProduct, &dwBufLen) == ERROR_SUCCESS) {
			osInfo += L"Product Name: " + std::wstring(szProduct) + L"\n";
		}

		TCHAR szCurrentVersion[1024];
		dwBufLen = sizeof(szCurrentVersion);
		if (RegQueryValueEx(hKey, _T("CurrentVersion"), NULL, NULL, (LPBYTE)szCurrentVersion, &dwBufLen) == ERROR_SUCCESS) {
			osInfo += L"Current Version: " + std::wstring(szCurrentVersion) + L"\n";
		}

		if (RegQueryValueEx(hKey, _T("ProductType"), NULL, NULL, (LPBYTE)szProductType, &dwBufLen) == ERROR_SUCCESS) {
			if (lstrcmp(szProductType, _T("1")) == 0) {
				osInfo += L"Product Type: Desktop\n";
			}
			else if (lstrcmp(szProductType, _T("2")) == 0) {
				osInfo += L"Product Type: Server\n";
			}
			else if (lstrcmp(szProductType, _T("3")) == 0) {
				osInfo += L"Product Type: Domain Controller\n";
			}
		}

		RegCloseKey(hKey);
	}

	return osInfo;
}

// ��� handle_client_request() ���������, ��� �������� ����� ��� �������
bool CheckFileOrReg(std::string after_plus)
{
	size_t found = after_plus.find("HKEY");

	// ��������, ���������� �� "HKEY" � ������
	if (found != std::string::npos)
	{
		return false;
	}
	else
	{
		return true;
	}
}

void DisplayAccessRights(ACCESS_ALLOWED_ACE* pACE, SE_OBJECT_TYPE objectType, std::string & response)
{
	std::ostringstream responseStream;

	PSID pSID = (PSID)(&(pACE->SidStart));
	TCHAR accountName[256];
	DWORD accountNameSize = sizeof(accountName) / sizeof(accountName[0]);
	TCHAR domainName[256];
	DWORD domainNameSize = sizeof(domainName) / sizeof(domainName[0]);
	SID_NAME_USE sidNameUse;

	if (LookupAccountSid(NULL, pSID, accountName, &accountNameSize, domainName, &domainNameSize, &sidNameUse))
	{
		responseStream << "SID: " << pSID << "\n";
		responseStream << "Account Name: " << accountName << "\n";
		responseStream << "SID Name Use: " << sidNameUse << "\n";

		// ����������� ���� �������
		const char* objectTypeStr = (objectType == SE_FILE_OBJECT) ? "����/�����" : "���� �������";
		responseStream << "��� �������: " << objectTypeStr << "\n";

		// ����� ������������
		responseStream << "����� ������������: " << domainName << "\n";

		// ����������� ���� ACE
		const char* aceTypeStr = (pACE->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) ? "���������" : "���������";
		responseStream << "��� ACE: " << aceTypeStr << "\n";

		// ����������� ������� ��������
		const char* aceFlagsStr = (pACE->Header.AceFlags == OBJECT_INHERIT_ACE) ? "������" : "�������";
		responseStream << "������� ��������: " << aceFlagsStr << "\n";

		responseStream << "����� �������: " << pACE->Mask << "\n";

		// ����� �������� ������������� ����� ����� �������
		responseStream << "�������� ����� ����� �������: ";
		if (pACE->Mask & GENERIC_READ)           responseStream << "GENERIC_READ ";
		if (pACE->Mask & GENERIC_WRITE)          responseStream << "GENERIC_WRITE ";
		if (pACE->Mask & GENERIC_EXECUTE)        responseStream << "GENERIC_EXECUTE ";
		if (pACE->Mask & GENERIC_ALL)            responseStream << "GENERIC_ALL ";
		if (pACE->Mask & FILE_READ_DATA)         responseStream << "FILE_READ_DATA ";
		if (pACE->Mask & FILE_WRITE_DATA)        responseStream << "FILE_WRITE_DATA ";
		if (pACE->Mask & FILE_APPEND_DATA)       responseStream << "FILE_APPEND_DATA ";
		if (pACE->Mask & FILE_READ_ATTRIBUTES)   responseStream << "FILE_READ_ATTRIBUTES ";
		if (pACE->Mask & FILE_WRITE_ATTRIBUTES)  responseStream << "FILE_WRITE_ATTRIBUTES ";
		if (pACE->Mask & DELETE)                 responseStream << "DELETE ";
		if (pACE->Mask & READ_CONTROL)           responseStream << "READ_CONTROL ";
		if (pACE->Mask & WRITE_DAC)              responseStream << "WRITE_DAC ";
		if (pACE->Mask & WRITE_OWNER)            responseStream << "WRITE_OWNER ";
		if (pACE->Mask & SYNCHRONIZE)            responseStream << "SYNCHRONIZE ";
		if (pACE->Mask & STANDARD_RIGHTS_READ)   responseStream << "STANDARD_RIGHTS_READ ";
		if (pACE->Mask & STANDARD_RIGHTS_WRITE)  responseStream << "STANDARD_RIGHTS_WRITE ";
		if (pACE->Mask & STANDARD_RIGHTS_EXECUTE) responseStream << "STANDARD_RIGHTS_EXECUTE ";

		responseStream << "\n\n";

		response += responseStream.str();
	}
}

void DisplaySecurityInfo(const wchar_t* path, SE_OBJECT_TYPE objectType, std::string & response)
{
	PACL pDACL = nullptr;
	PSECURITY_DESCRIPTOR pSD = nullptr;

	if (GetNamedSecurityInfo(path, objectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pDACL, nullptr, &pSD) == ERROR_SUCCESS)
	{
		ACL_SIZE_INFORMATION aclSizeInfo;
		if (GetAclInformation(pDACL, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation))
		{
			for (DWORD i = 0; i < aclSizeInfo.AceCount; ++i)
			{
				LPVOID pAce;
				if (GetAce(pDACL, i, &pAce))
				{
					DisplayAccessRights(reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAce), objectType, response);
				}
			}
		}

		LocalFree(pSD);
	}
}

void GetFileOwner(const wchar_t* file, SE_OBJECT_TYPE objectType, std::string& response)
{
	std::ostringstream responseStream;

	PSID pOwnerSid = nullptr;
	PSECURITY_DESCRIPTOR pSD = nullptr;

	if (GetNamedSecurityInfo(file, objectType, OWNER_SECURITY_INFORMATION, &pOwnerSid, nullptr, nullptr, nullptr, &pSD) == ERROR_SUCCESS)
	{
		WCHAR userName[256];
		WCHAR domainName[256];
		DWORD userNameSize = sizeof(userName) / sizeof(userName[0]);
		DWORD domainNameSize = sizeof(domainName) / sizeof(domainName[0]);
		SID_NAME_USE sidNameUse;

		if (LookupAccountSid(nullptr, pOwnerSid, userName, &userNameSize, domainName, &domainNameSize, &sidNameUse))
		{
			// �������������� WCHAR � wstring
			std::wstring domainNameString(domainName), userNameString(userName);
			// �������������� wstring � string
			std::string domainString(domainNameString.begin(), domainNameString.end()), userString(userNameString.begin(), userNameString.end());
			response += domainString + userString;
		}
		else {
			responseStream << "Error looking up account: " << GetLastError() << "\n";
		}
	}
	else {
		responseStream << "Error getting security information: " << GetLastError() << "\n";
	}

	response += responseStream.str();

	LocalFree(pSD); // ���������� ������ ����� �������������
}

void handle_client_request(DWORD idx, std::string& request)
{
	std::string response = "";
	std::string after_plus = "";
	
	size_t plus_pos = request.find("+");
	bool flag = 1;

	// �������, ���� �� � ��� �������� ������/�����/�������, � ���� ��, �������� �� request 
	if (plus_pos != std::string::npos)
	{
		after_plus = request.substr(plus_pos + 1);

		// ��������� �������� ������, ������� ������ ����� �� ������� '+'
		request.erase(plus_pos);
	}
	else
	{
		after_plus = request;
		flag = 0;
	}
	std::string after_vosk = "";
	size_t vosk_pos = after_plus.find("!");
	if (vosk_pos != std::string::npos)
	{
		after_vosk = after_plus.substr(vosk_pos + 1);

		// ��������� �������� ������, ������� ������ ����� �� ������� '+'
		after_plus.erase(vosk_pos);
		if (flag == 0)
		{
			request.erase(vosk_pos);
		}
	}
	


	// ��������� �������
	if (request.find("i") != std::string::npos)
	{
		response += "OS type and version:\n";
		std::wstring osInfo = GetOSInfo();
		std::string osInfoStr(osInfo.begin(), osInfo.end());
		response += osInfoStr;
		response += "\n";
	}
	if (request.find("n") != std::string::npos)
	{
		response += "Current time:\n";
		std::time_t currentTime = std::time(0);
		std::string timeString = std::ctime(&currentTime);
		response += timeString;
		response += "\n";
	}
	if (request.find("w") != std::string::npos)
	{
		response += "Working time of OS:\n";

		DWORD uptime = GetTickCount();

		unsigned int seconds = uptime / 1000;
		unsigned int minutes = seconds / 60;
		unsigned int hours = minutes / 60;
		seconds %= 60;
		minutes %= 60;

		response += std::to_string(hours) + " hours, " + std::to_string(minutes) + " minutes, " + std::to_string(seconds) + " seconds.";
		response += "\n";
	}
	if (request.find("m") != std::string::npos)
	{
		response += "Information about the used memory:\n";

		MEMORYSTATUS stat;
		GlobalMemoryStatus(&stat);

		response +=std::to_string(stat.dwLength)        + " - the length of the structure in bytes\n"
				 + std::to_string(stat.dwMemoryLoad)    + " - memory usage as a percentage\n"
			     + std::to_string(stat.dwTotalPhys)     + " - maximum amount of physical memory in bytes\n"
			     + std::to_string(stat.dwAvailPhys)     + " - free amount of physical memory in bytes\n"
			     + std::to_string(stat.dwTotalPageFile) + " - maximum amount of memory for programs in bytes\n"
		         + std::to_string(stat.dwAvailPageFile) + " - free amount of memory for programs in bytes\n"
			     + std::to_string(stat.dwTotalVirtual)  + " - maximum amount of virtual memory in bytes\n"
		         + std::to_string(stat.dwAvailVirtual)  + " - free amount of virtual memory in bytes";
		response += "\n";
	}
	if (request.find("d") != std::string::npos)
	{
		response += "Types of attached disks (local/network/removable, file system):\n";

		char disks[26][4] = { 0 };
		int count = 0;

		DWORD logicalDrives = GetLogicalDrives();

		for (int i = 0; i < 26; i++)
		{
			if ((logicalDrives >> i) & 0x00000001)
			{
				disks[count][0] = static_cast<char>('A' + i);
				disks[count][1] = ':';
				disks[count][2] = '\\';
				count++;
			}
		}

		for (int i = 0; i < count; i++)
		{
			DWORD driveType = GetDriveTypeA(disks[i]);

			if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE || driveType == DRIVE_REMOTE)
			{
				char volumeName[MAX_PATH + 1];
				char fileSystemName[MAX_PATH + 1];
				DWORD volumeSerialNumber;
				DWORD maximumComponentLength;
				DWORD fileSystemFlags;

				if (GetVolumeInformationA(disks[i], volumeName, MAX_PATH + 1, &volumeSerialNumber, &maximumComponentLength, &fileSystemFlags, fileSystemName, MAX_PATH + 1))
				{
					std::string d = disks[i];
					response += "Drive " + d + " - ";

					switch (driveType)
					{
					case DRIVE_FIXED:
						response += "local disk";
						break;
					case DRIVE_REMOTE:
						response += "network drive";
						break;
					case DRIVE_REMOVABLE:
						response += "removable drive";
						break;
					default:
						response += "unknown type";
						break;
					}

					std::string f = fileSystemName;
					response += ", file system: " + f + '\n';
				}
				else
				{
					std::cerr << "Failed to get volume information for drive " << disks[i] << std::endl;
				}
			}
		}

		response += "\n";

	}
	if (request.find("f") != std::string::npos)
	{
		response += "Free space on local disks:\n";

		char disks[26][4] = { 0 };
		int count = 0;

		DWORD logicalDrives = GetLogicalDrives();

		for (int i = 0; i < 26; i++)
		{
			if ((logicalDrives >> i) & 0x00000001)
			{
				disks[count][0] = static_cast<char>('A' + i);
				disks[count][1] = ':';
				disks[count][2] = '\\';
				count++;
			}
		}

		for (int i = 0; i < count; i++) {
			if (GetDriveTypeA(disks[i]) == DRIVE_FIXED)
			{
				DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
				if (GetDiskFreeSpaceA(disks[i], &sectorsPerCluster, &bytesPerSector, &numberOfFreeClusters, &totalNumberOfClusters))
				{
					double freeSpace = static_cast<double>(sectorsPerCluster) * bytesPerSector * numberOfFreeClusters / 1024.0 / 1024.0 / 1024.0;

					std::cout << "Drive " << disks[i] << " has " << freeSpace << " GB of free space." << std::endl;
					std::string d = disks[i];
					response += "Drive " + d + " has " + std::to_string(freeSpace) + " GB of free space.\n";
				}
				else
				{
					std::cerr << "Failed to get disk free space for drive " << disks[i] << std::endl;
				}
			}
		}
	}
	if (request.find("a") != std::string::npos)
	{
		response += "Text access rights to " + after_plus + ":\n";

		// ������� ������ std::wstring_convert
		std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
		// ��������������� � ������� ������ (wstring)
		std::wstring filePath = converter.from_bytes(after_plus);
		// �������� ��������� �� const wchar_t*
		const wchar_t* file = filePath.c_str();

		if (CheckFileOrReg(after_plus))
		{
			DisplaySecurityInfo(file, SE_FILE_OBJECT, response);
		}
		else
		{
			DisplaySecurityInfo(file, SE_REGISTRY_KEY, response);
		}

		response += "\n";
	}
	if (request.find("o") != std::string::npos)
	{
		response += "Owner of " + after_vosk + ":\n";

		// ������� ������ std::wstring_convert
		std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
		// ��������������� � ������� ������ (wstring)
		std::wstring filePath = converter.from_bytes(after_vosk);
		// �������� ��������� �� const wchar_t*
		const wchar_t* file = filePath.c_str();

		if (CheckFileOrReg(after_vosk))
		{
			GetFileOwner(file, SE_FILE_OBJECT, response);
		}
		else
		{
			GetFileOwner(file, SE_REGISTRY_KEY, response);
		}

		response += "\n";
	}

	// ����������� ������ � ����� ��� �������� �������
	strcpy(g_ctxs[idx].buf_send, response.c_str());
	g_ctxs[idx].sz_send_total = response.size();
	g_ctxs[idx].sz_send = 0;

	// ������ �������� ������ �������
	schedule_write(idx);
}

//void handle_client_request(DWORD idx, std::string& request)
//{
//	std::string response = "";
//	// ��������� �������
//	if (request.find("i") != std::string::npos)
//	{
//		response += "OS type and version:\n";
//		std::wstring osInfo = GetOSInfo();
//		std::string osInfoStr(osInfo.begin(), osInfo.end());
//		response += osInfoStr;
//		response += "\n";
//	}
//
//	// ����������� ������ � ����� ��� �������� �������
//	strcpy(g_ctxs[idx].buf_send, response.c_str());
//	g_ctxs[idx].sz_send_total = response.size();
//	g_ctxs[idx].sz_send = 0;
//
//	// ��������� ��������� ����� �� �������
//	DWORD dwBlobLen = KEY_BUF_SIZE;
//	std::vector<BYTE> pbBlob(KEY_BUF_SIZE);
//	if (recv(g_ctxs[idx].socket, reinterpret_cast<char*>(pbBlob.data()), KEY_BUF_SIZE, 0) == SOCKET_ERROR)
//	{
//		std::cerr << "Failed to receive public key from client. Error code: " << GetLastError() << std::endl;
//		closesocket(g_ctxs[idx].socket);
//		return;
//	}
//
//	HCRYPTKEY hPublicKey;
//	if (!CryptImportKey(g_ctxs[idx].DescCSP, pbBlob.data(), dwBlobLen, 0, CRYPT_OAEP, &hPublicKey))
//	{
//		std::cerr << "Error importing public key. Error code: " << GetLastError() << std::endl;
//		closesocket(g_ctxs[idx].socket);
//		return;
//	}
//
//	// ���������� ������ � �������������� ��������� ����� �������
//	DWORD dwBlockSize = KEY_BUF_SIZE;
//	if (!CryptEncrypt(hPublicKey, 0, TRUE, 0, reinterpret_cast<BYTE*>(g_ctxs[idx].buf_send), reinterpret_cast<DWORD*>(&g_ctxs[idx].sz_send_total), g_ctxs[idx].sz_send_total))
//
//	{
//		std::cerr << "Error encrypting response. Error code: " << GetLastError() << std::endl;
//		closesocket(g_ctxs[idx].socket);
//		return;
//	}
//
//	// ������ �������� ������ �������
//	schedule_write(idx);
//}

//void handle_client_request(DWORD idx, std::string& request)
//{
//	std::cout << "-----------------------------1" << std::endl;
//	
//	std::cout << "-----------------------------2" << std::endl;
//	std::string response = "";
//	// ��������� �������
//	if (request.find("i") != std::string::npos)
//	{
//		response += "OS type and version:\n";
//		std::wstring osInfo = GetOSInfo();
//		std::string osInfoStr(osInfo.begin(), osInfo.end());
//		response += osInfoStr;
//		response += "\n";
//	}
//
//	// ����������� ������ � ����� ��� �������� �������
//	strcpy(g_ctxs[idx].buf_send, response.c_str());
//	g_ctxs[idx].sz_send_total = response.size();
//	g_ctxs[idx].sz_send = 0;
//
//	DWORD count = 0;
//	count = strlen(g_ctxs[idx].buf_send);
//	if (!CryptEncrypt(g_ctxs[idx].DescKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[idx].buf_send, (DWORD*)&count, 512))
//		printf("ERROR!!!!!, %x", GetLastError());
//	g_ctxs[idx].sz_send_total = count;
//
//	schedule_write(idx);
//}

void io_serv()
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}
	struct sockaddr_in addr;
	// �������� ������ �������������
	// WSASocket - ������� ��� �������� ������
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// �������� ����� ����������
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	// ��������� ��������� ������ ��� �������� �������� ����������
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_port = htons(9000);
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0) { printf("error bind() or listen()\n"); return; }
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// ������������� ������������� ������ s � ����� io_port. 
	// � �������� ����� ��� ��������������� ������ ������������ 0 
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;
	// ����� �������� �������� �����������.
	schedule_accept();
	// ����������� ���� �������� ������� � ����������� ���������
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		// �������� ������� � ������� 1 �������
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// ��������� ����������� � ���������� ��������
			if (key == 0) // ���� 0 - ��� ��������������� ������
			{
				g_ctxs[0].sz_recv += transferred;
				// �������� ����������� � ������ �������� ����������
				add_accepted_connection();
				//crypt_keys(key);
				schedule_accept();

			}
			else
			{
				// ����� ��������� ������� �� ���������� �������� �� �������. // ���� key - ������ � ������� g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// ������ �������:
					if (transferred == 0)
					{
						// ���������� ���������
						CancelIo((HANDLE)g_ctxs[key].socket); //����� ������� �������� ������������� ��������, �� �� ������� ����������� �� ��� ����������� ��������� �� �����.
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel); // ���������� ������� � ���� ����������
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					// �������� ������� �� �������
					std::string request(g_ctxs[key].buf_recv, g_ctxs[key].sz_recv);
					handle_client_request(key, request);
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// ������ ����������
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// ���� ������ ���������� �� ��������� - ���������� ����������
						schedule_write(key);
					}
					else
					{
						// ������ ���������� ���������, �������� ��� ������������, 
						// �������� � ���� ������� �� ���������� ������
						CancelIo((HANDLE)g_ctxs[key].socket); //����� ������� �������� ������������� ��������, �� �� ������� ����������� �� ��� ����������� ��������� �� �����.
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel); // ���������� ������� � ���� ����������

					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// ��� ������������ ���������, ����� ����� ���� ������
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}
		else
		{
			// �� ����� �������� �� ���� ��������� � ������� ��������� �������, ��������� �����
			// ��������� �����-���� ������ ��������
			// ... 
		}
	}
}

int main()
{
	setlocale(LC_ALL, "Russian");
	io_serv();
	return 0;
}
