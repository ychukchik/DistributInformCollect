#define WIN32_LEAN_AND_MEAN 
#include <windows.h> 
#include <winsock2.h> 
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib") 
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#include <conio.h>
#pragma warning(disable : 4996)

#include <iostream>
#include <string>
#include <vector>
//#include <map>

#define MAX_COMMAND_SIZE 500
#define MAX_BUFFER_SIZE 2048
#define KEY_BUF_SIZE 256
#define MIN_PATH_SIZE 5
#define KEY_BUF_SIZE 256

typedef struct sock
{
    int s;
    HCRYPTPROV DescCSP;
    HCRYPTKEY DescKey;
    HCRYPTKEY DescKey_imp;
    HCRYPTKEY hPublicKey, hPrivateKey;

}socketExtended;

std::vector<socketExtended> sockets;

void Start();
std::pair<std::string, std::string> Enter_IP_Port();
SOCKET CreateSocket();

int sock_err(const char* function, int s)
{
    int err;
    err = WSAGetLastError();
    fprintf(stderr, "%s: socket error: %d\n", function, err);
    return -1;
}

unsigned int strLength(char* mas, int startPos)
{
    int i = startPos;
    for (int j = startPos - 1; j >= 0; j--)
    {
        if (mas[j] != '\0') break;
        else i--;
    }

    return i;
}

int crytp_send(int choiceSize, char* buffer, unsigned int& bufSize, int s, char* choice)
{
    if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
        printf("ERROR!, %x", GetLastError());

    if (send(sockets[s].s, choice, choiceSize, 0) < 0)
        return sock_err("send", sockets[s].s);
    if (recv(sockets[s].s, buffer, MAX_BUFFER_SIZE, 0) < 0)
        return sock_err("receive", sockets[s].s);

    bufSize = strLength(buffer, MAX_BUFFER_SIZE);
    if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)buffer, (DWORD*)&bufSize))
        printf("ERROR!!, %x", GetLastError());
    return 1;
}

int CryptReal(int s, sockaddr_in addr)
{
    socketExtended result;
    // для создания контейнера ключей с определенным CSP
    /*phProv – указатель на дескриптор CSP.
      pszContainer – имя контейнера ключей.
      pszProvider – имя CSP.
      dwProvType – тип CSP.
      dwFlags – флаги.*/
      /*
      Создает новый контейнер ключей с именем, указанным в pszContainer .\
      Если pszContainer имеет значение NULL , создается контейнер ключей \
      с именем по умолчанию.
      */
    if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
    {
        if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
            printf("ERROR!!!, %x", GetLastError());
    }

    /*
    Данная функция предназначена для генерации сеансового ключа,
    а также для генерации пар ключей для обмена и цифровой подписи.
        hProv– дескриптор CSP.
        Algid – идентификатор алгоритма(указываем, что генерируем пару ключей, а не подпись).
        dwFlags – флаги.
        phKey – указатель на дескриптор ключа.*/
    if (CryptGenKey(result.DescCSP, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &result.DescKey) == 0)
        printf("ERROR!!!!, %i", GetLastError());

    //Функция CryptGetUserKey извлекает дескриптор одной из двух пар открытого и закрытого ключей пользователя
    if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPublicKey))
        printf("CryptGetUserKey err\n");
    if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPrivateKey))
        printf("CryptGetUserKey err\n");

    char ExpBuf[KEY_BUF_SIZE] = { 0 };
    DWORD len = KEY_BUF_SIZE;

    //Клиент посылает публичный ключ серверу
    //2й аргумент - 0, тк мы не шифруем посылаемый публичный ключ
    /*
    hKey – дескриптор экспортируемого ключа.
    hExpKey – ключ, с помощью которого будет зашифрован hKey при экспорте.
    dwBlobType – тип экспорта.
    dwFlags – флаги.
    pbData – буфер для экспорта. Будет содержать зашифрованный hKey с помощью
    hExpKey.
    pdwDataLen – длина буфера на вход. На выходе – количество значащих байт
    */
    if (!CryptExportKey(result.hPublicKey, 0, PUBLICKEYBLOB, NULL, (BYTE*)ExpBuf, &len))
        printf("ERROR!!!!!, %x", GetLastError());

    //передаём длину ключа
    int expBufSize = strLength(ExpBuf, KEY_BUF_SIZE);
    ExpBuf[expBufSize] = expBufSize;

    //отправка - получение информации
    if (send(s, ExpBuf, (expBufSize + 1), 0) < 0)
        sock_err("send", s);
    char buffer[KEY_BUF_SIZE] = { 0 };
    if (recv(s, buffer, KEY_BUF_SIZE, 0) < 0)
        sock_err("receive", s);

    int bufSize = strLength(buffer, KEY_BUF_SIZE) - 1;
    unsigned int dli = (unsigned char)buffer[bufSize];
    buffer[bufSize] = 0;

    //Клиент получает зашифрованное сообщение и расшифровывает его с помощью
    //своего приватного ключа
    //Функция предназначена для получения из каналов информации значения\
	ключа
    /*
    hProv – дескриптор CSP.
    pbData – импортируемый ключ представленный в виде массива байт.
    dwDataLen –длина данных в pbData.
    hPubKey - дескриптор ключа, который расшифрует ключ содержащийся в pbData.
    dwFlags - флаги.
    phKey – указатель на дескриптор ключа. Будет указывать на импортированный ключ
    */
    if (!CryptImportKey(result.DescCSP, (BYTE*)buffer, dli, result.hPrivateKey, 0, &result.DescKey_imp))//получаем сеансовый ключ
        printf("ERROR!!!!!!, %x", GetLastError());
    result.s = s;
    sockets.push_back(result);
    return s;
}

int crypt_send(int choiceSize, char* buffer, unsigned int& bufSize, int s, char* choice)
{
    if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
        printf("ERROR, %x", GetLastError());

    if (send(sockets[s].s, choice, choiceSize, 0) < 0)
        return sock_err("send", sockets[s].s);
    if (recv(sockets[s].s, buffer, MAX_BUFFER_SIZE, 0) < 0)
        return sock_err("receive", sockets[s].s);

    bufSize = strLength(buffer, MAX_BUFFER_SIZE);
    if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)buffer, (DWORD*)&bufSize))
        printf("ERROR, %x", GetLastError());
    return 1;
}

//void GenerateKeyPair(HCRYPTPROV hCryptProv, HCRYPTKEY& hPublicKey, HCRYPTKEY& hPrivateKey)
//{
//    // Генерация асимметричной ключ-пары
//    if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hPublicKey))
//    {
//        std::cerr << "Error generating public keyError code: " << GetLastError() << std::endl;
//    }
//
//    // Получение приватного ключа
//    DWORD dwPrivateKeyLen;
//    if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hPrivateKey))
//    {
//        std::cerr << "Error getting private keyError code: " << GetLastError() << std::endl;
//        exit(-1);
//    }
//}
//
//void SendPublicKey(SOCKET clientSocket, HCRYPTKEY hPublicKey)
//{
//    // Получение размера открытого ключа
//    DWORD dwBlobLen = KEY_BUF_SIZE;
//    if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen))
//    {
//        std::cerr << "Error exporting public keyError code: " << GetLastError() << std::endl;
//        exit(-1);
//    }
//
//    // Экспорт открытого ключа
//    std::vector<BYTE> pbBlob(dwBlobLen);
//    if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, &pbBlob[0], &dwBlobLen))
//    {
//        std::cerr << "Error exporting public keyError code: " << GetLastError() << std::endl;
//        exit(-1);
//    }
//
//    // Шифрование открытого ключа с использованием CRYPT_OAEP
//    DWORD dwBlockSize = KEY_BUF_SIZE;
//    if (!CryptEncrypt(hPublicKey, 0, TRUE, CRYPT_OAEP, reinterpret_cast<BYTE*>(&pbBlob[0]), &dwBlobLen, dwBlobLen))
//    {
//        std::cerr << "Error encrypting public key. Error code: " << GetLastError() << std::endl;
//        closesocket(clientSocket);
//        WSACleanup();
//        exit(-1);
//    }
//
//    // Отправка открытого ключа на сервер
//    if (send(clientSocket, reinterpret_cast<const char*>(pbBlob.data()), dwBlobLen, 0) == SOCKET_ERROR)
//    {
//        std::cerr << "Failed to send public key to serverError code: " << GetLastError() << std::endl;
//        closesocket(clientSocket);
//        WSACleanup();
//        exit(-1);
//    }
//}

void Start()
{
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
    {
        std::cout << "WSAStartup ok" << std::endl;
    }
    else
    {
        std::cerr << "WSAStartup failed" << std::endl;
    }
}

std::pair<std::string, std::string> Enter_IP_Port()
{
    std::string ip_port;
    std::cout << "Enter IP and port like ""192.168.1.10:9000"" ";
    std::cin >> ip_port;

    std::string ip;
    std::string port;
    ip = ip_port.substr(0, ip_port.find(":"));
    port = ip_port.substr(ip_port.find(":") + 1);

    if (ip.empty() || port.empty())
    {
        std::cerr << "IP or port are incorrect!" << std::endl;
    }

    std::pair<std::string, std::string> ip_port_return;
    ip_port_return.first = ip;
    ip_port_return.second = port;

    return ip_port_return;
}

SOCKET CreateSocket()
{
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
    }
    return clientSocket;
}

#include <limits>

bool WhatRequest(SOCKET clientSocket, std::string &request)
{
    std::cout << "Your requests: ";

    std::cin.get();

    std::getline(std::cin, request);
        
    if (request == "h")
    {
        std::cout << "h - output reference information" << std::endl;
        std::cout << "i - OS type and version" << std::endl;
        std::cout << "n - current time" << std::endl;
        std::cout << "w - working time of OS" << std::endl;
        std::cout << "m - information about the memory used" << std::endl;
        std::cout << "d - types of attached disks (local/network/removable, file system)" << std::endl;
        std::cout << "f - free space on local disks" << std::endl;
        std::cout << "a - text access rights to the specified file/folder/registry key" << std::endl;
        std::cout << "o - owner of the file/folder/registry key" << std::endl;
        std::cout << "q - quit" << std::endl;
    }
    else if (request == "q")
    {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }
    std::string tmp = request;
    if (tmp.find("a") != std::string::npos)
    {
        std::cout << "Enter file/folder/registry key to get infomation about text access: ";
        std::string extra_request;
        std::getline(std::cin, extra_request);
        request += "+" + extra_request;
    }
    if (tmp.find("o") != std::string::npos)
    {
        std::cout << "Enter file/folder/registry key to get infomation about owner: ";
        std::string extra_request;
        std::getline(std::cin, extra_request);
        request += "!" + extra_request;
    }
    
    return true;
}

std::string ReceiveResponse(SOCKET clientSocket)
{
    const int bufferSize = 512; // Размер буфера для приема данных от сервера
    char buffer[bufferSize];
    std::string response;

    // Принимаем данные от сервера
    int bytesRead;
    do
    {
        bytesRead = recv(clientSocket, buffer, bufferSize - 1, 0);
        if (bytesRead > 0)
        {
            buffer[bytesRead] = '\0'; // Добавляем завершающий нулевой символ
            response += buffer;
        }
    } while (bytesRead > 0);

    if (bytesRead == SOCKET_ERROR)
    {
        std::cerr << "Failed to receive response from server" << std::endl;
    }

    return response;
}

void SendRequest(SOCKET clientSocket, const std::string& request)
{
    if (send(clientSocket, request.c_str(), request.size(), 0) == SOCKET_ERROR)
    {
        std::cerr << "Failed to send request to server" << std::endl;
        closesocket(clientSocket);
    }

    std::string response = ReceiveResponse(clientSocket);
    std::cout << "\n>>Received response from server<<\n\n" << response;

    std::cout << "\n>><<\n" << std::endl;
}

//std::string ReceiveResponse(SOCKET clientSocket)
//{
//    const int bufferSize = 512; // Размер буфера для приема данных от сервера
//    char buffer[bufferSize];
//    std::string response;
//
//    // Принимаем данные от сервера
//    int bytesRead;
//    do
//    {
//        bytesRead = recv(clientSocket, buffer, bufferSize - 1, 0);
//        if (bytesRead > 0)
//        {
//            buffer[bytesRead] = '\0'; // Добавляем завершающий нулевой символ
//            response += buffer;
//        }
//    } while (bytesRead > 0);
//
//    if (bytesRead == SOCKET_ERROR)
//    {
//        std::cerr << "Failed to receive response from server" << std::endl;
//    }
//
//    if (!CryptDecrypt(sockets[0].DescKey_imp, NULL, TRUE, NULL, (BYTE*)(response.c_str()), (DWORD*)(response.size())))
//        printf("ERROR7, %x", GetLastError());
//
//    return response;
//}
//
//void SendRequest(SOCKET clientSocket, const std::string& request)
//{
//    if (!CryptEncrypt(sockets[0].DescKey_imp, 0, TRUE, 0, (BYTE*)(request.c_str()), (DWORD*)(request.size()), MAX_COMMAND_SIZE))
//        printf("ERROR8, %x", GetLastError());
//
//    if (send(clientSocket, request.c_str(), request.size(), 0) == SOCKET_ERROR)
//    {
//        std::cerr << "Failed to send request to server" << std::endl;
//        closesocket(clientSocket);
//    }
//
//    std::string response = ReceiveResponse(clientSocket);
//    std::cout << "\n>>Received response from server<<\n\n" << response;
//
//    std::cout << "\n>><<\n" << std::endl;
//}


int ProcessNewSocket()
{
    Start();

    std::pair<std::string, std::string> ip_port;
    ip_port = Enter_IP_Port();

    SOCKET clientSocket;
    clientSocket = CreateSocket();

    struct sockaddr_in serverAddr;
    short num_port = (short)atoi(ip_port.second.c_str());

    // Заполнение структуры с адресом удаленного узла 
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(num_port);
    serverAddr.sin_addr.s_addr = inet_addr(ip_port.first.c_str());

    // Подключаемся к серверу
    size_t i;
    for (i = 0; i <= 10; ++i)
    {
        if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
        {
            Sleep(100);
            if (i == 10)
            {
                std::cerr << "Failed to connect to server" << std::endl;
                closesocket(clientSocket);
                WSACleanup();
                exit(-1);
            }
        }
        else
        {
            break;
        }
    }
    if (i < 10) std::cout << "Success connection" << std::endl << std::endl;

    // Запрашиваем всё, что нам надо, пока не выйдем
    bool finish_flag = true;
    std::string request;
    WhatRequest(clientSocket, request);
    SendRequest(clientSocket, request);    

    closesocket(clientSocket);
    WSACleanup();

    return 0;
}

//int ProcessNewSocket()
//{
//    Start();
//
//    std::pair<std::string, std::string> ip_port;
//    ip_port = Enter_IP_Port();
//
//    SOCKET clientSocket;
//    clientSocket = CreateSocket();
//
//    struct sockaddr_in serverAddr;
//    short num_port = (short)atoi(ip_port.second.c_str());
//
//    // Заполнение структуры с адресом удаленного узла 
//    memset(&serverAddr, 0, sizeof(serverAddr));
//    serverAddr.sin_family = AF_INET;
//    serverAddr.sin_port = htons(num_port);
//    serverAddr.sin_addr.s_addr = inet_addr(ip_port.first.c_str());
//
//    // Подключаемся к серверу
//    size_t i;
//    for (i = 0; i <= 10; ++i)
//    {
//        if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
//        {
//            Sleep(100);
//            if (i == 10)
//            {
//                std::cerr << "Failed to connect to server" << std::endl;
//                closesocket(clientSocket);
//                WSACleanup();
//                exit(-1);
//            }
//        }
//        else
//        {
//            break;
//        }
//    }
//    if (i < 10) std::cout << "Success connection" << std::endl << std::endl;
//
//    // Запрашиваем всё, что нам надо, пока не выйдем
//    bool finish_flag = true;
//    std::string request;
//    WhatRequest(clientSocket, request);
//
//    // Генерация асимметричной ключ-пары и отправка публичного ключа
//    HCRYPTPROV hCryptProv;
//    HCRYPTKEY hPublicKey, hPrivateKey;
//
//    // Получение контекста криптопровайдера
//    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
//    {
//        std::cerr << "Error acquiring cryptographic context" << std::endl;
//        closesocket(clientSocket);
//        WSACleanup();
//        exit(-1);
//    }
//
//    // Генерация асимметричной ключ-пары
//    GenerateKeyPair(hCryptProv, hPublicKey, hPrivateKey);
//
//    // Отправка публичного ключа серверу
//    SendPublicKey(clientSocket, hPublicKey);
//
//    // Отправка запроса на сервер
//    SendRequest(clientSocket, request);
//
//    // Закрытие сокета и завершение работы
//    closesocket(clientSocket);
//    WSACleanup();
//
//    return 0;
//}

//int ProcessNewSocket()
//{
//    Start();
//
//    std::pair<std::string, std::string> ip_port;
//    ip_port = Enter_IP_Port();
//
//    SOCKET clientSocket;
//    clientSocket = CreateSocket();
//
//    struct sockaddr_in serverAddr;
//    short num_port = (short)atoi(ip_port.second.c_str());
//
//    // Заполнение структуры с адресом удаленного узла 
//    memset(&serverAddr, 0, sizeof(serverAddr));
//    serverAddr.sin_family = AF_INET;
//    serverAddr.sin_port = htons(num_port);
//    serverAddr.sin_addr.s_addr = inet_addr(ip_port.first.c_str());
//
//    // Подключаемся к серверу
//    size_t i;
//    for (i = 0; i <= 10; ++i)
//    {
//        if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
//        {
//            Sleep(100);
//            if (i == 10)
//            {
//                std::cerr << "Failed to connect to server" << std::endl;
//                closesocket(clientSocket);
//                WSACleanup();
//                exit(-1);
//            }
//        }
//        else
//        {
//            break;
//        }
//    }
//    if (i < 10) std::cout << "Success connection" << std::endl << std::endl;
//
//    int s = clientSocket;
//    //crypt
//    s = CryptReal(s, serverAddr);
//
//    //Запрашиваем всё, что нам надо, пока не выйдем
//    bool finish_flag = true;
//    std::string request;
//    WhatRequest(clientSocket, request);
//
//    //crypt_send()
//
//    SendRequest(s, request);    
//
//    closesocket(clientSocket);
//    WSACleanup();
//
//    return 0;
//}


int main()
{
    setlocale(LC_ALL, "Russian");
    while (1)
    {
        ProcessNewSocket();
    }
    return 0;
}
