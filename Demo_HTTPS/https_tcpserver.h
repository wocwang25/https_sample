// https_tcpserver.h
#ifndef INCLUDED_HTTPS_TCPSERVER
#define INCLUDED_HTTPS_TCPSERVER

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <sstream>
#include <map>

const std::string m_encryptionKey = "my_secret_key_1234567890123456"; // 32 bytes for AES-256

#pragma comment(lib, "Ws2_32.lib") // Winsock Library for MSVC

namespace https
{
    class TcpServer
    {
    public:
        TcpServer(std::string ip_address, int port);
        ~TcpServer();
        void startListen();

    private:
        std::string m_ip_address;
        int m_port;
        SOCKET m_socket;
        SOCKET m_new_socket;
        struct sockaddr_in m_socketAddress;
        int m_socketAddress_len;
        std::string m_serverMessage;
        std::map<std::string, std::string> m_users; // Lưu trữ thông tin người dùng (username, password)

        WSADATA m_wsaData;
        SSL_CTX* m_sslCtx;
        SSL* m_ssl;

        int startServer();
        void closeServer();
        void acceptConnection(SOCKET& new_socket);
        void sendResponse();
        std::string buildResponse();

        // Các phương thức lưu trữ dữ liệu
        void saveUsersToFile(const std::string& filename);
        void loadUsersFromFile(const std::string& filename);

        // Các phương thức xử lý yêu cầu HTTP
        std::string handleRequest(const std::string& request);
        std::string getRequestPath(const std::string& request);
        std::string getRequestMethod(const std::string& request);
        std::map<std::string, std::string> parseFormData(const std::string& request);

        // Các phương thức xử lý đăng nhập và đăng ký
        std::string handleLogin(const std::map<std::string, std::string>& formData);
        std::string handleRegister(const std::map<std::string, std::string>& formData);

        // Các phương thức tạo trang HTML
        std::string buildHtmlResponse(const std::string& content, int statusCode = 200);
        std::string getLoginPage();
        std::string getRegisterPage();
        std::string getHomePage(const std::string& username);
    };
} // namespace https

#endif