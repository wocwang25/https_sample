// https_tcpserver.cpp

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "https_tcpserver.h"


//Function to log messages and exit the program
namespace
{
    void log(const std::string& message)
    {
        std::cout << message << std::endl;
    }

    void exitWithError(const std::string& errorMessage)
    {
        std::cout << WSAGetLastError() << std::endl;
        log("ERROR: " + errorMessage);
        exit(1);
    }
}


//Function definitions for the TcpServer class  
namespace https
{
    // Constructor to initialize the server
    TcpServer::TcpServer(std::string ip_address, int port) : m_ip_address(ip_address), m_port(port), m_socket(), m_new_socket(),
        m_socketAddress(), m_socketAddress_len(sizeof(m_socketAddress)), m_sslCtx(nullptr),
        m_ssl(nullptr), m_serverMessage(buildResponse()), m_wsaData()
    {
        m_socketAddress.sin_family = AF_INET;
        m_socketAddress.sin_port = htons(m_port);
        m_socketAddress.sin_addr.s_addr = inet_addr(m_ip_address.c_str());

        // Đọc thông tin người dùng từ file
        loadUsersFromFile("users.csv");

        // Thêm một tài khoản mẫu nếu không có tài khoản nào
        if (m_users.empty())
        {
            m_users["admin"] = "admin123";
        }

        if (startServer() != 0)
        {
            log("Failed to start server");
        }
    }

    // Destructor to close the server
    TcpServer::~TcpServer()
    {
        closeServer();
    }

    // Function to start the server
    int TcpServer::startServer()
    {
        if (WSAStartup(MAKEWORD(2, 0), &m_wsaData) != 0)
        {
            exitWithError("WSAStartup failed");
        }

        m_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket < 0)
        {
            exitWithError("Cannot create socket");
        }

        if (bind(m_socket, (sockaddr*)&m_socketAddress, m_socketAddress_len) < 0)
        {
            exitWithError("Cannot bind socket");
        }

        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        m_sslCtx = SSL_CTX_new(TLS_server_method());
        if (!m_sslCtx)
        {
            exitWithError("Failed to create SSL context");
        }

        if (SSL_CTX_use_certificate_file(m_sslCtx, "C:/OpenSSL-Win64/tests/certs/servercert.pem", SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(m_sslCtx, "C:/OpenSSL-Win64/tests/certs/serverkey.pem", SSL_FILETYPE_PEM) <= 0)
        {
            exitWithError("Failed to load certificate or key");
        }

        return 0;
    }

    // Function to start listening for incoming connections
    void TcpServer::startListen()
    {
        if (listen(m_socket, 20) < 0)
        {
            exitWithError("Socket listen failed");
        }

        while (true)
        {
            log("Waiting for a new connection...");
            acceptConnection(m_new_socket);

            char buffer[4096] = { 0 };
            int bytesReceived = SSL_read(m_ssl, buffer, sizeof(buffer));
            if (bytesReceived < 0)
            {
                log("Failed to receive data");
                SSL_shutdown(m_ssl);
                SSL_free(m_ssl);
                closesocket(m_new_socket);
                continue;
            }

            std::string request(buffer);
            log("Received request:");
            log(request);

            // Xử lý yêu cầu và tạo phản hồi
            std::string response = handleRequest(request);

            // Gửi phản hồi
            SSL_write(m_ssl, response.c_str(), response.size());

            log("------ Server Response sent to client ------\n\n");
            log(response);

            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
            closesocket(m_new_socket);
        }
    }

    // Function to accept incoming connections
    void TcpServer::acceptConnection(SOCKET& new_socket)
    {
        new_socket = accept(m_socket, (sockaddr*)&m_socketAddress, &m_socketAddress_len);
        if (new_socket < 0)
        {
            exitWithError("Failed to accept connection");
        }

        m_ssl = SSL_new(m_sslCtx);
        SSL_set_fd(m_ssl, new_socket);
        if (SSL_accept(m_ssl) <= 0)
        {
            //wait for a few seconds before closing the connection
            Sleep(10000);
            exitWithError("SSL handshake failed");
        }
    }

    // Function to build the response
    std::string TcpServer::buildResponse()
    {
        std::string htmlFile = "<!DOCTYPE html><html><body><h1>Secure Server</h1><p>Welcome to HTTPS Server!</p></body></html>";
        std::ostringstream ss;
        ss << "HTTPS/1.1 200 OK\nContent-Type: text/html\nContent-Length: " << htmlFile.size() << "\n\n" << htmlFile;
        return ss.str();
    }

    // Function to send the response
    void TcpServer::sendResponse()
    {
        std::string response = buildResponse();
        SSL_write(m_ssl, response.c_str(), response.size());
        int bytesSent;
        long totalBytesSent = 0;

        while (totalBytesSent < m_serverMessage.size())
        {
            bytesSent = send(m_new_socket, m_serverMessage.c_str(), m_serverMessage.size(), 0);
            if (bytesSent < 0)
            {
                break;
            }
            totalBytesSent += bytesSent;
        }

        if (totalBytesSent == m_serverMessage.size())
        {
            log("------ Server Response sent to client ------\n\n");
            log(m_serverMessage);
        }
        else
        {
            log("Error sending response to client.");
            log(std::to_string(WSAGetLastError()));
        }
    }

    // Function to close the server
    void TcpServer::closeServer()
    {
        SSL_CTX_free(m_sslCtx);
        closesocket(m_socket);
        WSACleanup();
    }
}
