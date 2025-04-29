#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "https_tcpserver.h"
#include <iostream>
#include <sstream>
#include <regex>
#include <map>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <vector>

// Helper: convert bytes to hex string
std::string toHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char byte : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return oss.str();
}

// Helper: convert hex string to bytes
std::vector<unsigned char> fromHex(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
        bytes.push_back((unsigned char)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    return bytes;
}

// AES encryption
std::string aesEncrypt(const std::string& plaintext, const std::string& key) {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)key.data(), iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    std::string ivHex = toHex(std::vector<unsigned char>(iv, iv + sizeof(iv)));
    std::string ctHex = toHex(ciphertext);

    return ivHex + ":" + ctHex;
}

// AES decryption
std::string aesDecrypt(const std::string& cipherHexWithIV, const std::string& key) {
    size_t sep = cipherHexWithIV.find(':');
    if (sep == std::string::npos) return "";

    std::vector<unsigned char> iv = fromHex(cipherHexWithIV.substr(0, sep));
    std::vector<unsigned char> ciphertext = fromHex(cipherHexWithIV.substr(sep + 1));

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, plaintext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}



namespace https
{
    // Phương thức để lưu thông tin người dùng vào file
    void TcpServer::saveUsersToFile(const std::string& filename)
    {
        std::ofstream file(filename, std::ios::out | std::ios::trunc);
        if (!file.is_open())
        {
            std::cerr << "Error: Could not open file for writing: " << filename << std::endl;
            return;
        }

        for (const auto& user : m_users)
        {
            std::string encryptedPass = aesEncrypt(user.second, m_encryptionKey);
            file << user.first << "," << encryptedPass << std::endl;
        }

        file.close();
    }


    // Phương thức để đọc thông tin người dùng từ file
    void TcpServer::loadUsersFromFile(const std::string& filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            std::cerr << "Warning: Could not open file for reading: " << filename << std::endl;
            return;
        }

        m_users.clear();
        std::string line;
        while (std::getline(file, line))
        {
            size_t commaPos = line.find(',');
            if (commaPos != std::string::npos)
            {
                std::string username = line.substr(0, commaPos);
                std::string encryptedPass = line.substr(commaPos + 1);
                std::string decryptedPass = aesDecrypt(encryptedPass, m_encryptionKey);

                m_users[username] = decryptedPass;
            }
        }

        file.close();
    }

    // Phân tích dữ liệu biểu mẫu từ yêu cầu POST
    std::map<std::string, std::string> TcpServer::parseFormData(const std::string& request)
    {
        std::map<std::string, std::string> formData;

        // Tìm phần thân của yêu cầu (sau dòng trống)
        size_t bodyPos = request.find("\r\n\r\n");
        if (bodyPos == std::string::npos)
            return formData;

        std::string body = request.substr(bodyPos + 4);

        // Phân tích các cặp key-value
        std::istringstream iss(body);
        std::string pair;

        while (std::getline(iss, pair, '&'))
        {
            size_t pos = pair.find('=');
            if (pos != std::string::npos)
            {
                std::string key = pair.substr(0, pos);
                std::string value = pair.substr(pos + 1);

                // Giải mã URL encoding (đơn giản)
                std::string decodedValue;
                for (size_t i = 0; i < value.length(); ++i)
                {
                    if (value[i] == '+')
                        decodedValue += ' ';
                    else if (value[i] == '%' && i + 2 < value.length())
                    {
                        int hex = std::stoi(value.substr(i + 1, 2), nullptr, 16);
                        decodedValue += static_cast<char>(hex);
                        i += 2;
                    }
                    else
                        decodedValue += value[i];
                }

                formData[key] = decodedValue;
            }
        }

        return formData;
    }

    std::string TcpServer::handleLogin(const std::map<std::string, std::string>& formData)
    {
        auto usernameIt = formData.find("username");
        auto passwordIt = formData.find("password");

        if (usernameIt != formData.end() && passwordIt != formData.end())
        {
            std::string username = usernameIt->second;
            std::string password = passwordIt->second;

            auto userIt = m_users.find(username);
            if (userIt != m_users.end() && userIt->second == password)
            {
                // Login successful
                return buildHtmlResponse(getHomePage(username));
            }
        }

        // Login failed
        return buildHtmlResponse(getLoginPage() + "<script>alert('Login failed. Please check your username and password.');</script>");
    }

    // Xử lý đăng ký
    std::string TcpServer::handleRegister(const std::map<std::string, std::string>& formData)
    {
        auto usernameIt = formData.find("username");
        auto passwordIt = formData.find("password");
        auto confirmPasswordIt = formData.find("confirm_password");

        if (usernameIt != formData.end() && passwordIt != formData.end() && confirmPasswordIt != formData.end())
        {
            std::string username = usernameIt->second;
            std::string password = passwordIt->second;
            std::string confirmPassword = confirmPasswordIt->second;

            if (password != confirmPassword)
            {
                return buildHtmlResponse(getRegisterPage() + "<script>alert('Password confirmation does not match!');</script>");
            }

            if (m_users.find(username) != m_users.end())
            {
                return buildHtmlResponse(getRegisterPage() + "<script>alert('Username already exists!');</script>");
            }

            // Registration successful
            m_users[username] = password;

            // Lưu thông tin người dùng vào file
            saveUsersToFile("users.csv");

            return buildHtmlResponse(getLoginPage() + "<script>alert('Registration successful! Please login.');</script>");
        }

        // Registration failed
        return buildHtmlResponse(getRegisterPage() + "<script>alert('Registration failed. Please fill in all required information.');</script>");
    }
    // Lấy phương thức HTTP từ yêu cầu
    std::string TcpServer::getRequestMethod(const std::string& request)
    {
        std::istringstream iss(request);
        std::string method;
        iss >> method;
        return method;
    }

    // Lấy đường dẫn từ yêu cầu
    std::string TcpServer::getRequestPath(const std::string& request)
    {
        std::istringstream iss(request);
        std::string method, path;
        iss >> method >> path;
        return path;
    }

    // Xử lý yêu cầu HTTP
    std::string TcpServer::handleRequest(const std::string& request)
    {
        std::string method = getRequestMethod(request);
        std::string path = getRequestPath(request);

        std::cout << "Method: " << method << ", Path: " << path << std::endl;

        if (path == "/" || path == "/index.html")
        {
            return buildHtmlResponse(getLoginPage());
        }
        else if (path == "/register" && method == "GET")
        {
            return buildHtmlResponse(getRegisterPage());
        }
        else if (path == "/login" && method == "POST")
        {
            auto formData = parseFormData(request);
            return handleLogin(formData);
        }
        else if (path == "/register" && method == "POST")
        {
            auto formData = parseFormData(request);
            return handleRegister(formData);
        }
        else if (path == "/logout")
        {
            return buildHtmlResponse(getLoginPage());
        }
        else
        {
            return buildHtmlResponse("<h1>404 Not Found</h1><p>The requested page was not found.</p>", 404);
        }
    }

    // Tạo phản hồi HTML
    std::string TcpServer::buildHtmlResponse(const std::string& content, int statusCode)
    {
        std::string statusText = (statusCode == 200) ? "OK" : "Not Found";
        std::ostringstream ss;
        ss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
        ss << "Content-Type: text/html; charset=UTF-8\r\n";
        ss << "Content-Length: " << content.length() << "\r\n";
        ss << "Connection: close\r\n";
        ss << "\r\n";
        ss << content;
        return ss.str();
    }
}