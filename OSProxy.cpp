#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <optional>

#pragma comment(lib, "Ws2_32.lib")

static const int kBufSz = 64 * 1024;

struct ParsedRequest {
    std::string method;
    std::string url_or_path;
    std::string http_version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string host;
    std::string port = "80";
    std::string path = "/";
    bool is_connect = false;
};

static inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static inline void send_string(SOCKET s, const std::string& data) {
    const char* p = data.data();
    int left = (int)data.size();
    while (left > 0) {
        int n = send(s, p, left, 0);
        if (n <= 0) throw std::runtime_error("send failed");
        p += n;
        left -= n;
    }
}

static void send_http_error(SOCKET client, int code, const char* text) {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %zu\r\n\r\n"
        "%d %s\n",
        code, text, std::strlen(text) + 4, code, text);
    
    send(client, buf, (int)std::strlen(buf), 0);
}

static std::optional<std::string> recv_until(SOCKET s, const std::string& delim, int max_bytes = 1024 * 1024) {
    std::string out;
    out.reserve(8192);
    char buf[4096];
    while (out.size() < (size_t)max_bytes) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n == 0) break;          
        if (n < 0) return std::nullopt; 
        out.append(buf, buf + n);
        if (out.find(delim) != std::string::npos) return out;
    }
    return std::nullopt; 
}

static bool parse_start_line(const std::string& line, ParsedRequest& pr) {
    size_t p1 = line.find(' ');
    size_t p2 = (p1 == std::string::npos) ? std::string::npos : line.find(' ', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos) return false;
    pr.method = line.substr(0, p1);
    pr.url_or_path = line.substr(p1 + 1, p2 - (p1 + 1));
    pr.http_version = line.substr(p2 + 1);
    pr.is_connect = (to_lower(pr.method) == "connect");
    return true;
}

static void split_host_port(std::string hostport, std::string& host, std::string& port, const char* default_port) {
    auto pos = hostport.find(':');
    if (pos == std::string::npos) {
        host = std::move(hostport);
        port = default_port;
    }
    else {
        host = hostport.substr(0, pos);
        port = hostport.substr(pos + 1);
    }
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
}

static bool parse_headers(const std::string& headers_blob, ParsedRequest& pr) {
    size_t start = 0;
    while (start < headers_blob.size()) {
        size_t end = headers_blob.find("\r\n", start);
        if (end == std::string::npos) break;
        if (end == start) { 
            start = end + 2;
            continue;
        }
        std::string line = headers_blob.substr(start, end - start);
        start = end + 2;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        size_t i = 0; while (i < value.size() && (value[i] == ' ' || value[i] == '\t')) ++i;
        value = value.substr(i);
        pr.headers.emplace_back(name, value);
    }
    return true;
}

static bool parse_request(ParsedRequest& pr, const std::string& raw, size_t& header_end_index) {

    auto pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos) return false;
    header_end_index = pos + 4;
    std::string head = raw.substr(0, pos); 

    size_t eol = head.find("\r\n");
    if (eol == std::string::npos) return false;
    std::string start_line = head.substr(0, eol);
    if (!parse_start_line(start_line, pr)) return false;

    std::string headers_only = head.substr(eol + 2);
    parse_headers(headers_only, pr);

    std::string method_l = to_lower(pr.method);
    if (pr.is_connect) {
        split_host_port(pr.url_or_path, pr.host, pr.port, "443");
        pr.path = "";
    }
    else {

        const std::string http_prefix = "http://";
        const std::string https_prefix = "https://";
        std::string target = pr.url_or_path;
        if (target.rfind(http_prefix, 0) == 0 || target.rfind(https_prefix, 0) == 0) {
            bool is_https = target.rfind(https_prefix, 0) == 0;
            auto after = is_https ? https_prefix.size() : http_prefix.size();
            size_t slash = target.find('/', after);
            std::string hostport = (slash == std::string::npos) ? target.substr(after) : target.substr(after, slash - after);
            split_host_port(hostport, pr.host, pr.port, is_https ? "443" : "80");
            pr.path = (slash == std::string::npos) ? "/" : target.substr(slash);
        }
        else {
            pr.path = target.empty() ? "/" : target;
            std::string host_val;
            for (auto& kv : pr.headers) {
                if (to_lower(kv.first) == "host") { host_val = kv.second; break; }
            }
            if (host_val.empty()) return false;
            split_host_port(host_val, pr.host, pr.port, "80");
        }
    }
    return true;
}

static SOCKET connect_to_remote(const std::string& host, const std::string& port) {
    struct addrinfo hints {}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return INVALID_SOCKET;

    SOCKET s = INVALID_SOCKET;
    for (auto p = res; p; p = p->ai_next) {
        SOCKET t = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (t == INVALID_SOCKET) continue;
        if (connect(t, p->ai_addr, (int)p->ai_addrlen) == 0) { s = t; break; }
        closesocket(t);
    }
    freeaddrinfo(res);
    return s;
}

static std::string rebuild_header_lines_sans_proxy_fields(const ParsedRequest& pr) {
    std::string out;
    bool have_connection = false;
    for (const auto& kv : pr.headers) {
        std::string name_l = to_lower(kv.first);
        if (name_l == "proxy-connection") continue; 
        if (name_l == "connection") {
            have_connection = true;
            out += "Connection: close\r\n";
            continue;
        }
        out += kv.first + ": " + kv.second + "\r\n";
    }
    if (!have_connection) out += "Connection: close\r\n";
    return out;
}

static void pipe_data(SOCKET in, SOCKET out) {
    char* buf = new char[kBufSz];
    while (true) {
        int n = recv(in, buf, kBufSz, 0);
        if (n <= 0) break;
        int sent = 0;
        while (sent < n) {
            int m = send(out, buf + sent, n - sent, 0);
            if (m <= 0) { n = -1; break; }
            sent += m;
        }
        if (n < 0) break;
    }
    delete[] buf;
}

static void handle_connect(SOCKET client, ParsedRequest& pr) {
    SOCKET upstream = connect_to_remote(pr.host, pr.port);
    if (upstream == INVALID_SOCKET) {
        send_http_error(client, 502, "Bad Gateway");
        return;
    }

    send_string(client, "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n");

    std::thread t1([&] { pipe_data(client, upstream); shutdown(upstream, SD_SEND); });
    std::thread t2([&] { pipe_data(upstream, client); shutdown(client, SD_SEND); });
    t1.join();
    t2.join();

    closesocket(upstream);
}

static void handle_http_forward(SOCKET client, ParsedRequest& pr, const std::string& first_chunk_after_headers) {
    SOCKET upstream = connect_to_remote(pr.host, pr.port);
    if (upstream == INVALID_SOCKET) {
        send_http_error(client, 502, "Bad Gateway");
        return;
    }

    std::string start = pr.method + " " + pr.path + " " + pr.http_version + "\r\n";
    std::string hdrs = rebuild_header_lines_sans_proxy_fields(pr);
    bool have_host = false;
    for (auto& h : pr.headers) if (to_lower(h.first) == "host") { have_host = true; break; }
    if (!have_host) hdrs += "Host: " + pr.host + "\r\n";

    send_string(upstream, start);
    send_string(upstream, hdrs);
    send_string(upstream, "\r\n");

    if (!first_chunk_after_headers.empty()) {
        send_string(upstream, first_chunk_after_headers);
    }

    std::thread t_up([&] { pipe_data(client, upstream); shutdown(upstream, SD_SEND); });
    std::thread t_down([&] { pipe_data(upstream, client); shutdown(client, SD_SEND); });
    t_up.join();
    t_down.join();

    closesocket(upstream);
}

static void handle_client(SOCKET client) {
    try {

        auto maybe = recv_until(client, "\r\n\r\n");
        if (!maybe.has_value()) {
            send_http_error(client, 400, "Bad Request");
            return;
        }
        std::string raw = *maybe;

        ParsedRequest pr;
        size_t header_end = 0;
        if (!parse_request(pr, raw, header_end)) {
            send_http_error(client, 400, "Bad Request");
            return;
        }
        std::string after_headers;
        if (header_end < raw.size()) after_headers.assign(raw.begin() + header_end, raw.end());

        if (pr.is_connect) {
            handle_connect(client, pr);
        }
        else {
            handle_http_forward(client, pr, after_headers);
        }
    }
    catch (...) {
    }
    closesocket(client);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <listen_port>\n", argv[0]);
        return 1;
    }
    const char* listen_port = argv[1];

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
    addrinfo* res = nullptr;
    if (getaddrinfo(nullptr, listen_port, &hints, &res) != 0) {
        std::fprintf(stderr, "getaddrinfo failed for port %s\n", listen_port);
        WSACleanup();
        return 1;
    }

    SOCKET listener = INVALID_SOCKET;
    for (auto p = res; p; p = p->ai_next) {
        SOCKET s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        BOOL yes = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

        if (bind(s, p->ai_addr, (int)p->ai_addrlen) == 0 && listen(s, SOMAXCONN) == 0) {
            listener = s;
            break;
        }
        closesocket(s);
    }
    freeaddrinfo(res);

    if (listener == INVALID_SOCKET) {
        std::fprintf(stderr, "Failed to bind/listen on port %s\n", listen_port);
        WSACleanup();
        return 1;
    }

    std::printf("Proxy listening on port %s ...\n", listen_port);

    while (true) {
        sockaddr_in cli_addr{};
        int len = sizeof(cli_addr);
        SOCKET client = accept(listener, (sockaddr*)&cli_addr, &len);
        if (client == INVALID_SOCKET) {
            std::fprintf(stderr, "accept failed\n");
            continue;
        }
        std::thread(handle_client, client).detach();
    }

    closesocket(listener);
    WSACleanup();
    return 0;
}
