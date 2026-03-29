#include <iostream>
#include <pcap.h>
#include <cstring>
#include <map>
#include <chrono>
#include <thread>
#include <vector>
#include <mutex>  
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <jsoncpp/json/json.h>
#include <atomic>

using namespace std;

string targetIP;
ofstream logFile("nids_log.txt");
mutex packetMutex;

// Using time_point to track last attack time
atomic<chrono::steady_clock::time_point> last_attack_time;

// Global map for attack labels
map<int, string> attack_labels = {
    {0, "Benign"},
    {1, "Ping Flood"},
    {2, "HTTP Request Flood"},
    {3, "Broadcast Ping Flood"},
    {4, "Random Port Connection Flood"},
    {5, "UDP Flood"}
};

void testMLServerConnection() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cout << "[INFO][ML] Unable to create socket to ML server." << endl;
        return;
    }
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5001);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cout << "[INFO][ML] Could not connect to ML server on port 5001." << endl;
    } else {
        cout << "[INFO][ML] Connected to ML server on port 5001." << endl;
    }
    close(sock);
}

string classifyPacketWithML(const Json::Value& features) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";
    
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5001);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return "";
    }

    Json::StreamWriterBuilder writer;
    string jsonData = Json::writeString(writer, features);

    string httpRequest = "POST /predict HTTP/1.1\r\n";
    httpRequest += "Host: 127.0.0.1:5001\r\n";
    httpRequest += "Content-Type: application/json\r\n";
    httpRequest += "Content-Length: " + to_string(jsonData.length()) + "\r\n";
    httpRequest += "Connection: close\r\n";
    httpRequest += "\r\n";
    httpRequest += jsonData;

    send(sock, httpRequest.c_str(), httpRequest.size(), 0);

    string response;
    char buffer[1024] = {0};
    int valread;

    while ((valread = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        response.append(buffer, valread);
    }
    close(sock);

    size_t json_start = response.find("\r\n\r\n");
    if (json_start != string::npos) {
        return response.substr(json_start + 4);
    }

    return "";
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const int ipHeaderOffset = 14;
    const struct ip *ipHeader = (struct ip *)(packet + ipHeaderOffset);
    char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);
    
    if (targetIP != srcIP && targetIP != dstIP) return;

    string protocol;
    if (ipHeader->ip_p == IPPROTO_ICMP) protocol = "ICMP";
    else if (ipHeader->ip_p == IPPROTO_UDP) protocol = "UDP";
    else if (ipHeader->ip_p == IPPROTO_TCP) protocol = "TCP";
    else protocol = "Unknown (" + to_string((int)ipHeader->ip_p) + ")";

    {
        lock_guard<mutex> lock(packetMutex);
        cout << "[DEBUG][ML] Captured IP Protocol: " << protocol << " | " << srcIP << " -> " << dstIP << endl;
    }

    Json::Value featuresJson;
    featuresJson["src_ip"] = srcIP;
    featuresJson["dst_ip"] = dstIP;
    featuresJson["protocol_num"] = ipHeader->ip_p;
    featuresJson["packet_size"] = header->len;
    featuresJson["ttl"] = ipHeader->ip_ttl;

    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp = (struct tcphdr*)(packet + ipHeaderOffset + (ipHeader->ip_hl * 4));
        featuresJson["src_port"] = ntohs(tcp->th_sport);
        featuresJson["dst_port"] = ntohs(tcp->th_dport);
        featuresJson["tcp_flags"] = tcp->th_flags;
        featuresJson["window_size"] = ntohs(tcp->th_win);
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* udp = (struct udphdr*)(packet + ipHeaderOffset + (ipHeader->ip_hl * 4));
        featuresJson["src_port"] = ntohs(udp->uh_sport);
        featuresJson["dst_port"] = ntohs(udp->uh_dport);
    } else {
        featuresJson["src_port"] = 0;
        featuresJson["dst_port"] = 0;
    }

    string ml_response_str = classifyPacketWithML(featuresJson);
    if (ml_response_str.empty()) return;

    Json::Value ml_response_json;
    Json::Reader reader;
    if (reader.parse(ml_response_str, ml_response_json) && ml_response_json["success"].asBool()) {
        int prediction_int = ml_response_json["prediction"].asInt();
        if (prediction_int != 0) {
            last_attack_time = chrono::steady_clock::now();
            string attack_name = attack_labels.count(prediction_int) ? attack_labels[prediction_int] : "Unknown Attack";
            string alert = "[ALERT][ML] " + attack_name + " detected. From: " + srcIP + " To: " + dstIP;
            lock_guard<mutex> lock(packetMutex);
            cout << alert << endl;
            logFile << alert << endl;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    testMLServerConnection();
    cout << "Enter the IP address to monitor: ";
    cin >> targetIP;

    last_attack_time = chrono::steady_clock::now();

    pcap_if_t *allDevs;
    if (pcap_findalldevs(&allDevs, errbuf) == -1 || allDevs == nullptr) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }
    
    pcap_t *handle = pcap_open_live(allDevs->name, BUFSIZ, 1, 100, errbuf);
    if (!handle) {
        cerr << "Error opening device: " << errbuf << endl;
        return 1;
    }

    // Heartbeat thread for "Network is normal"
    thread heartbeat([]{
        while(true) {
            sleep(3);
            auto now = chrono::steady_clock::now();
            if (chrono::duration_cast<chrono::seconds>(now - last_attack_time.load()).count() >= 3) {
                lock_guard<mutex> lock(packetMutex);
                cout << "[INFO][ML] Monitoring... Network is normal." << endl;
            }
        }
    });
    heartbeat.detach();

    cout << "[INFO] NIDS Started on " << allDevs->name << endl;
    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);
    logFile.close();
    return 0;
}
