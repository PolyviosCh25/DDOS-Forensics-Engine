#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <thread>
#include <chrono>
#include <algorithm>
#include <random>
#include "json.hpp"

using json = nlohmann::json;

// Executes a curl command and reads the JSON response directly into memory
std::string execute_curl(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int main() {
    std::cout << "========================================================\n";
    std::cout << "  Live Threat Correlation Engine (Randomized Hunt)\n";
    std::cout << "========================================================\n\n";

    // 1. PASTE YOUR CENSYS TOKEN HERE
    std::string censys_token = "censys_Wy1NqXP7_7Nhfx25cBCG1Rm3ZcBz81UrS";

    // 2. READ THE CLEAN IP LIST
    std::vector<std::string> ips;
    std::ifstream file("2026_targets.txt");
    if (!file.is_open()) {
        std::cerr << "[-] Error: Could not open 2026_targets.txt.\n";
        return 1;
    }

    std::string ip;
    while (std::getline(file, ip)) {
        // Since we already used grep to isolate just the IPs, we don't need complex CSV parsing here
        if (!ip.empty()) {
            ips.push_back(ip);
        }
    }

    if (ips.empty()) {
        std::cerr << "[-] No IPs found in 2026_targets.txt.\n";
        return 1;
    }

    // 3. SHUFFLE THE LIST TO GUARANTEE FRESH TARGETS EVERY RUN
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::shuffle(ips.begin(), ips.end(), std::default_random_engine(seed));

    int num_to_scan = 20;
    std::cout << "[+] Loaded " << ips.size() << " active C2 IPs. Selecting " << num_to_scan << " random targets...\n";

    for (int i = 0; i < num_to_scan && i < ips.size(); i++) {
        std::string target_ip = ips[i];
        std::cout << "\n--------------------------------------------------------\n";
        std::cout << "[!] TARGET HOST: " << target_ip << "\n";

        // LAYER 1: CENSYS HOST LOOKUP
        std::cout << "    [+] Querying Censys Host API...\n";
        std::string censys_cmd = "curl -s -X GET 'https://api.platform.censys.io/v3/global/asset/host/" + target_ip + "' "
                                 "-H 'Authorization: Bearer " + censys_token + "' "
                                 "-H 'Accept: application/json'";
        
        std::string raw_censys = execute_curl(censys_cmd);
        bool has_tls = false;

        if (!raw_censys.empty()) {
            try {
                json doc = json::parse(raw_censys);
                if (doc.contains("result") && doc["result"].contains("resource") && doc["result"]["resource"].contains("services")) {
                    for (const auto& service : doc["result"]["resource"]["services"]) {
                        if (service.contains("tls") && service["tls"].contains("fingerprint_sha256")) {
                            std::string cert_hash = service["tls"]["fingerprint_sha256"];
                            std::cout << "        * Extracted TLS SHA-256: " << cert_hash << "\n";
                            std::cout << "        * UI Pivot Query: host.services.cert.fingerprint_sha256: \"" << cert_hash << "\"\n";
                            has_tls = true;
                            break; 
                        }
                    }
                }
                if (!has_tls) std::cout << "        - No TLS certificate indexed by Censys yet.\n";
            } catch (...) {
                std::cout << "        - Censys has not scanned this IP yet (404 Not Found).\n";
            }
        }

        // LAYER 2: URLSCAN APPLICATION LOOKUP
        std::cout << "    [+] Querying URLScan.io...\n";
        std::string urlscan_cmd = "curl -s --max-time 5 \"https://urlscan.io/api/v1/search/?q=ip:" + target_ip + "\"";
        std::string raw_urlscan = execute_curl(urlscan_cmd);

        if (!raw_urlscan.empty()) {
            try {
                json us_doc = json::parse(raw_urlscan);
                if (us_doc.contains("total") && us_doc["total"].get<int>() > 0) {
                    std::string c2_url = us_doc["results"][0]["page"].value("url", "N/A");
                    std::cout << "        * Web Payload Found: " << c2_url << "\n";
                } else {
                    std::cout << "        - No web panels recorded in URLScan.\n";
                }
            } catch (...) {
                std::cout << "        - URLScan rate limit hit.\n";
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    std::cout << "\n[+] Live Threat Correlation Complete.\n";
    return 0;
}