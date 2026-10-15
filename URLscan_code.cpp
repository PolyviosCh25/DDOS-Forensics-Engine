#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <memory>
#include <thread>
#include <chrono>
#include "json.hpp"

using json = nlohmann::json;

// Executes a shell command and reads stdout directly into memory
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
    std::cout << "  Threat Infrastructure Correlation Engine\n";
    std::cout << "========================================================\n\n";

    std::ifstream file("2026_targets.txt");
    if (!file.is_open()) {
        std::cerr << "[-] Error: 2026_targets.txt not found in current directory.\n";
        return 1;
    }

    std::string line;
    int record_index = 0;

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        try {
            json doc = json::parse(line);
            if (!doc.contains("result") || !doc["result"].contains("resource")) continue;

            auto& res = doc["result"]["resource"];
            std::string ip = res.value("ip", "UNKNOWN");
            record_index++;

            std::cout << "--------------------------------------------------------\n";
            std::cout << "[" << record_index << "] TARGET HOST: " << ip << "\n";

            // 1. DNS / Domain Information
            if (res.contains("dns") && res["dns"].contains("names")) {
                std::cout << "    [+] Associated Domains:\n";
                for (const auto& name : res["dns"]["names"]) {
                    std::cout << "        - " << name.get<std::string>() << "\n";
                }
            }

            // 2. Services, Ports, and TLS Fingerprints
            if (res.contains("services")) {
                std::cout << "    [+] Active Services & Cryptographic Signatures:\n";
                for (const auto& service : res["services"]) {
                    int port = service.value("port", 0);
                    std::string proto = service.value("protocol", "TCP");
                    std::cout << "        - Port " << port << " (" << proto << ")\n";

                    if (service.contains("tls") && service["tls"].contains("fingerprint_sha256")) {
                        std::string cert_hash = service["tls"]["fingerprint_sha256"];
                        std::cout << "          * TLS SHA-256: " << cert_hash << "\n";
                        std::cout << "          * UI Pivot Query: host.services.cert.fingerprint_sha256: \"" 
                                  << cert_hash << "\"\n";
                    }
                }
            } else {
                std::cout << "    [-] No active services indexed by Censys.\n";
            }

            // 3. Application-Layer Intelligence (URLScan via in-memory curl)
            std::cout << "    [+] Querying URLScan.io...\n";
            std::string urlscan_cmd = "curl -s --max-time 5 \"https://urlscan.io/api/v1/search/?q=ip:" + ip + "\"";
            std::string raw_urlscan = execute_curl(urlscan_cmd);

            if (!raw_urlscan.empty()) {
                try {
                    json us_doc = json::parse(raw_urlscan);
                    if (us_doc.contains("total") && us_doc["total"].get<int>() > 0) {
                        std::string c2_url = us_doc["results"][0]["page"].value("url", "N/A");
                        std::string c2_domain = us_doc["results"][0]["page"].value("domain", "N/A");
                        std::cout << "        * Payload URL: " << c2_url << "\n";
                        std::cout << "        * Hosted Domain: " << c2_domain << "\n";
                    } else {
                        std::cout << "        * No records found in URLScan.\n";
                    }
                } catch (...) {
                    std::cout << "        * URLScan response parsing failed (rate-limit or invalid JSON).\n";
                }
            }

            std::cout << "\n";
            std::this_thread::sleep_for(std::chrono::seconds(1));

        } catch (const json::parse_error& e) {
            std::cerr << "[-] JSON parse error on line: " << e.what() << "\n";
            continue;
        }
    }

    std::cout << "[+] Processing complete. All records parsed.\n";
    return 0;
}