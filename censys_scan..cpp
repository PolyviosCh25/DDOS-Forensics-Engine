#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include "json.hpp" 

using json = nlohmann::json;

int main() {
    std::cout << "=== Sprint 2: Threat Infrastructure Correlation Engine ===\n";
    std::cout << "[+] Loading harvested C2 profiles from Sprint 1...\n\n";

    // 1. PASTE YOUR CENSYS TOKEN HERE
    std::string censys_token = "API TOKEN GOES HERE";

    std::ifstream file("censys_results.json");
    if (!file.is_open()) {
        std::cerr << "[-] Error: Could not open censys_results.json.\n";
        return 1;
    }

    std::string line;
    bool pivot_complete = false;

    // Loop through the IPs we downloaded
    while (std::getline(file, line) && !pivot_complete) {
        if (line.empty()) continue;

        try {
            json doc = json::parse(line);
            std::string ip = doc["result"]["resource"]["ip"];
            
            for (auto& service : doc["result"]["resource"]["services"]) {
                // If we find a TLS fingerprint, we execute the pivot
                if (service.contains("tls") && service["tls"].contains("fingerprint_sha256")) {
                    std::string cert_hash = service["tls"]["fingerprint_sha256"];
                    int port_num = service["port"];
                    
                    std::cout << "[!] Target IP: " << ip << "\n";
                    std::cout << "    -> [Port " << port_num << "] Extracted TLS Hash: " << cert_hash << "\n";
                    std::cout << "    -> [*] Executing Infrastructure Pivot on Censys Platform API...\n";

                    // 2. THE PIVOT CURL COMMAND (v3 Search API)
                    std::string payload = "{\"query\": \"services.tls.fingerprint_sha256: " + cert_hash + "\"}";
                    std::string command = "curl -s -X POST 'https://api.platform.censys.io/v3/global/search/query' "
                                          "-H 'Authorization: Bearer " + censys_token + "' "
                                          "-H 'Accept: application/json' "
                                          "-H 'Content-Type: application/json' "
                                          "-d '" + payload + "' | tr -d '\\n' > pivot_results.json";
                    
                    std::system(command.c_str());
                    
                    std::cout << "[+] Pivot successful. Hidden C2 servers dumped to pivot_results.json\n";
                    
                    // Break out immediately so we only burn 1 API token testing this
                    pivot_complete = true;
                    break;
                }
            }
        } catch (json::parse_error& e) {
            continue;
        }
    }

    std::cout << "\n[+] Sprint 2 complete. Ready for Database Ingestion.\n";
    return 0;
}