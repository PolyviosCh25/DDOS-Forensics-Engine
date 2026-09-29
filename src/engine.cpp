#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>

int main() {
    std::string filename = "../data/malware_urls.csv";
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cerr << "[-] Error: Could not open data file." << std::endl;
        return 1;
    }

    std::cout << "=== C++ Network Forensics Engine Initialized ===\n";
    std::cout << "[+] Reading live malware feed...\n\n";

    std::string line;
    int count = 0;

    while (std::getline(file, line) && count < 3) { // Reduced to 3 for clean output
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        std::string item;
        std::vector<std::string> columns;

        while (std::getline(ss, item, ',')) {
            if (!item.empty() && item.front() == '"') item.erase(0, 1);
            if (!item.empty() && item.back() == '"') item.pop_back();
            columns.push_back(item);
        }

        if (columns.size() > 2) {
            std::string raw_url = columns[2];
            
            // 1. Strip http://
            size_t start_pos = raw_url.find("://");
            start_pos = (start_pos != std::string::npos) ? start_pos + 3 : 0;
            size_t end_pos = raw_url.find('/', start_pos);
            std::string domain = raw_url.substr(start_pos, end_pos - start_pos);

            // 2. Strip port number (e.g., :51736)
            size_t port_pos = domain.find(':');
            if (port_pos != std::string::npos) {
                domain = domain.substr(0, port_pos);
            }

            std::cout << "[!] Target " << count + 1 << ": " << domain << std::endl;
            
            // 3. Automated OSINT Lookup (ASN, ISP, Country)
            std::string command = "curl -s 'http://ip-api.com/json/" + domain + "?fields=status,country,isp,org,as'";
            std::system(command.c_str());
            
            std::cout << "\n----------------------------------------\n";
            count++;
        }
    }

    file.close();
    return 0;
}