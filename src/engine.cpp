#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

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

    while (std::getline(file, line) && count < 5) {
        // Skip comment lines in the URLhaus CSV
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        std::string item;
        std::vector<std::string> columns;

        // Split the CSV line by commas
        while (std::getline(ss, item, ',')) {
            // Remove quotes if they exist
            if (!item.empty() && item.front() == '"') item.erase(0, 1);
            if (!item.empty() && item.back() == '"') item.pop_back();
            columns.push_back(item);
        }

        // The URL is in the 3rd column (index 2)
        if (columns.size() > 2) {
            std::string raw_url = columns[2];
            
            // Extract the domain by stripping http:// or https://
            size_t start_pos = raw_url.find("://");
            start_pos = (start_pos != std::string::npos) ? start_pos + 3 : 0;
            size_t end_pos = raw_url.find('/', start_pos);
            std::string domain = raw_url.substr(start_pos, end_pos - start_pos);

            std::cout << "[!] Target " << count + 1 << ": " << domain << std::endl;
            count++;
        }
    }

    file.close();
    std::cout << "\n[+] Engine PoC complete. Ready for ASN resolution module." << std::endl;
    return 0;
}
