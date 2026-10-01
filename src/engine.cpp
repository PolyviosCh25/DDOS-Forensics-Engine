#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>

int main() {
    std::string filename = "../data/botnet_c2.csv";
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cerr << "[-] Error: Could not open Botnet dataset." << std::endl;
        return 1;
    }

    std::cout << "=== C++ Forensics Engine: Shodan InternetDB Module ===\n";
    std::cout << "[+] Ingesting Botnet C2 Infrastructure Feed...\n\n";

    std::string line;
    int count = 0;
    
    // Clear the previous output file
    std::system("echo '' > ../data/shodan_results.json");

    // Skip the first row (the CSV header)
    std::getline(file, line);

    while (std::getline(file, line) && count < 3) {
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        std::string item;
        std::vector<std::string> columns;

        while (std::getline(ss, item, ',')) {
            // Strip the quotation marks so the IP is perfectly clean
            if (!item.empty() && item.front() == '"') item.erase(0, 1);
            if (!item.empty() && item.back() == '"') item.pop_back();
            columns.push_back(item);
        }

        if (columns.size() > 1) {
            std::string target_ip = columns[1];
            
            // Failsafe: Skip if it still reads the header
            if (target_ip == "dst_ip") continue;

            std::cout << "[!] Querying Shodan InternetDB for C2 Server: " << target_ip << std::endl;
            
            // Hit Shodan's open InternetDB API
            std::string command = "curl -s 'https://internetdb.shodan.io/" + target_ip + "' >> ../data/shodan_results.json";
            std::system(command.c_str());
            
            // Add a newline to the JSON file so the outputs don't merge into one giant line
            std::system("echo '' >> ../data/shodan_results.json");
            
            std::cout << "[+] Data saved to data/shodan_results.json\n";
            count++;
        }
    }

    file.close();
    std::cout << "\n[+] Engine execution complete. Ready for analysis." << std::endl;
    return 0;
}