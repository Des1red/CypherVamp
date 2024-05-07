# Cypher: IP Reconnaissance Tool

Cypher is an advanced IP reconnaissance tool designed for security professionals to conduct comprehensive scans, tests, and monitoring activities on network hosts. With its focus on security testing, including vulnerability scanning, host discovery, and wireless network monitoring, Cypher empowers users to perform active reconnaissance, vulnerability assessments, and penetration testing with confidence and efficiency.


## Author
- Thanos Diridis (@Des1red)

## Key Features

- **Help Function:** Provides detailed usage instructions for the command-line tool, ensuring ease of use for all users.
- **Vamp Function:** Enables network scanning on specified IP addresses. It prompts users for multiple IP addresses, validates them, and performs scans using industry-standard tools such as nmap and nikto.
- **File Scanning Functionality:** ScanFile() reads IP addresses from a file and scans them concurrently using nmap, streamlining the scanning process for large sets of IP addresses.
- **Network Scanning Functionality:** netScan() scans a specified subnet for hosts with open ports using nmap, facilitating efficient host discovery and port scanning.
- **Network Monitoring Functionality:** MonitorMode() enables monitor mode on a specified wireless adapter, captures wireless traffic, scans a target, deauthenticates the target, and attempts to crack WPA keys using tools like airodump-ng, aireplay-ng, and aircrack-ng.
- **Utility Functions:** Various utility functions like isValidIP, processIP, sanitizeURL, readIPListFromFile, MassiveScan, parseNmapOutput, and Icon enhance the functionality and usability of the tool.

Cypher is an indispensable tool for security professionals seeking to bolster their cybersecurity defenses, identify vulnerabilities, and mitigate potential threats effectively.

## Installation
To install Cypher, clone the repository to your local machine:
https://github.com/Des1red/CypherVamp.git

Give permissions to installer : chmod +x installer.sh

Run the installer : sudo ./installer.sh

## Usage

Cypher supports the following command-line options:

-h, --help: Display the usage instructions.

-v: Start Cypher scanner for a specific URL/IP.

-f, --file: Run Cypher with your own file containing targets.

-nS, --net-scan: Scan the local network for targets.

-m: Enter network monitor mode.

## Examples

Scan a specific URL/IP: cypher -v

Run Cypher with a file containing targets: cypher -f targetfile.txt

Scan the local network for targets: cypher -nS

Enter network monitor mode: cypher -m


## Contributing

TODO: Add contribution guidelines here.

## License

Cypher is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Summary of Key Points

- **Permissions:** You are free to use, modify, and distribute the software.
- **Conditions:** You must include a copy of the license with any distribution, and if you modify the software, you must indicate the changes made.
- **No Warranty:** The software is provided "as is," without warranties or conditions of any kind.
- **Limitation of Liability:** Contributors are not liable for any damages arising from the use of the software.
- **Additional Terms:** If you distribute the software, you may offer additional warranties or liability obligations, but only on your own behalf.
- **Third-Party Tools:** The license does not apply to third-party tools incorporated into the software, each of which is subject to its own licensing terms.

For more details, please refer to the full text of the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
