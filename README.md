# CypherVamp
IP reconnaissance tool

Cypher actively probes and interacts with network hosts by conducting scans, tests, and monitoring activities.
This tool is focused on security testing, including vulnerability scanning, host discovery, and wireless network monitoring.
Cypher is suitable for security professionals conducting active reconnaissance, vulnerability assessments, and penetration testing.

Help Function: Provides usage instructions for the command-line tool.
Vamp Function: This perform network scanning on specified IP addresses. It prompts the user for multiple IP addresses, checks if they are valid, and then performs scans using nmap and nikto.
File Scanning Functionality: ScanFile() reads IP addresses from a file and scans them concurrently using nmap.
Network Scanning Functionality: netScan() scans a specified subnet for hosts with open ports using nmap.
Network Monitoring Functionality: MonitorMode() enables monitor mode on a specified wireless adapter, captures wireless traffic, scans a target, deauthenticates the target, and attempts to crack WPA key using airodump-ng, aireplay-ng, and aircrack-ng.
Utility Functions: Various utility functions like isValidIP, processIP, sanitizeURL, readIPListFromFile, MassiveScan, parseNmapOutput, and Icon assist in different functionalities of the tool.
