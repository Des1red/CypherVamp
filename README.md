# CypherVamp
IP reconnaissance tool

Help Function: Provides usage instructions for the command-line tool.
Vamp Function: This perform network scanning on specified IP addresses. It prompts the user for multiple IP addresses, checks if they are valid, and then performs scans using nmap and nikto.
File Scanning Functionality: ScanFile() reads IP addresses from a file and scans them concurrently using nmap.
Network Scanning Functionality: netScan() scans a specified subnet for hosts with open ports using nmap.
Network Monitoring Functionality: MonitorMode() enables monitor mode on a specified wireless adapter, captures wireless traffic, scans a target, deauthenticates the target, and attempts to crack WPA key using airodump-ng, aireplay-ng, and aircrack-ng.
Utility Functions: Various utility functions like isValidIP, processIP, sanitizeURL, readIPListFromFile, MassiveScan, parseNmapOutput, and Icon assist in different functionalities of the tool.
