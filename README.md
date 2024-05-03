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

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      [Definitions remain the same as in the Apache License.]

   2. Grant of Copyright License. [Remains the same.]

   3. Grant of Patent License. [Remains the same.]

   4. Redistribution. [Remains the same.]

   5. Submission of Contributions. [Remains the same.]

   6. Trademarks. [Remains the same.]

   7. Disclaimer of Warranty. [Remains the same.]

   8. Limitation of Liability. [Remains the same.]

   9. Accepting Warranty or Additional Liability. [Remains the same.]

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      [The appendix remains the same.]

Exceptions:

This program incorporates third-party tools, libraries, and dependencies, each of which is subject to its own licensing terms. These third-party tools include, but are not limited to, the following:

- Nmap: Licensed under the terms of the Nmap Public Source License (NPSL). For details, see https://nmap.org/book/man-legal.html.
- Uniscan: Licensed under the terms of the GNU General Public License (GPL), version 2.0. For details, see https://github.com/rezasp/uniscan/blob/master/LICENSE.
- Dirb: Licensed under the terms of the GNU General Public License (GPL), version 2.0. For details, see https://github.com/v0re/dirb/blob/master/LICENSE.
- Nikto: Distributed under the terms of the General Public License (GPL), version 2.0. For details, see https://github.com/sullo/nikto/blob/master/LICENSE.
- Aircrack-ng: Distributed under the terms of the GNU General Public License (GPL), version 2.0. For details, see https://github.com/aircrack-ng/aircrack-ng/blob/master/COPYING.
- Airodump-ng: Distributed under the terms of the GNU General Public License (GPL), version 2.0. For details, see https://github.com/aircrack-ng/aircrack-ng/blob/master/COPYING.

This project is licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

**Summary of Key Points:**

- **Permissions**: You are free to use, modify, and distribute the software.
- **Conditions**: You must include a copy of the license with any distribution, and if you modify the software, you must indicate the changes made.
- **No Warranty**: The software is provided "as is," without warranties or conditions of any kind.
- **Limitation of Liability**: Contributors are not liable for any damages arising from the use of the software.
- **Additional Terms**: If you distribute the software, you may offer additional warranties or liability obligations, but only on your own behalf.
- **Third-Party Tools**: The license does not apply to third-party tools incorporated into the software, each of which is subject to its own licensing terms.

For more details, please refer to the full text of the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
