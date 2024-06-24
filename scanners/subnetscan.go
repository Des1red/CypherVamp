package scanners

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func NetScan() {
    var subnet string
    fmt.Print("Enter the subnet address (e.g., 192.168.1.0/24, empty for default): ")
    fmt.Scanln(&subnet)
    if subnet == "" {
        subnet = "192.168.1.0/24"
    }
	fmt.Print("Do you want to scan only common ports ? ")
	var choice string
	fmt.Scanln(&choice)
	for choice != "y" && choice != "n" {
        fmt.Println("Please type y/n")
        fmt.Print("Do you want to scan only common ports? (y/n): ")
        fmt.Scanln(&choice)
    }
	
	var cmd *exec.Cmd
	if choice == "y" {
		cmd = exec.Command("nmap", "-p80,443,445,21,22,23,25,110,143,8080", "-oG", "-", "-T4", subnet)
	} 
	if choice == "n" {
		cmd = exec.Command("nmap", "-sS", "-oG", "-", "-T4", subnet)
	}
	
    fmt.Println(Green + "\nScanning " + Reset + subnet + Red + " >>" + Reset)

    // Execute the command
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    // Parse the output to extract alive hosts with open ports
    scannedHosts := parseNmapOutput(string(output))

    // Check if no hosts were found
    if len(scannedHosts) == 0 {
        fmt.Println("No hosts found.")
    } else {
		fmt.Println("_______________________________________________________________________________________________\n")
		// Print the scanned hosts with open ports
    	for host, ports := range scannedHosts {
        	fmt.Printf("\nScanned host: " + Red + "%s" + Reset + "\n	Open Ports: " + Green + "%v\n" + Reset, host, ports)
    	}
	}
	fmt.Println()
	fmt.Println("_______________________________________________________________________________________________\n")
	fmt.Print("Do you want to perform an arp scan ? (y/n): ")
	fmt.Scanln(&choice)
	for choice != "y" && choice != "n" {
        fmt.Println("Please type y/n")
        fmt.Print("Do you want to perform an arp scan ? (y/n): ")
        fmt.Scanln(&choice)
    }
	if choice == "y" {
		fmt.Println()
		cmd = exec.Command("arp-scan", subnet)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
   		if err != nil {
			fmt.Println("\nError:", err)
			return
		}
		fmt.Println()
		fmt.Println("ARP CACHE : \n")
		cmd = exec.Command("ip", "neighbor")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
   		if err != nil {
			fmt.Println("Error:", err)
			return
    	}
	}

	fmt.Println()
	fmt.Println("_______________________________________________________________________________________________\n")
	
	
}
	
// ParseNmapOutput parses the Nmap output and extracts alive hosts with open ports
func parseNmapOutput(output string) map[string][]string {
    scannedHosts := make(map[string][]string)

    lines := strings.Split(output, "\n")
    var currentHost string
    for _, line := range lines {
        // Check if the line indicates an alive host with open ports
        if strings.Contains(line, "Host:") && strings.Contains(line, "Status: Up") {
            // Extract the IP address from the line
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                currentHost = fields[1]
            }
        } else if strings.Contains(line, "/open/") {
            // Extract port information from the line
            fields := strings.Fields(line)
            for _, field := range fields {
                // Check if the field contains an open port
                if strings.Contains(field, "/open/") {
                    // Extract the port number
                    port := strings.Split(field, "/")[0]
                    scannedHosts[currentHost] = append(scannedHosts[currentHost], port)
                }
            }
        }
    }

    return scannedHosts
}