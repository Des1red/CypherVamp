package scanners

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"net"
	"regexp"
	"strings"
	"bufio"
	"errors"
	"bytes"
	"math/rand"
)

// SPOOFER
// generateMAC generates a random MAC address. for spoof scan
func generateMAC() (string, error) {
	mac := make([]byte, 6)
	_, err := rand.Read(mac)
	if err != nil {
		return "", err
	}

	// Set the local bit (second least significant bit of the first byte)
	mac[0] = (mac[0] | 2) & 0xfe

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]), nil
}
// isValidMAC checks if the given input is a valid MAC address. for spoof scan
func isValidMAC(mac string) bool {
	// Regular expression for validating MAC address
	re := regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	return re.MatchString(mac)
}
// getSystemIP retrieves the system's IP address based on a specified network adapter.
func getSystemIP(adapter string) (string, error) {
	// Get the IP address for the specified adapter
	cmd := exec.Command("ip", "-4", "addr", "show", adapter)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Parse the output to find the IP address
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			// Extract the IP address
			parts := strings.Fields(line)
			if len(parts) > 1 {
				ip := strings.Split(parts[1], "/")[0]
				return ip, nil
			}
		}
	}
	return "", errors.New("could not find IP address for adapter")
}

func Spoof(ctx context.Context, ip, outputDir string) {
	fmt.Println("Results are saved at : " + outputDir + "\n")
	fmt.Printf("Set to Spoofed Scan" + Red + " >> " + Reset + "%s\n", ip)
	
	//get user input
	adapter, macAddress, sourceIP, changedsource := getInput()
	macAddress = validateOrGenerateMAC(macAddress)
	sourceIP = getSourceIP(sourceIP, adapter)

	// clean up after program is done
	originalMAC, err := getOriginalMAC(adapter)
	if err != nil {
		fmt.Println("Error retrieving original MAC address:", err)
		os.Exit(1)
	}
	defer restoreMAC(adapter, originalMAC)

	// Set the spoofed MAC address
	if err := setMAC(adapter, macAddress); err != nil {
		fmt.Println("Error setting spoofed MAC address:", err)
		os.Exit(1)
	}

	if changedsource {
		defer removeSpoofedIP(sourceIP, adapter)
	}

	// execute spoof scan
	nmapDone, npingDone, tcpdumpDone := make(chan struct{}), make(chan struct{}), make(chan struct{})

	go runNmap(ctx, nmapDone, ip, outputDir, macAddress, sourceIP, adapter)
	go runNping(ctx, nmapDone, npingDone, ip, sourceIP, macAddress, adapter)
	go runTcpdump(ctx, nmapDone, tcpdumpDone, ip, adapter)

	<-npingDone
	<-tcpdumpDone

	fmt.Println("All tasks completed successfully")
}

func getInput() (string, string, string, bool) {
	var adapter, macAddress, sourceIP string
	fmt.Print("ADAPTER: ")
	fmt.Scanln(&adapter)
	fmt.Print("\nMAC ADDRESS (leave blank to generate Mac): ")
	fmt.Scanln(&macAddress)
	macAddress = strings.TrimSpace(macAddress)
	fmt.Print("\nSource IP (leave blank to use system IP): ")
	fmt.Scanln(&sourceIP)
	return adapter, macAddress, sourceIP, false
}

func validateOrGenerateMAC(macAddress string) string {
	for !isValidMAC(macAddress) && macAddress != "" {
		fmt.Print("Invalid MAC ADDRESS. Please enter a valid MAC address: ")
		fmt.Scanln(&macAddress)
		macAddress = strings.TrimSpace(macAddress)
	}
	if macAddress == "" {
		fmt.Println("\nGenerating MAC Address.")
		var err error
		macAddress, err = generateMAC()
		if err != nil {
			fmt.Println("Error generating MAC address:", err)
			os.Exit(1)
		}
	}
	fmt.Printf("\nMAC address set to %s.\n", macAddress)
	return macAddress
}

func getSourceIP(sourceIP, adapter string) string {
	if sourceIP != "" {
		for !IsValidIP(sourceIP) {
			fmt.Print("Invalid IP, try again: ")
			fmt.Scanln(&sourceIP)
		}
		assignIP(sourceIP, adapter, true)
	} else {
		systemIP, err := getSystemIP(adapter)
		if err != nil {
			fmt.Println("Error getting system IP address:", err)
			os.Exit(1)
		}
		sourceIP = systemIP
	}
	fmt.Printf("\nSource IP set to: %s\n", sourceIP)
	return sourceIP
}

func assignIP(sourceIP, adapter string, add bool) {
	skipadd := false
	action := "add"
	if !add {
		action = "del"
	} else { // if its not del check if ip is assigned
		
		assigned, err := isIPAssigned(sourceIP)
		if err != nil {
			fmt.Printf("Error checking IP assignment: %v\n", err)
			return
		}
		if assigned {
				fmt.Printf("IP address %s is already assigned.\n", sourceIP)
				skipadd = true
		} else {
				fmt.Printf("IP address %s is not assigned. Assigning Ip.\n", sourceIP)	
		}

	}
	
//continue with action
	if skipadd != true {
		ipcmd := exec.Command("ip", "addr", action, sourceIP+"/24", "dev", adapter)
		ipcmd.Stderr = os.Stderr
		if err := ipcmd.Run(); err != nil {

			fmt.Printf("\nError: Could not %s IP address: %v\n", action, err)
			if add {
				os.Exit(1)
			}
	
		} else {
			
			fmt.Printf("IP address %sed successfully\n", action)
		
		}
	}
}

func runNmap(ctx context.Context, done chan struct{}, ip, outputDir, macAddress, sourceIP, adapter string) {
	defer close(done)
	cmd := exec.Command("nmap", "-Pn", "-sS", "-O", "-p1-1000", "--open", "--reason", "--stats-every", "30s", "-oA", outputDir+"/Spoofer_"+ip, "-f", "--spoof-mac", macAddress, "-S", sourceIP, "-D", "RND:5", "-e", adapter, ip)
	cmd.Stderr = os.Stderr

	fmt.Printf("Starting nmap scan on IP: %s\n", ip)
	if err := cmd.Run(); err != nil {
		fmt.Printf("\nError: Could not run nmap command: %v\n", err)
	} else {
		fmt.Print("\n--------------------------------\n")
		fmt.Println("nmap scan completed successfully")
		fmt.Print("\n--------------------------------\n")
	}
}

func runNping(ctx context.Context, nmapDone, npingDone chan struct{}, ip, sourceIP, macAddress, adapter string) {
	defer close(npingDone)
	npingCmd := exec.Command("nping", "--dest-ip", ip, "--source-ip", sourceIP, "--spoof-mac", macAddress, "--icmp", "--rate", "10", "--delay", "20ms", "--count", "10000", "-e", adapter)
	npingCmd.Stderr = os.Stderr

	fmt.Printf("Starting nping on IP: %s\n", ip)
	if err := npingCmd.Start(); err != nil {
		fmt.Printf("\nError: Could not start nping command: %v\n", err)
		return
	}

	<-nmapDone
	if err := npingCmd.Process.Kill(); err != nil {
		fmt.Printf("\nError: Could not stop nping command: %v\n", err)
	} else {
		fmt.Print("\n--------------------------------\n")
		fmt.Println("nping completed successfully")
		fmt.Print("\n--------------------------------\n")
	}
}

func runTcpdump(ctx context.Context, nmapDone, tcpdumpDone chan struct{}, ip, adapter string) {
	defer close(tcpdumpDone)
	tcpdumpCmd := exec.Command("tcpdump", "-n", "-i", adapter, "icmp", "and", "host", ip)
	stdoutPipe, err := tcpdumpCmd.StdoutPipe()
	if err != nil {
		fmt.Printf("Error: Could not get stdout pipe: %v\n", err)
		return
	}
	tcpdumpCmd.Stderr = os.Stderr

	fmt.Printf("Starting tcpdump on interface: %s, host: %s\n", adapter, ip)
	if err := tcpdumpCmd.Start(); err != nil {
		fmt.Printf("\nError: Could not start tcpdump command: %v\n", err)
		return
	}

	scanner := bufio.NewScanner(stdoutPipe)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "ICMP echo reply") || strings.Contains(line, "ICMP echo request") {
				parts := strings.Fields(line)
				if len(parts) >= 9 {
					srcIP := parts[2]
					dstIP := parts[4]
					status := Red + "Failed" + Reset
					if strings.Contains(line, "ICMP echo reply") {
						status = Green + "Successful" + Reset
					}
					fmt.Printf(Yellow + "Source IP"+ Reset + ": %s," + Yellow + "	Destination IP" + Reset + ": %s," + Yellow + "	Status" + Reset + ": %s\n", srcIP, dstIP, status)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading tcpdump output: %v\n", err)
		}
	}()

	<-nmapDone
	if err := tcpdumpCmd.Process.Kill(); err != nil {
		fmt.Printf("\nError: Could not stop tcpdump command: %v\n", err)
	} else {
		fmt.Print("\n--------------------------------\n")
		fmt.Println("tcpdump completed successfully")
		fmt.Print("\n--------------------------------\n")
	}
}

//cleaning up ip address
func removeSpoofedIP(sourceIP, adapter string) {
	assignIP(sourceIP, adapter, false)
}

// check if spoof ip is already assigned
func isIPAssigned(ipToCheck string) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.String() == ipToCheck {
				return true, nil
			}
		}
	}

	return false, nil
}

// cleaning up mac address
func getOriginalMAC(adapter string) (string, error) {
	iface, err := net.InterfaceByName(adapter)
	if err != nil {
		return "", fmt.Errorf("failed to get interface by name: %w", err)
	}
	return iface.HardwareAddr.String(), nil
}

func restoreMAC(adapter, originalMAC string) {
	if err := setMAC(adapter, originalMAC); err != nil {
		fmt.Println("Error restoring original MAC address:", err)
	}
}

func setMAC(adapter, macAddress string) error {
	cmd := exec.Command("ip", "link", "set", "dev", adapter, "address", macAddress)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not set MAC address: %w", err)
	}
	fmt.Printf("MAC address set back to %s\n", macAddress)
	return nil
}