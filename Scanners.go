package main

import (
	"fmt"
	"os/exec"
	"os/signal"
	"os"
	"strings"
	"context"
	"path/filepath"
    "bufio"
	
	"scanners/scanners"
)

// COLORS
const (
	Red   = "\033[31m"
	Green = "\033[32m"
	Reset = "\033[0m"
	Yellow = "\033[33m"
)

func main() {
	outputDir := "Cypher_RESULTS/"
	scanners.Directory(outputDir)
	if len(os.Args) < 2 || len(os.Args) > 4 {
		fmt.Println("Usage: cypher [options] [sub-option]")
		return
	}
	permission := CheckIfroot()
	if permission == false {
		fmt.Print("You are not root. Some scans are " + Red + "unavailable \n" + Reset)
	}
	// Create a channel to listen for interrupt signals
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt)
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure the cancellation function is called on exit
	defer cancel()

	// Start a goroutine to listen for the interrupt signal
	go func() {
		<-sigChannel
		fmt.Println(Red + "\nReceived interrupt signal. Shutting down..." + Reset)
		cancel()
	}()
	switch os.Args[1] {
	case "-h", "--help":
		help()
	case "-v":
		if permission {
			if len(os.Args) > 2 {
				switch os.Args[2] {
				case "ip":
					if len(os.Args) > 3 {
						IpScan(ctx, outputDir)
					} else {
						fmt.Println("Usage: cypher -v ip [IP_ADDRESS]")
					}
				case "url":
					if len(os.Args) > 3 {
						UrlScan(outputDir)
					} else {
						fmt.Println("Usage: cypher -v url [URL]")
					}
				default:
					fmt.Println("Invalid sub-option for -v. Use 'ip' or 'url'.")
				}
			} else {
				vamp(ctx, outputDir)
			}
		} else {
			return
		}
	case "--file", "-f" :
		if permission == true {
			scanners.ScanFile(outputDir)
		} else {
			return
		}
	case "-nS", "--net-scan":
			scanners.NetScan()
	case "-wm":
		if permission == true {
			scanners.MonitorMode()
		} else {
			return
		}
	default:
		fmt.Println("Invalid option. Use '-h' or '--help' for usage instructions.")
	}
}

//Manual
func help() {
	fmt.Println("\nManual \n")
	fmt.Println("Command line " + Red + ">> \n" + Reset)
	fmt.Println("Command 			Usage")
	fmt.Println()
	fmt.Println("	-h 	 --help		Shows the command line\n")
	fmt.Println("	-f  	  --file	Starts Cypher Scanner ,reading file with targets\n")
	fmt.Println("	-v			Starts cypher scanner, FULL scan")
	fmt.Println("	-v ip 			Starts cypher scanner, IP only")
	fmt.Println("	-v url			Starts cypher scanner, URL only\n")
	fmt.Println("	-nS	--net-scan	Scans the local network\n")
	fmt.Println("	-wm			Wifi Monitoring")
	fmt.Print("\n Command examples :	./cypher -v ip <<Target IP>>   |   ./cypher -v   |   ./cypher -wm <<adapter>>")
	fmt.Println("\n")
	fmt.Println(Red + " !" + Reset + "WARNING : High number of IPs for concurrent scans using the --file argument may affect your system performance")
    fmt.Println("			     Using the spoofing option for target scans might cause a dos attack depending on the specific network")
}

func CheckIfroot() bool {
	  // Get the effective user ID of the current process
	  euid := os.Geteuid()
	// Check if the effective user ID is 0 (root)
	if euid == 0 {
		fmt.Println("The program is running as " + Green + "root" + Reset + ".\n")
		return true
	} else {
		fmt.Println("The program is not running as root.\n")
		return false
	}
}
func IpScan(ctx context.Context, outputDir string) {
	// Define the scanners.Directory path to save the output files
	IPDir := filepath.Join(outputDir, "IPS")
	scanners.Directory(IPDir)
	
	// Retrieve the IP address from command-line arguments
	ip := os.Args[3]
	
	// Check if the provided IP is valid
	if scanners.IsValidIP(ip) {
		// Check if the host at the IP address is alive
		if isHostAlive(ip) {
			// Define the target scanners.Directory for the specific IP
			TargetIpDir := IPDir + "/" + ip
			// Create the scanners.Directory for the specific IP
			scanners.Directory(TargetIpDir)
			
			// Run Nmap scan and save the results in the target scanners.Directory
			NmapMenu(ctx, ip, TargetIpDir)
		} else {
			fmt.Println("Host is down.\n")
		}
	} else {
		fmt.Println("Invalid IP.\n")
	}
}
	
func UrlScan(outputDir string) {
    URLDir := filepath.Join(outputDir, "URLS")
    scanners.Directory(URLDir)
    url := os.Args[3]
    scanners.PerformScan(url, URLDir)
}
// Vamp //
func vamp(ctx context.Context, outputDir string) {
	VAMPDir := filepath.Join(outputDir, "FullScans")
	scanners.Directory(VAMPDir)
	fmt.Printf(Icon())

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
	fmt.Println("\nIP addresses received:", ipList)

	// Loop through each IP address and process them one by one
	for _, ip := range ipList {
		if scanners.IsValidIP(ip) {
			TargetIpDir := VAMPDir + "/" + ip
			scanners.Directory(TargetIpDir)
			processIPForVamp(ctx, ip, TargetIpDir)
		} else {
			fmt.Printf("Invalid IP: %s\n", ip)
		}
	}

	fmt.Println("\nAll scans completed.")
}

//running all scanners 
func processIPForVamp(ctx context.Context, ip, outputDir string) {
	fmt.Printf("\nTarget set to " + Red + ">> %s\n", Green+ip+Reset)
	if isHostAlive(ip) {
		NmapMenu(ctx, ip, outputDir)
		scanners.GetSpecificURL(ip, outputDir)
	} else {
		fmt.Printf("%s is 6 feet under :(.\n", Green+ip+Reset)
	}
}
//checking if host is alive
func isHostAlive(ip string) bool {
	fmt.Println("\nChecking if target is reachable")
	check := exec.Command("ping", "-c", "5", ip)
	if err := check.Run(); err != nil {
		return false
	}
	fmt.Println(Green + "Target " + ip + " is alive... for now. ;)" + Reset)
	return true
}

//nmap options menu
func NmapMenu(ctx context.Context, ip, outputDir string) {
	fmt.Println("\n Directory -> "+outputDir)
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
        scanners.Aggressive(ctx, ip, outputDir, done)
    case "s", "S":
        scanners.Spoof(ctx, ip, outputDir)
    case "q", "Q":
        scanners.Quick(ip,  outputDir)
    default:
        fmt.Println("Invalid scan type")
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
