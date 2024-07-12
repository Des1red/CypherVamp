package scanners

import (
	"fmt"
	"sync"
	"os/exec"
	"unicode"
	"strings"

	
)

type FilterFunc func(string, string, string) string

func execNmapAndFilter(args []string, filter FilterFunc, startat, endat string) (string, error) {
    cmd := exec.Command("nmap", args...)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return "", fmt.Errorf("failed to execute command: %v, output: %s", err, string(output))
    }

    // Convert the output to string
    scanOutput := string(output)

    // Filter the scan output based on specified criteria
    filteredOutput := filter(scanOutput, startat, endat)

    return filteredOutput, nil
}

//NMAP QUICK
func Quick(ip , outputDir string) {
    fmt.Println("Results are saved at : " + outputDir + "\n")
    fmt.Printf("Set to  " + Green + "Quick Scan" + Reset + "\n  IP  " + Red + ">> " + Reset + "%s\n", Red+ip+Reset)
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
        fmt.Printf("\nPerforming second scan on open ports: %s\n",Green+openPorts+Reset)

        // Command arguments for version and OS detection scan
        args1 := []string{"-Pn", "-A", "-p", openPorts, "-oN", fmt.Sprintf("%s/QuickScan_%s_VersionOsScan", outputDir, ip), ip}
        // Command arguments for vulnerability scan
        args2 := []string{"-Pn", "--script", "vuln", "-p", openPorts, "-oN", fmt.Sprintf("%s/QuickScan_%s_VulnScan", outputDir, ip), ip}

        // Execute the version and OS detection scan
        var wg sync.WaitGroup

        // Increment the WaitGroup counter for the first Goroutine
        wg.Add(1)
        go func() {
            defer wg.Done() // Decrement the counter when the Goroutine completes
            startat := "PORT"
            endat := "OS and Service"
            filteredOutput, err := execNmapAndFilter(args1, filterScanOutput, startat, endat)
            if err != nil {
                fmt.Println("Error executing nmap command:", err)
                return
            } 
            fmt.Println(filteredOutput)
        }()

        // Increment the WaitGroup counter for the second Goroutine
        wg.Add(1)
        go func() {
            defer wg.Done() // Decrement the counter when the Goroutine completes
            startat := "PORT"
            endat := "# Nmap done"
            filteredOutput, err := execNmapAndFilter(args2, filterScanOutput, startat, endat)
            if err != nil {
                fmt.Println("Error executing nmap command:", err)
                return
            }
            fmt.Println(filteredOutput)
        }()

        // Wait for both Goroutines to complete
        wg.Wait()
		fmt.Printf("\nFor full scan details check : %s\n", outputDir)

    } else {
        fmt.Println(Green + "\nNo open ports found, skipping second scan." + Reset)
    }

    fmt.Println(Red + "\n =============================================================" + Reset)
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