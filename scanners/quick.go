package scanners

import (
	"fmt"
	"os"
	"os/exec"
	"unicode"
	"strings"
	"bytes"
	
)

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
        cmd = exec.Command("nmap", "-Pn", "-A", "--script", "vuln", "-p"+openPorts,"-oA", outputDir+"/QuickScan_"+ip, ip)
        var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr

        if err := cmd.Run(); err != nil {
            fmt.Println(Red+"could not run nmap command:", err, Reset)
            return
        }

		scanOutput := out.String()
		filteredOutput := filterScanOutput(scanOutput)
		fmt.Print(filteredOutput)

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