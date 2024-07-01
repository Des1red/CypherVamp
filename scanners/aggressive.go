package scanners

import (
	"fmt"
	"context"
	"os/exec"
	"regexp"
	"os"
	"path/filepath"
	"bytes"


)

// COLORS
const (
	Red   = "\033[31m"
	Green = "\033[32m"
	Reset = "\033[0m"
	Yellow = "\033[33m"
)

func Aggressive(ctx context.Context, ip, outputDir string, done chan<- bool) {
    defer func() { done <- true }()
    
    ports := promptUserForPorts()
    if ports == "" {
        ports = "1-10000"
    }
    fmt.Println("Results are saved at : " + outputDir + "\n")
    fmt.Printf("Set to %sAggressive Scan%s ports: %s%s >> %s%s%s\n", Green, Reset, Green, ports, Red, ip, Reset)
    cmd := exec.Command("nmap", "-Pn", "-A", "--script", "vuln", "-p"+ports, "--open", "-oA", filepath.Join(outputDir, "AggresiveScan_"+ip), ip)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

    if err := cmd.Run(); err != nil {
        logError("could not run nmap command:", err)
        return
    }

	scanOutput := out.String()
    startat := "PORT   STATE SERVICE VERSION"
    endat := "OS and Service"
	filteredOutput := filterScanOutput(scanOutput, startat, endat)
	fmt.Printf("\n%s",filteredOutput)
    
	fmt.Printf("\nFor full scan details check : %s\n", outputDir)


    logSuccess("Aggressive scan completed")
}

func promptUserForPorts() string {
    fmt.Print("Ports (<21,22,23>, empty for default): ")
    var ports string
    fmt.Scanln(&ports)
    if valid, err := validatePorts(ports); !valid || err != nil {
        logError("Invalid input. Ports must be numbers separated by commas.", err)
        return ""
    }
    return ports
}

func validatePorts(ports string) (bool, error) {
    if len(ports) == 0 {
        return true, nil
    }
    valid, err := regexp.MatchString(`^(\d+)(,\d+)*$`, ports)
    return valid, err
}

func logError(message string, err error) {
    fmt.Println(Red, message, err, Reset)
}

func logSuccess(message string) {
    fmt.Println(Green, message, Reset)
}