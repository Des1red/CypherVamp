package scanners

import (
	"strings"
	"net/url"
	"bufio"
	"sync"
	"os"
	"os/exec"
	"context"
	"fmt"
	"time"
	"path/filepath"


)

// URL Scaanner //
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

// URL SCAN
func GetSpecificURL(ip, outputDir string) {

    scanner := bufio.NewScanner(os.Stdin)
    for {
        fmt.Printf("Enter the URL for IP %s%s%s or press Enter to scan the next IP: ", Green, ip, Reset)
        scanner.Scan()
        site := scanner.Text()
        if len(site) == 0 {
            fmt.Println(Green + "Scanning the next IP..." + Reset)
            break
        }

        // Perform the scan with additional arguments
        PerformScan(site, outputDir)
    }
}

func PerformScan(site, outputDir string) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sanitizedURL := sanitizeURL(site)
    targetIP, err := extractIPAddress(site)
    if err != nil {
        fmt.Println("Error extracting IP address:", err)
        return
    }

    var mu sync.Mutex
    completedScans := 0

    updateProgress := func(scanName string) {
        mu.Lock()
        defer mu.Unlock()
        completedScans++
        fmt.Printf("\n %s \n" , scanName)
    }

    loadingDone := make(chan struct{})
    go func() {
        defer close(loadingDone)
        for {
            select {
            case <-loadingDone:
                return
            default:
                time.Sleep(500 * time.Millisecond)
                mu.Lock()
                fmt.Printf("\r%d/4 Scans " + Yellow + "%s " + Reset, completedScans, dots())
                mu.Unlock()
            }
        }
    }()

    executeCommand := func(cmd *exec.Cmd, name string) (string, error) {
        output, err := cmd.CombinedOutput()
        if err != nil {
            return "", fmt.Errorf("\nError executing %s command: %v\nStderr: %s", name, err, string(output))
        }
        return string(output), nil
    }

    dirbOutput, err := executeCommand(exec.CommandContext(ctx, "dirb", site, "-S", "-N", "404"), "dirb")
    if err != nil {
        fmt.Println(err)
    }
    updateProgress("Dirb completed")

    uniscanOutput, err := executeCommand(exec.CommandContext(ctx, "uniscan", "-u", site, "-qwe"), "uniscan")
    if err != nil {
        fmt.Println(err)
    }
    updateProgress("Uniscan completed")

    nmapOutput, err := executeCommand(exec.CommandContext(ctx, "nmap", "-p443", "--script", "http-waf-detect", "--script-args", "http-waf-detect.aggro,http-waf-detect.detectBodyChanges", targetIP), "nmap")
    if err != nil {
        fmt.Println(err)
    }
    updateProgress("Nmap completed")

    niktoOutput, err := executeCommand(exec.CommandContext(ctx, "nikto", "-h", site, "-maxtime", "120", "-Tuning", "123bde"), "nikto")
    if err != nil {
        fmt.Println(err)
    }
    updateProgress("Nikto completed")

    finalOutputFile := filepath.Join(outputDir, sanitizedURL+".txt")
    file, err := os.Create(finalOutputFile)
    if err != nil {
        fmt.Printf("Error creating output file: %v\n", err)
        return
    }
    defer file.Close()

    writer := bufio.NewWriter(file)
    fmt.Fprintln(writer, "Dirb Output:\n", dirbOutput)
    fmt.Fprintln(writer, "------------------------------------------------------------")
    fmt.Fprintln(writer, "Uniscan Output:\n", uniscanOutput)
    fmt.Fprintln(writer, "------------------------------------------------------------")
    fmt.Fprintln(writer, "Nmap Output:\n", nmapOutput)
    fmt.Fprintln(writer, "------------------------------------------------------------")
    fmt.Fprintln(writer, "Nikto Output:\n", niktoOutput)
    writer.Flush()

    loadingDone <- struct{}{} // Signal the loading dots goroutine to stop

    fmt.Println("\nWeb scans completed. Combined output saved to:", finalOutputFile)
}

// Function to generate animated loading dots
func dots() string {
	dots := []string{"", ".", "..", "..."}
	return dots[int(time.Now().UnixNano()/500000000)%4]
}