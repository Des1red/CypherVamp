package scanners

import(
	"os"
	"net"
	"bufio"
	"bytes"
	"strings"
)

// these functions are being used in more than one programms of this project
func Directory(outputDir string) {
	// Create the directory if it doesn't exist
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		os.Mkdir(outputDir, 0755)
	}
}

//validating ip
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func filterScanOutput(scanOutput string) string {
    scanner := bufio.NewScanner(strings.NewReader(scanOutput))
    var filteredOutput bytes.Buffer
    inPortSection := false

    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasPrefix(line, "Warning:") {
            break
        }
        if strings.HasPrefix(line, "PORT   STATE SERVICE VERSION") {
            inPortSection = true
        }
        if inPortSection {
            filteredOutput.WriteString(line + "\n")
        }
    }

    return filteredOutput.String()
}