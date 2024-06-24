package scanners

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"bufio"
	"bytes"
)

func ScanFile(outputDir string) {
	var fileToScan string

	if len(os.Args) <= 2 || os.Args[2] == "" {
		fmt.Print("File with targets " + Red + ">> " + Reset)
		fmt.Scanln(&fileToScan)
	} else {
		fileToScan = os.Args[2]
	}
	// Check if the file exists
	if _, err := os.Stat(fileToScan); os.IsNotExist(err) {
		fmt.Println("File does not exist.")
		return
	}
    
	// Read IP list from file
    ipList, err := readIPListFromFile(fileToScan)
    if err != nil {
        fmt.Printf("Error reading IP list: %v\n", err)
        return
    }

    // Define the directory path to save the output files
    FileDir := outputDir+"ScannedFiles/"
	Directory(FileDir)

    var wg sync.WaitGroup
    var mu sync.Mutex // Mutex for protecting buffer
    var outputBuffer bytes.Buffer // Buffer to collect output
    done := make(chan struct{}, len(ipList)) // Buffered channel

    for _, ip := range ipList {
        if IsValidIP(ip) {
            wg.Add(1)
            go func(ip string) {
                defer wg.Done()
                scanOutput := MassiveScan(ip, FileDir)
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
	combinedXMLFile := FileDir + "combined.xml"
	fmt.Println("Combining XML files into:", combinedXMLFile)

	// Check the list of XML files in the directory
	xmlFiles, err := filepath.Glob(FileDir + "*.xml")
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
	//saving output file with name
	var outputFile string
	outputFile = outputDir + ip + ".txt"
	

    var output bytes.Buffer // Buffer to collect output
    fmt.Printf("Starting " + Green + "Scan" + Reset + " for IP " + Red + ">> " + Reset + "%s\n", Red+ip+Reset)
	
    //executing scan
	cmd := exec.Command("nmap", "-T5", "-A", "--open", "-oA", outputFile, ip)
    
    cmd.Stdout = &output // Redirect command output to buffer
    fmt.Println("------------------------------------------------------------" + Reset)

    if err := cmd.Run(); err != nil {
        fmt.Println(Red+"could not run nmap command:", err, Reset)
    }

    return output.String() // Return output as string
}
