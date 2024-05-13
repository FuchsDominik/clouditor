// Copyright 2021 Fraunhofer AISEC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//           $$\                           $$\ $$\   $$\
//           $$ |                          $$ |\__|  $$ |
//  $$$$$$$\ $$ | $$$$$$\  $$\   $$\  $$$$$$$ |$$\ $$$$$$\    $$$$$$\   $$$$$$\
// $$  _____|$$ |$$  __$$\ $$ |  $$ |$$  __$$ |$$ |\_$$  _|  $$  __$$\ $$  __$$\
// $$ /      $$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |$$ |  $$ |    $$ /  $$ |$$ | \__|
// $$ |      $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$\ $$ |  $$ |$$ |
// \$$$$$$\  $$ |\$$$$$   |\$$$$$   |\$$$$$$  |$$ |  \$$$   |\$$$$$   |$$ |
//  \_______|\__| \______/  \______/  \_______|\__|   \____/  \______/ \__|
//
// This file is part of Clouditor Community Edition.

package gvm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fsnotify/fsnotify"

	"clouditor.io/clouditor/v2/api/discovery"
	"clouditor.io/clouditor/v2/api/ontology"
	"github.com/sirupsen/logrus"
)

var log *logrus.Entry

func init() {
	log = logrus.WithField("component", "gvm-discovery")
}

type gvmDiscovery struct {
	csID   string
	domain string
}

type DiscoveryOption func(a *gvmDiscovery)

func NewGvmDiscovery(id string) discovery.Discoverer {
	d := &gvmDiscovery{
		csID:   id,
		domain: "localhost",
	}

	return d
}

func (d *gvmDiscovery) CloudServiceID() string {
	return d.csID
}

func (d *gvmDiscovery) Name() string {
	return "Greenbone Vulnerability Management Discovery"
}

func (*gvmDiscovery) Description() string {
	return "Discovery of operating system vulnerabilities using Greenbone Vulnerability Management"
}

// List returns a list of resources that were discovered
func (d *gvmDiscovery) List() (list []ontology.IsResource, err error) {
	log.Info("Scanning for resources...")

	// Create connection to GVM container
	return d.discoverOperatingSystem()

	//TODO: Check for errors
	// Forward the results to the evaluation module
}

func (d *gvmDiscovery) discoverOperatingSystem() (providers []ontology.IsResource, err error) {

	// Define the command and parameters
	// cmd := exec.Command("bash", "-c", "ls -la") // Works!

	// A buffer to capture the output
	// var out bytes.Buffer
	// cmd.Stdout = &out

	// Run the command
	// errorMessage := cmd.Run()
	// if errorMessage != nil {
	//	return nil, errorMessage
	// }

	os := &ontology.OperatingSystem{
		Name:            "Linux",
		Vulnerabilities: []*ontology.Vulnerability{},
	}

	results, err := d.collectEvidences()
	if err != nil {
		fmt.Println("Error collecting the evidences:", err)
	}

	// We use the KEV catalog to check if the vulnerability has been exploited in the past
	data, err := loadFileAsString("/Users/dominik.fuchs/Documents/clouditor/internal/kevcatalog/kevcatalog.json") //TODO: Update catalog regurarly to get updated CVEs
	if err != nil {
		fmt.Println("Error reading file:", err)
	}

	fmt.Println(len(data))

	// Map the xml structure to ontology structure
	for _, result := range results {
		for _, ref := range result.NVT.Refs.Ref { //TODO: Here, we create a new vulnerability for each CVE, maybe we should create one vulnerability with multiple CVEs
			vul := &ontology.Vulnerability{}
			vul.Id = result.ID
			vul.Name = result.Name
			vul.Port = result.Port
			vul.Severity = float32(result.Severity) // Convert int to float32
			vul.Threat = result.Threat
			vul.Family = result.NVT.Family
			// Ref specific
			vul.Cve = ref.ID

			// Check if the vulnerability has been exploited in the past
			if data != "" {
				vul.Exploitable = strings.Contains(data, vul.Cve) // Maybe check for "CVE-2021-1234" instead of CVE-2021-1234 to make sure we catch the whole CVE
			} else {
				vul.Exploitable = false
			}

			os.Vulnerabilities = append(os.Vulnerabilities, vul)
		}
	}

	fmt.Println("Vulnerabilities found: ", len(os.Vulnerabilities))
	// fmt.Println("First Vulnerability: ", os.Vulnerabilities[0].Name)  -> jQuery < 1.6.3 XSS Vulnerability

	if err != nil {
		log.Fatal("Error while evaluating vulnerabilities:", err)
	}

	// Print the output from the command
	// fmt.Println("Command Output:", out.String())

	return []ontology.IsResource{os}, err
}

func (d *gvmDiscovery) collectEvidences() (results []Result, err error) {

	// Define the command and parameters
	// cmd := exec.Command("docker", "exec", "greenbone-community-container-gvmd-1", "python3", "/home/GreenbonePythonScript/authenticatedScript.py", filename)

	targetId, err := getTargetId()

	if err != nil {
		fmt.Printf("Error while looking for target: %v", err)
		return
	}
	fmt.Println("TargetId: ", targetId)

	configId, err := getConfigId()

	if err != nil {
		fmt.Printf("Error while looking for config: %v", err)
		return
	}
	fmt.Println("ConfigId: ", configId)

	// Generate a random hash for the name of the task, 16 characters long,
	// or a default hash if something went wrong
	filename, err := generateRandomHex(8)
	if err != nil {
		fmt.Println("Could not generate a random Hash:", err)
		filename = "123456789abcdefg"
	}

	taskId, err := createScanTask(filename, targetId, configId)
	if err != nil {
		fmt.Printf("Error while creating the task: %v", err)
		return
	}
	fmt.Println("TaskId: ", taskId)

	reportId, err := startTask(taskId)
	if err != nil {
		fmt.Printf("Error while starting the task: %v", err)
		return
	}
	fmt.Println("Started task, report Id: ", reportId)

	// Check for new results of the scan
	// reportText, err := d.watchResults(directory, filename) // filename
	if err != nil {
		fmt.Printf("Error while watching the results: %v", err)
		return
	}

	// Go on to parse the report
	/*

		report := Report{}
		// Unmarshal the XML content to the struct
		err = xml.Unmarshal(reportText, &report)
		if err != nil {
			fmt.Printf("Error while parsing the report: %v", err)
			return
		}

		results = report.Report.Results.Result

		// Seems ok, Authenticated Scan / LSC Info Consolidation (Linux/Unix SSH Login)
		// fmt.Println("First Name: ", results[0].Name)
		fmt.Println("results: ", len(results))

		// Only keep the CVE references
		for i := range results {
			var cves []Ref
			// fmt.Println("Refs: ", len(results[i].NVT.Refs.Ref))
			for _, ref := range results[i].NVT.Refs.Ref {
				if ref.Type == "cve" {
					cves = append(cves, ref)
				}
			}
			results[i].NVT.Refs.Ref = cves
		}

		// fmt.Println("First CVE: ", results[0].NVT.Refs.Ref[0].ID) // -> Throws error, since 1. result does not have a CVE reference
	*/
	return
}

// WatchResults creates a watcher for the file and returns the content of the file
func (d *gvmDiscovery) watchResults(directory string, filename string) (contentText []byte, err error) {

	// Create a channel to receive the file content
	contentCh := make(chan []byte)

	// Set up a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Start listening for events
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					log.Println("Error in the event the file created:", err)
					return
				}
				fmt.Println("Event:", event)
				if event.Op&fsnotify.Create == fsnotify.Create {
					if event.Name == directory+"/"+filename {
						fmt.Println("File Created:", event.Name)
						content, err := os.ReadFile(event.Name)
						contentText = content
						if err != nil {
							log.Println("Error reading file:", err)
							continue
						}
						// Send the file content to the channel
						contentCh <- content
						return
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					log.Println("error:", err)
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(directory)
	if err != nil {
		log.Fatal(err)
	}

	// Receive the file content from the channel
	contentText = <-contentCh

	return contentText, nil

}

// loadFileAsString reads the entire file content as a single string
func loadFileAsString(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// generateRandomHex generates a random hex string of length n
func generateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getTargetId() (string, error) {
	cmd := exec.Command("bash", "-c", `ssh -i ~/.ssh/gvm kali@192.168.178.112 -f 'gvm-cli --gmp-username admin --gmp-password ff4e1015-ccdf-476d-baad-13bb657f552e socket --xml "<get_targets/>"'`)

	// Execute the command and collect the output
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Could not run target command: ", err)
	}

	var response GetTargetsResponse

	err = xml.Unmarshal(out, &response)
	if err != nil {
		fmt.Println("Error unmarshaling target XML:", err)
		return "", err
	}

	if response.Targets.Hosts == "192.168.178.102" {
		fmt.Println("ID of target with IP '192.168.178.102':", response.Targets.ID)
	} else {
		fmt.Println("No target with the specified IP found.")
	}
	return response.Targets.ID, nil
}

func getConfigId() (string, error) {
	cmd := exec.Command("bash", "-c", `ssh -i ~/.ssh/gvm kali@192.168.178.112 -f 'gvm-cli --gmp-username admin --gmp-password ff4e1015-ccdf-476d-baad-13bb657f552e socket --xml "<get_configs/>"'`)

	// Execute the command and collect the output
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Could not run config command: ", err)
	}

	var response GetConfigsResponse

	err = xml.Unmarshal(out, &response)
	if err != nil {
		fmt.Println("Error unmarshaling config XML:", err)
		return "", err
	}

	// Loop through all configs and find the one with the specified name
	for _, config := range response.Configs {
		if config.Name == "Full and fast Ports" {
			fmt.Printf("ID of '%s' config: %s\n", config.Name, config.ID)
			return config.ID, nil
		}
	}

	return "", nil
}

func createScanTask(filename string, targetId string, configId string) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm kali@192.168.178.112 -f 'gvm-cli --gmp-username admin --gmp-password ff4e1015-ccdf-476d-baad-13bb657f552e socket --xml "<create_task><name>%s</name> \
	<target id=\"%s\"></target> \
	<config id=\"%s\"></config></create_task>"'`, filename, targetId, configId))

	// Execute the command and collect the output
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Could not run create task command: ", err)
	}

	target := string(out)

	fmt.Println("Output:\n", target)

	var response CreateTaskResponse

	err = xml.Unmarshal(out, &response)
	if err != nil {
		fmt.Println("Error unmarshaling create task XML:", err)
		return "", err
	}

	if response.Status == "201" {
		fmt.Println("Task successfully created with Id: ", response.ID)
	} else {
		fmt.Println("Could not create the task. Status: ", response.Status)
		return "", nil
	}
	return response.ID, nil
}

func startTask(taskId string) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm kali@192.168.178.112 -f 'gvm-cli --gmp-username admin --gmp-password ff4e1015-ccdf-476d-baad-13bb657f552e socket --xml "<start_task task_id=\"%s\"/>"'`, taskId))

	// Execute the command and collect the output
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Could not run start task command: ", err)
	}

	var response StartTaskResponse

	err = xml.Unmarshal(out, &response)
	if err != nil {
		fmt.Println("Error unmarshaling start task XML:", err)
		return "", err
	}

	if response.Status == "202" {
		fmt.Println("Task successfully started with report Id: ", response.ReportID)
	} else {
		fmt.Println("Could not start the task. Status: ", response.Status)
		return "", nil
	}
	return response.ReportID, nil
}
