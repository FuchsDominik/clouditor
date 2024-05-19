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
	"time"

	"clouditor.io/clouditor/v2/api/discovery"
	"clouditor.io/clouditor/v2/api/ontology"
	"clouditor.io/clouditor/v2/internal/config"
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
}

func (d *gvmDiscovery) discoverOperatingSystem() (providers []ontology.IsResource, err error) {

	os := &ontology.OperatingSystem{
		Id:              "linuxOS",
		Name:            "Ubuntu",
		Vulnerabilities: []*ontology.Vulnerability{},
		Raw:             "This is the raw object of the operating system",
	}

	results, err := d.collectEvidences()
	if err != nil {
		fmt.Println("Error collecting the evidences:", err)
	}

	// We use the KEV catalog to check if the vulnerability has been exploited in the past
	cmd := exec.Command("bash", "-c", `curl https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)

	// Execute the command and collect the output
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error reading kev catalog:", err)
	}

	// Convert the output from []byte to a string
	data := string(out)

	// Map the xml structure to ontology structure
	for _, result := range results {
		vul := &ontology.Vulnerability{}
		vul.Id = result.ID
		vul.Name = result.Name
		vul.Port = result.Port
		vul.Severity = float32(result.Severity) // Convert int to float32
		vul.Threat = result.Threat
		vul.Family = result.NVT.Family

		// Cve specific
		vul.Exploitable = false
		// vul.Cve = [] // TODO: Add CVEs as array to use for other requirements

		for _, ref := range result.NVT.Refs {
			// vul.Cve = ref.ID

			// Check if the vulnerability has been exploited in the past
			if data != "" && strings.Contains(data, "\""+ref.ID+"\"") {
				vul.Exploitable = true
			}
		}
		os.Vulnerabilities = append(os.Vulnerabilities, vul)
	}

	fmt.Println("Vulnerabilities found: ", len(os.Vulnerabilities))

	if err != nil {
		log.Fatal("Error while evaluating vulnerabilities:", err)
	}
	return []ontology.IsResource{os}, err
}

func (d *gvmDiscovery) collectEvidences() (results []Result, err error) {

	// Get the targetId for the predefined IP-address
	targetId, err := getTargetId()
	if err != nil {
		fmt.Printf("Error while looking for target: %v", err)
		return
	}

	// Get the configId of Full and fast Ports
	configId, err := getConfigId()
	if err != nil {
		fmt.Printf("Error while looking for config: %v", err)
		return
	}

	// Generate a random hash for the name of the task, 16 characters long,
	// or a default hash if something went wrong
	filename, err := generateRandomHex(8)
	if err != nil {
		fmt.Println("Could not generate a random Hash:", err)
		filename = "123456789abcdefg"
	}

	// Create the scan task and get the corresponding taskId
	taskId, err := createScanTask(filename, targetId, configId)
	if err != nil {
		fmt.Printf("Error while creating the task: %v", err)
		return
	}

	// Start the scan and get the reportId
	reportId, err := startTask(taskId)
	if err != nil {
		fmt.Printf("Error while starting the task: %v", err)
		return
	}

	// Get the report format id - Anonymous XML
	reportFormatId, err := getReportFormatId()
	if err != nil {
		fmt.Printf("Error while getting the report format: %v", err)
		return
	}

	// Regularly check for the results
	reportChan := make(chan GetReportsResponse)
	errChan := make(chan error)

	go monitorScan(reportChan, errChan, taskId, reportId, reportFormatId)

	for {
		select {
		case report := <-reportChan:
			fmt.Println("Scan finished!")
			return report.Report.Results, nil
		case err = <-errChan:
			fmt.Println("Error while monitoring the scan: ", err)
			return
		}
	}
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
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm %s@%s -f 'gvm-cli --gmp-username %s --gmp-password %s socket --xml "<get_targets/>"'`, config.VMUsername, config.VMIpAddress, config.GMPUsername, config.GMPPassword))

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

	if response.Targets.Hosts == config.TargetIPAdress {
		fmt.Printf("ID of target with IP '%s': %s\n", config.TargetIPAdress, response.Targets.ID)
	} else {
		fmt.Println("No target with the specified IP found.")
	}
	return response.Targets.ID, nil
}

func getConfigId() (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm %s@%s -f 'gvm-cli --gmp-username %s --gmp-password %s socket --xml "<get_configs/>"'`, config.VMUsername, config.VMIpAddress, config.GMPUsername, config.GMPPassword))

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

	fmt.Println("Could not find correct scan configuration.")
	return "", nil
}

func createScanTask(filename string, targetId string, configId string) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm %s@%s -f 'gvm-cli --gmp-username %s --gmp-password %s socket --xml "<create_task><name>%s</name> \
	<target id=\"%s\"></target> \
	<config id=\"%s\"></config></create_task>"'`, config.VMUsername, config.VMIpAddress, config.GMPUsername, config.GMPPassword, filename, targetId, configId))

	// Execute the command and collect the output
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Could not run create task command: ", err)
	}

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
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm %s@%s -f 'gvm-cli --gmp-username %s --gmp-password %s socket --xml "<start_task task_id=\"%s\"/>"'`, config.VMUsername, config.VMIpAddress, config.GMPUsername, config.GMPPassword, taskId))

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

func getReportFormatId() (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm %s@%s -f 'gvm-cli --gmp-username %s --gmp-password %s socket --xml "<get_report_formats/>"'`, config.VMUsername, config.VMIpAddress, config.GMPUsername, config.GMPPassword))

	// Execute the command and collect the output
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Could not run report format command: ", err)
	}

	var response GetReportFormatsResponse

	err = xml.Unmarshal(out, &response)
	if err != nil {
		fmt.Println("Error unmarshaling report format XML:", err)
		return "", err
	}

	// Loop through all report formats and find the one with the specified name
	for _, format := range response.ReportFormats {
		if format.Name == "Anonymous XML" {
			fmt.Printf("ID of 'Anonymous XML' report format: %s\n", format.ID)
			return format.ID, nil
		}
	}

	return "", nil
}

// monitorScan checks the scan status periodically and processes the report when done.
func monitorScan(reportChan chan<- GetReportsResponse, errChan chan<- error, taskId string, reportId string, reportFormatId string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cmd := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm %s@%s -f 'gvm-cli --gmp-username %s --gmp-password %s socket --xml "<get_tasks filter_string=\"rows=-1\"/>"'`, config.VMUsername, config.VMIpAddress, config.GMPUsername, config.GMPPassword))

			// Execute the command and collect the output
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Could not run get tasks command: ", err)
			}

			var response GetTasksResponse

			err = xml.Unmarshal(out, &response)
			if err != nil {
				fmt.Println("Error unmarshaling get tasks XML:", err)
				// return "", err
				errChan <- err
			}

			// Loop through all configs and find the one with the specified name
			taskFound := false
			finished := false
			for _, task := range response.Tasks {
				if task.ID == taskId {
					taskFound = true
					if task.Status == "Done" {
						fmt.Println("Task finished!")
						finished = true
					}
				}
			}
			if !taskFound {
				fmt.Println("Could not find task. Are you sure it's running?")
				// return "", err
			}

			if taskFound && finished {

				// Simulate report processing
				cmdSecond := exec.Command("bash", "-c", fmt.Sprintf(`ssh -i ~/.ssh/gvm %s@%s -f 'gvm-cli --gmp-username %s --gmp-password %s socket --xml "<get_reports report_id=\"%s\" filter=\"rows=-1\" details=\"1\" format_id=\"%s\"/>"'`, config.VMUsername, config.VMIpAddress, config.GMPUsername, config.GMPPassword, reportId, reportFormatId))

				// Execute the command and collect the output
				out, err = cmdSecond.CombinedOutput()
				if err != nil {
					fmt.Println("Could not run get report command: ", err)
					return
				}

				var response GetReportsResponse

				err = xml.Unmarshal(out, &response)
				if err != nil {
					fmt.Println("Error unmarshaling get report XML:", err)
					errChan <- err
					return
				}

				results := response.Report.Results
				fmt.Println("Unmarshalling worked! Here is the length of the results: ", len(results))
				count := 0

				// Only keep the CVE references
				for i := range response.Report.Results {
					var cves []Ref
					// fmt.Println("Refs: ", len(results[i].NVT.Refs.Ref))
					if len(response.Report.Results[i].NVT.Refs) != 0 {
						for _, ref := range response.Report.Results[i].NVT.Refs {
							if ref.Type == "cve" {
								cves = append(cves, ref)
								count++
							}
						}
						response.Report.Results[i].NVT.Refs = cves
					}
				}
				fmt.Println("CVE count:", count)
				reportChan <- response
				return
			} else {
				fmt.Println("Scan not finished...")
			}
		}
	}
}
