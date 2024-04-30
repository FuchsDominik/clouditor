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
	"fmt"
	"os"

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

func NewGvmDiscovery(opts ...DiscoveryOption) discovery.Discoverer {
	d := &gvmDiscovery{
		csID:   discovery.DefaultCloudServiceID,
		domain: "localhost",
		// client: http.DefaultClient,
	}

	// Apply options
	for _, opt := range opts {
		opt(d)
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

// Starts the discovery process
func (d *gvmDiscovery) collectEvidences() any {

	// Generate a random hash as name for the report; n is the number of bytes,
	// hex string will be twice as long
	filename, err := generateRandomHex(8) // Generates a 16-character hex string
	if err != nil {
		fmt.Println("Error:", err)
		filename = "123456789abcdef" // Default hash
	}

	//TODO: Connect to gvmd Container
	//TODO: Call the script
	// python3 authenticatedScript.py unique_filename

	filename += ".xml" // Add extension

	// Define the directory to watch
	directory := "/Users/dominik.fuchs/Documents/clouditor/reports"

	// Set up a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	contentText := ""

	// Start listening for events
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create {
					if event.Name == directory+"/"+filename {
						fmt.Println("File Created:", event.Name)
						content, err := os.ReadFile(event.Name)
						contentText = string(content)
						if err != nil {
							log.Println("Error reading file:", err)
							continue
						}
						// fmt.Println("File content:", string(content))
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
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

	print(contentText)
	// TODO: Parse the content and map it to the ontology

	// Keep the program alive
	select {}

}

func generateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err // Handle errors properly
	}
	return hex.EncodeToString(bytes), nil
}

// List returns a list of resources discovered by the GVM
// Is this the method where Evicences are discovered, i.e. vulnerabilities stored?
func (d *gvmDiscovery) List() (list []ontology.IsResource, err error) {
	log.Info("Scanning for vulnerabilities on the target system...")

	// Create connection to GVM container

	ssh_connection := d.establishSSHConnection() // Create an instance of SSHConnection

	// Start scanning for vulnerabilities
	results := ssh_connection.startScan()
	print(results)

	//TODO: Check for errors
	// Forward the results to the evaluation module

	return nil, nil
}

// Define the type of ssh_connection
type SSHConnection struct {
	port      string `default:"22"`
	ipAddress string
}

// startScan starts the scan for vulnerabilities
func (s *SSHConnection) startScan() []any {
	// Implementation of the startScan method

	return s.report()
}

// report reports the scan results
func (s *SSHConnection) report() []any {
	// Implementation of the report method
	return []any{}
}

// establishSSHConnection establishes a SSH connection to the GVM server
func (d *gvmDiscovery) establishSSHConnection() SSHConnection {
	panic("unimplemented")
}
