// Copyright 2023 Fraunhofer AISEC
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

package discovery

import (
	"context"
	"fmt"

	"clouditor.io/clouditor/api/discovery"
	"clouditor.io/clouditor/cli"
	"github.com/spf13/cobra"
)

// NewDiscoveryCommand returns a cobra command for `experimental` subcommands
func NewExperimentalCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "experimental",
		Short: "Experimental discovery service commands",
	}

	AddExperimentalCommands(cmd)

	return cmd
}

// AddExperimentalCommands adds all experimental subcommands
func AddExperimentalCommands(cmd *cobra.Command) {
	cmd.AddCommand(
		NewListGraphEdgesCommand(),
	)
}

// NewListEdgesCommand returns a cobra command for the `list-graph-edges` subcommand
func NewListGraphEdgesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-graph-edges",
		Short: "Lists graph edges",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				err     error
				session *cli.Session
				client  discovery.ExperimentalDiscoveryClient
				res     *discovery.ListGraphEdgesResponse
			)

			if session, err = cli.ContinueSession(); err != nil {
				fmt.Printf("Error while retrieving the session. Please re-authenticate.\n")
				return nil
			}

			client = discovery.NewExperimentalDiscoveryClient(session)

			res, err = client.ListGraphEdges(context.Background(), &discovery.ListGraphEdgesRequest{})

			return session.HandleResponse(res, err)
		},
	}

	return cmd
}