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

package assessmentresult

import (
	"bytes"
	"clouditor.io/clouditor/api/assessment"
	"clouditor.io/clouditor/api/orchestrator"
	"clouditor.io/clouditor/cli"
	"clouditor.io/clouditor/cli/commands/login"
	"clouditor.io/clouditor/persistence"
	service_auth "clouditor.io/clouditor/service/auth"
	service_orchestrator "clouditor.io/clouditor/service/orchestrator"
	"context"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"io/ioutil"
	"net"
	"os"
	"testing"
)

var sock net.Listener
var server *grpc.Server

func TestMain(m *testing.M) {
	var (
		err     error
		dir     string
		service *service_orchestrator.Service
	)

	err = os.Chdir("../../../")
	if err != nil {
		panic(err)
	}

	err = persistence.InitDB(true, "", 0)
	if err != nil {
		panic(err)
	}

	service = service_orchestrator.NewService()

	sock, server, err = service_auth.StartDedicatedAuthServer(":0")
	if err != nil {
		panic(err)
	}
	// Store an assessment result that output of CMD 'list' is not empty
	orchestrator.RegisterOrchestratorServer(server, service)
	_, err = service.StoreAssessmentResult(context.TODO(), &orchestrator.StoreAssessmentResultRequest{
		Result: &assessment.AssessmentResult{
			Id:         "assessmentResultID",
			MetricId:   "assessmentResultMetricID",
			EvidenceId: "evidenceID",
			Timestamp:  timestamppb.Now(),
			MetricConfiguration: &assessment.MetricConfiguration{
				TargetValue: toStruct(1.0),
				Operator:    "operator",
				IsDefault:   true,
			}}})

	if err != nil {
		panic(err)
	}

	defer func(sock net.Listener) {
		err = sock.Close()
		if err != nil {
			panic(err)
		}
	}(sock)
	defer server.Stop()

	dir, err = ioutil.TempDir(os.TempDir(), ".clouditor")
	if err != nil {
		panic(err)
	}

	viper.Set("username", "clouditor")
	viper.Set("password", "clouditor")
	viper.Set("session-directory", dir)

	cmd := login.NewLoginCommand()
	err = cmd.RunE(nil, []string{fmt.Sprintf("localhost:%d", sock.Addr().(*net.TCPAddr).Port)})
	if err != nil {
		panic(err)
	}
	defer os.Exit(m.Run())
}

func TestAddCommands(t *testing.T) {
	cmd := NewAssessmentResultCommand()

	// Check if sub commands were added
	assert.True(t, cmd.HasSubCommands())

	// Check if NewListAssessmentResultsCommand was added
	for _, v := range cmd.Commands() {
		if v.Use == "list" {
			return
		}
	}
	t.Errorf("No list command was added")
}

func TestNewListResultsCommand(t *testing.T) {
	var b bytes.Buffer

	cli.Output = &b

	cmd := NewListAssessmentResultsCommand()
	err := cmd.RunE(nil, []string{})
	assert.Nil(t, err)

	var response = &assessment.ListAssessmentResultsResponse{}
	err = protojson.Unmarshal(b.Bytes(), response)

	assert.Nil(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.Results)
}

func toStruct(f float32) (s *structpb.Value) {
	var (
		b   []byte
		err error
	)

	s = new(structpb.Value)

	b, err = json.Marshal(f)
	if err != nil {
		return nil
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return nil
	}

	return
}