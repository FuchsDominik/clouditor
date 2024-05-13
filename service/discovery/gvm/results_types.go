package gvm

import "encoding/xml"

// These types are used by Unmarshal to parse the xml to structs.

// Manage the targets
type GetTargetsResponse struct {
	XMLName xml.Name `xml:"get_targets_response"`
	Targets Target   `xml:"target"`
}

type Target struct {
	ID    string `xml:"id,attr"`
	Hosts string `xml:"hosts"`
}

// Manage the configs

type GetConfigsResponse struct {
	XMLName xml.Name `xml:"get_configs_response"`
	Configs []Config `xml:"config"`
}

type Config struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

// Manage the reponse of the create task request

type CreateTaskResponse struct {
	XMLName xml.Name `xml:"create_task_response"`
	Status  string   `xml:"status,attr"`
	ID      string   `xml:"id,attr"`
}

// Manage the reponse of the start task request

type StartTaskResponse struct {
	XMLName  xml.Name `xml:"start_task_response"`
	Status   string   `xml:"status,attr"`
	ReportID string   `xml:"report_id"`
}

// The ultimate report

type Report struct {
	Report ReportData `xml:"report"`
}

type ReportData struct {
	Results Results `xml:"results"`
}

type Results struct {
	Result []Result `xml:"result"`
}

type Result struct {
	XMLName  xml.Name `xml:"result"`
	ID       string   `xml:"id,attr"`
	Name     string   `xml:"name"`
	Port     string   `xml:"port"`
	NVT      NVT      `xml:"nvt"`
	Threat   string   `xml:"threat"`
	Severity float32  `xml:"severity"`
}

type NVT struct {
	OID    string `xml:"oid,attr"`
	Family string `xml:"family"`
	Refs   Refs   `xml:"refs"`
}

type Refs struct {
	Ref []Ref `xml:"ref"`
}

// Ref are references where we will only handle CVEs
type Ref struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

/* Example Refs:
<ref type="url" id="https://bugs.jquery.com/ticket/11290"/>
<ref type="cert-bund" id="WID-SEC-2022-0673"/>
<ref type="cert-bund" id="CB-K22/0045"/>
<ref type="dfn-cert" id="DFN-CERT-2023-1197"/>
*/

type CVE struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}
