package gvm

import "encoding/xml"

// These types are used by Unmarshal to parse the xml to structs.

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
