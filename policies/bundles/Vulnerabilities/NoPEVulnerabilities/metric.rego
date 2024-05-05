package clouditor.metrics.no_pe_vulnerabilities
import data.clouditor.compare
import input.PEVulnerabilities as pev

default compliant = false

default applicable = false

applicable {
	false
}

compliant {
	compare(data.operator, data.target_value, pev)
}
