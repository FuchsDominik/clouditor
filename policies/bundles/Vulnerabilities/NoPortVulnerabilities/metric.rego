package clouditor.metrics.no_port_vulnerabilities
import data.clouditor.compare
import input.portVulnerabilities as pv

default compliant = false

default applicable = false

applicable {
	false
}

compliant {
	compare(data.operator, data.target_value, pv)
}
