package clouditor.metrics.no_known_vulnerabilities

import data.clouditor.compare
import input.vulnerabilities as vul
import input.type as types

default compliant = false

default applicable = false

applicable {
	vul
	some i
    types[i] != "OperatingSystem"
}

compliant {
	compare(data.operator, data.target_value, vul)
}
