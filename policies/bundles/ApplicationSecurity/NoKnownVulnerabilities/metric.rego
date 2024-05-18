package clouditor.metrics.no_known_vulnerabilities

import data.clouditor.compare
import future.keywords.every
import input.vulnerabilities as vul
import input.type as types

default compliant = false

default applicable = false

applicable {
	vul

	is_array(types)
     every t in types {
    	t == "OperatingSystem"
    }
}

compliant {
	compare(data.operator, data.target_value, vul)
}
