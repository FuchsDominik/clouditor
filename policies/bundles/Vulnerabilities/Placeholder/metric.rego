package clouditor.metrics.placeholder
import data.clouditor.compare

import input.type as types

default compliant = false

default applicable = false

applicable {
	some i
    types[i] == "OperatingSystem"
}

compliant {
	compare(data.operator, data.target_value, true)
}
