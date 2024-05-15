package clouditor.metrics.placeholder
import data.clouditor.compare
import input.operatingSystem as os

default compliant = false

default applicable = false

applicable {
	os
}

compliant {
	compare(data.operator, data.target_value, true)
}
