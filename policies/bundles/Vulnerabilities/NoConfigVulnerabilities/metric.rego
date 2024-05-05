package clouditor.metrics.no_config_vulnerabilities
import data.clouditor.compare
import input.configVulnerabilities as confvul

default compliant = false

default applicable = false

applicable {
	false
}

compliant {
	compare(data.operator, data.target_value, confvul)
}
