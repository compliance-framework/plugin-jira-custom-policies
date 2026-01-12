package compliance_framework.jira_issue_has_required_fields

import future.keywords.if
import future.keywords.in

title := "Change requests must have required fields populated"
description := "All change request issues must have Release URL, Deployment ID, and Service Name fields populated."

required_field_patterns := {
	"release_url": ["release url", "release_url", "releaseurl", "release link"],
	"deployment_id": ["deployment id", "deployment_id", "deploymentid", "deploy id", "deploy_id"],
	"service_name": ["service name", "service_name", "servicename", "service", "application name", "app name"],
}

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	some field_type, patterns in required_field_patterns
	not has_matching_field(issue, patterns)
	remarks := sprintf("Issue %s is missing required field matching pattern: %s", [issue.key, field_type])
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in ["change request", "change", "cr", "request a change"]
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in ["change request", "change", "cr", "request a change"]
}

has_matching_field(issue, patterns) if {
	field := issue.fields_with_metadata[_]
	field_name_lower := lower(field.name)
	pattern := patterns[_]
	contains(field_name_lower, pattern)
	field.value != null
	field.value != ""
}

has_matching_field(issue, patterns) if {
	some field_key, field_value in issue.fields
	field_name_lower := lower(field_key)
	pattern := patterns[_]
	contains(field_name_lower, pattern)
	field_value != null
	field_value != ""
}
