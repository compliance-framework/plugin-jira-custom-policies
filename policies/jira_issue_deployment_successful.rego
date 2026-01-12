package compliance_framework.jira_issue_deployment_successful

import future.keywords.if
import future.keywords.in

title := "Change requests must have deployment and release information"
description := "All change request issues must have deployment and release information in custom fields."

deployment_field_patterns := ["deployment", "deploy", "release"]

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	count(project.issues) > 0
	issue := project.issues[_]
	is_change_request(issue)
	not has_deployment_field(issue)
	remarks := sprintf("Issue %s does not have deployment or release information in custom fields.", [issue.key])
}

change_request_types := ["change request", "change", "cr", "request a change"]

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in change_request_types
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in change_request_types
}

has_deployment_field(issue) if {
	field := issue.fields_with_metadata[_]
	field_name_lower := lower(field.name)
	pattern := deployment_field_patterns[_]
	contains(field_name_lower, pattern)
	field.value != null
	field.value != ""
}

has_deployment_field(issue) if {
	some field_key, field_value in issue.fields
	field_name_lower := lower(field_key)
	pattern := deployment_field_patterns[_]
	contains(field_name_lower, pattern)
	field_value != null
	field_value != ""
}
