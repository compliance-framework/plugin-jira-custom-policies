package compliance_framework.jira_issue_deployment_successful

import future.keywords.if
import future.keywords.in

title := "Change requests must have deployment and release information"
description := "All change request issues must have deployment and release information in custom fields."

deployment_field_patterns := ["deployment", "deploy", "release"]

risk_templates := [{
	"name": "Change request missing deployment or release information",
	"title": "Untracked Deployment Information Prevents Change Audit and Rollback Planning",
	"statement": "A change request without deployment or release information in its custom fields cannot be linked to a specific deployed artifact or release version. This breaks the traceability chain from change approval to production deployment, making it impossible to determine what was deployed when, to verify the deployment matches the approved change, or to roll back to a known good state during an incident.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title": "Incomplete Documentation",
			"url": "https://cwe.mitre.org/data/definitions/1059.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title": "Protection Mechanism Failure",
			"url": "https://cwe.mitre.org/data/definitions/693.html",
		},
	],
	"remediation": {
		"title": "Populate deployment and release fields on all change requests",
		"description": "Ensure all change request issues include deployment or release information in the appropriate custom fields. Integrate the deployment pipeline to automatically populate these fields upon successful deployment.",
		"tasks": [
			{"title": "Identify and update all change requests missing deployment or release custom field values"},
			{"title": "Configure the CI/CD pipeline to update Jira custom fields with deployment ID and release URL upon completion"},
			{"title": "Add deployment and release fields as required fields in the Jira change request issue type screen"},
			{"title": "Create a Jira automation rule to flag CRs that reach 'Done' status without deployment fields populated"},
			{"title": "Document the expected field naming convention for deployment/release fields in the project's working agreement"},
		],
	},
}]

violation[{"id": "missing_deployment_info", "remarks": remarks}] if {
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
