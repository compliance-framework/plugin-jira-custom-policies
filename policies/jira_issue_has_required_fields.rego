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

risk_templates := [{
	"name": "Change request missing required custom fields",
	"title": "Incomplete Change Request Fields Undermine Change Traceability and Release Governance",
	"statement": "Change requests missing required fields such as Release URL, Deployment ID, or Service Name cannot be fully traced to their associated deployment, cannot be linked to the impacted service, and cannot be verified as successfully deployed. These fields are essential for post-change verification, incident correlation, and regulatory audit of production changes.",
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
		"title": "Populate all required fields on change request issues",
		"description": "Ensure all change requests have Release URL, Deployment ID, and Service Name fields populated. Make these fields required in the Jira issue type screen configuration and automate population from the deployment pipeline where possible.",
		"tasks": [
			{"title": "Identify all change requests missing any of the required fields and populate them"},
			{"title": "Configure Release URL, Deployment ID, and Service Name as required fields on the Change Request screen in Jira"},
			{"title": "Integrate the CI/CD pipeline to automatically populate Deployment ID and Release URL fields on issue transition"},
			{"title": "Add a Jira automation rule that blocks transition to 'Done' if any required field is empty"},
			{"title": "Document the expected field names and format in the team's working agreement or project README"},
		],
	},
}]

violation[{"id": "missing_required_field", "remarks": remarks}] if {
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
