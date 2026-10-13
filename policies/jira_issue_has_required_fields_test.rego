package compliance_framework.jira_issue_has_required_fields_test

import data.compliance_framework.jira_issue_has_required_fields as policy

test_violation_when_missing_release_url if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"customfield_10001": "deploy-123",
			"customfield_10002": "my-service",
		},
		"fields_with_metadata": [
			{
				"id": "customfield_10001",
				"name": "Deployment ID",
				"type": "string",
				"value": "deploy-123",
			},
			{
				"id": "customfield_10002",
				"name": "Service Name",
				"type": "string",
				"value": "my-service",
			},
		],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_missing_deployment_id if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"customfield_10003": "https://github.com/org/repo/releases/tag/v1.0.0",
			"customfield_10002": "my-service",
		},
		"fields_with_metadata": [
			{
				"id": "customfield_10003",
				"name": "Release URL",
				"type": "string",
				"value": "https://github.com/org/repo/releases/tag/v1.0.0",
			},
			{
				"id": "customfield_10002",
				"name": "Service Name",
				"type": "string",
				"value": "my-service",
			},
		],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_missing_service_name if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"customfield_10003": "https://github.com/org/repo/releases/tag/v1.0.0",
			"customfield_10001": "deploy-123",
		},
		"fields_with_metadata": [
			{
				"id": "customfield_10003",
				"name": "Release URL",
				"type": "string",
				"value": "https://github.com/org/repo/releases/tag/v1.0.0",
			},
			{
				"id": "customfield_10001",
				"name": "Deployment ID",
				"type": "string",
				"value": "deploy-123",
			},
		],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_missing_all_fields if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name": "Change Request"}},
		"fields_with_metadata": [],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 3
}

test_pass_when_all_fields_present if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"customfield_10001": "deploy-123",
			"customfield_10002": "my-service",
			"customfield_10003": "https://github.com/org/repo/releases/tag/v1.0.0",
		},
		"fields_with_metadata": [
			{
				"id": "customfield_10001",
				"name": "Deployment ID",
				"type": "string",
				"value": "deploy-123",
			},
			{
				"id": "customfield_10002",
				"name": "Service Name",
				"type": "string",
				"value": "my-service",
			},
			{
				"id": "customfield_10003",
				"name": "Release URL",
				"type": "string",
				"value": "https://github.com/org/repo/releases/tag/v1.0.0",
			},
		],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_change_request if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {"issuetype": {"name": "Bug"}},
		"fields_with_metadata": [],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_fields_match_alternative_patterns if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-456",
		"fields": {
			"issuetype": {"name": "Change"},
			"customfield_10004": "deploy-456",
			"customfield_10005": "payment-service",
			"customfield_10006": "https://releases.example.com/v2.0.0",
		},
		"fields_with_metadata": [
			{
				"id": "customfield_10004",
				"name": "Deploy ID",
				"type": "string",
				"value": "deploy-456",
			},
			{
				"id": "customfield_10005",
				"name": "Application Name",
				"type": "string",
				"value": "payment-service",
			},
			{
				"id": "customfield_10006",
				"name": "Release Link",
				"type": "string",
				"value": "https://releases.example.com/v2.0.0",
			},
		],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
