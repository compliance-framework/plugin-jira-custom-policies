package compliance_framework.jira_issue_deployment_successful_test

import data.compliance_framework.jira_issue_deployment_successful as policy

test_violation_when_change_request_has_no_deployment_field if {
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
	count(violations) == 1
}

test_violation_when_deployment_field_is_empty if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"customfield_10003": "",
		},
		"fields_with_metadata": [{
			"id": "customfield_10003",
			"name": "Deployment ID",
			"type": "string",
			"value": "",
		}],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_change_request_has_deployment_field if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"customfield_10003": "deploy-12345",
		},
		"fields_with_metadata": [{
			"id": "customfield_10003",
			"name": "Deployment ID",
			"type": "string",
			"value": "deploy-12345",
		}],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_change_request_has_release_field if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-456",
		"fields": {
			"issuetype": {"name": "Change"},
			"customfield_10004": "https://github.com/org/repo/releases/tag/v1.0.0",
		},
		"fields_with_metadata": [{
			"id": "customfield_10004",
			"name": "Release URL",
			"type": "string",
			"value": "https://github.com/org/repo/releases/tag/v1.0.0",
		}],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_change_request_has_no_deployment if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {"issuetype": {"name": "Bug"}},
		"fields_with_metadata": [],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": null,
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_deploy_field_matches_pattern if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-789",
		"fields": {
			"issuetype": {"name": "Request a change"},
			"customfield_10005": "prod-deploy-2024-01-10",
		},
		"fields_with_metadata": [{
			"id": "customfield_10005",
			"name": "Deploy Reference",
			"type": "string",
			"value": "prod-deploy-2024-01-10",
		}],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
