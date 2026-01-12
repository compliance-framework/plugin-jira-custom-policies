package compliance_framework.jira_issue_has_linked_pr_test

import data.compliance_framework.jira_issue_has_linked_pr as policy

test_violation_when_change_request_has_no_pr_field if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"created": old_date,
		},
		"fields_with_metadata": [],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_pr_field_is_empty if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"created": old_date,
			"customfield_10001": "",
		},
		"fields_with_metadata": [{
			"id": "customfield_10001",
			"name": "Pull Request URL",
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

test_pass_when_change_request_has_pr_field if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"created": old_date,
			"customfield_10001": "https://github.com/org/repo/pull/1",
		},
		"fields_with_metadata": [{
			"id": "customfield_10001",
			"name": "Pull Request URL",
			"type": "string",
			"value": "https://github.com/org/repo/pull/1",
		}],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_change_request_has_no_pr if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {
			"issuetype": {"name": "Bug"},
			"created": old_date,
		},
		"fields_with_metadata": [],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_change_request_within_grace_period if {
	recent_date := time.format(time.add_date(time.now_ns(), 0, 0, -5))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-789",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"created": recent_date,
		},
		"fields_with_metadata": [],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_pr_field_matches_pattern if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-456",
		"fields": {
			"issuetype": {"name": "Change"},
			"created": old_date,
			"customfield_10002": "PR-123",
		},
		"fields_with_metadata": [{
			"id": "customfield_10002",
			"name": "Merge Request ID",
			"type": "string",
			"value": "PR-123",
		}],
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
