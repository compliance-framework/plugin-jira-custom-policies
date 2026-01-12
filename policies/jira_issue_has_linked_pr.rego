package compliance_framework.jira_issue_has_linked_pr

import future.keywords.if
import future.keywords.in

title := "Change requests must have pull request information"
description := "All change request issues must have pull request information in custom fields. A 2-week grace period is allowed from issue creation."

grace_period_seconds := 1209600

pr_field_patterns := ["pull request", "pr", "pull_request", "pullrequest", "merge request", "mr"]

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	count(project.issues) > 0
	issue := project.issues[_]
	is_change_request(issue)
	not has_pr_field(issue)
	is_past_grace_period(issue)
	remarks := sprintf("Issue %s does not have pull request information in custom fields (created more than 2 weeks ago).", [issue.key])
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

has_pr_field(issue) if {
	field := issue.fields_with_metadata[_]
	field_name_lower := lower(field.name)
	pattern := pr_field_patterns[_]
	contains(field_name_lower, pattern)
	field.value != null
	field.value != ""
}

has_pr_field(issue) if {
	some field_key, field_value in issue.fields
	field_name_lower := lower(field_key)
	pattern := pr_field_patterns[_]
	contains(field_name_lower, pattern)
	field_value != null
	field_value != ""
}

is_past_grace_period(issue) if {
	created := object.get(issue.fields, "created", "")
	created != ""
	created_time := time.parse_rfc3339_ns(created)
	current_time := time.now_ns()
	elapsed_seconds := (current_time - created_time) / 1000000000
	elapsed_seconds > grace_period_seconds
}

is_past_grace_period(issue) if {
	not object.get(issue.fields, "created", null)
}
