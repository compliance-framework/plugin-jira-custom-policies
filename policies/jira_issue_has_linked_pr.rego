package compliance_framework.jira_issue_has_linked_pr

import future.keywords.if
import future.keywords.in

title := "Change requests must have pull request information"
description := "All change request issues must have pull request information in custom fields. A 2-week grace period is allowed from issue creation."

grace_period_seconds := 1209600

pr_field_patterns := ["pull request", "pr", "pull_request", "pullrequest", "merge request", "mr"]

risk_templates := [{
  "name": "Change request has no linked pull request",
  "title": "Unlinked PRs Break Traceability Between Code Changes and Approved Changes",
  "statement": "A change request without a linked pull request cannot be verified to correspond to actual code changes that went through code review. Without this link, it is impossible to confirm that the code merged to production matches the approved change scope, that the code was peer-reviewed, or that security scanning passed. This breaks the end-to-end audit trail from issue approval to code delivery. A two-week grace period is allowed after creation.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1059",
      "title": "Incomplete Documentation",
      "url": "https://cwe.mitre.org/data/definitions/1059.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    }
  ],
  "remediation": {
    "title": "Link pull requests to all change request issues",
    "description": "Ensure every change request has at least one linked pull request to maintain traceability between approved changes and the actual code delivered. Automate this link via branch naming conventions or PR title patterns.",
    "tasks": [
      { "title": "Identify all change requests older than 2 weeks without a linked PR and add the missing link" },
      { "title": "Enforce a branch naming or PR title convention that includes the Jira issue key (e.g., CR-123)" },
      { "title": "Enable the Jira GitHub/Bitbucket integration to automatically link PRs mentioning the issue key" },
      { "title": "Add a workflow validator or Jira automation that flags CRs transitioning to 'Done' without a PR link" },
      { "title": "Configure PR templates to prompt developers to include the Jira issue key" }
    ]
  }
}]

violation[{"id": "missing_linked_pr", "remarks": remarks}] if {
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
