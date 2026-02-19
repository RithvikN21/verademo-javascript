      package main
      import future.keywords
      
      policy := {
          "orgId": 109937,
          "policyId": "07fb8614-0b57-485d-aeab-1ab767da04bf",
          "policyRevision": 1,
          "requestDate": request_date(time.now_ns()),
          "policyPassed" : count(deny) == 0,
          "issuesCount": count(deny), 
          "issues": MAX_SEVERITY_MEDIUM_Configurations | MAX_SEVERITY_MEDIUM_Secrets | MAX_SEVERITY_MEDIUM_Vulnerabilities
      }
      
      
deny contains reason if { MAX_SEVERITY_MEDIUM_Configurations[reason] }
deny contains reason if { MAX_SEVERITY_MEDIUM_Secrets[reason] }
deny contains reason if { MAX_SEVERITY_MEDIUM_Vulnerabilities[reason] }
      
      MAX_SEVERITY_MEDIUM_Configurations contains issue if {
    some a, b
    input.configs.Results[a].Misconfigurations[b].Severity in  { "MEDIUM","HIGH","CRITICAL" }

    msg = sprintf(
      "Found %s issues in infrastructure as code: %s: %s",
      [ input.configs.Results[a].Misconfigurations[b].Severity,
        input.configs.Results[a].Target,
        input.configs.Results[a].Misconfigurations[b].Title
      ] )
    
    issue := buildIssueJson(
        msg,
        "MAX_SEVERITY",
        3.0,
        input.configs.Results[a].Misconfigurations[b].ID,
        input.configs.Results[a].Misconfigurations[b].PrimaryURL,
        3.0,
        input.configs.Results[a].Misconfigurations[b].Severity,
    )           
}
MAX_SEVERITY_MEDIUM_Secrets contains issue if {
    some a, b
    input.secrets.Results[a].Secrets[b].Severity in { "MEDIUM","HIGH","CRITICAL" }

    msg = sprintf(
      "Found %s issues in infrastructure as code: %s: %s",
      [ input.secrets.Results[a].Secrets[b].Severity,
        input.secrets.Results[a].Target,
        input.secrets.Results[a].Secrets[b].Title
      ] )
    
    issue := buildIssueJson(
        msg,
        "MAX_SEVERITY",
        3.0,
        input.secrets.Results[a].Secrets[b].RuleID,
        input.secrets.Results[a].Target,
        3.0,
        input.secrets.Results[a].Secrets[b].Severity,
    )           
}
MAX_SEVERITY_MEDIUM_Vulnerabilities contains issue if {
    some a
    input.vulnerabilities.matches[a].vulnerability.severity in { "Medium","High","Critical" }
    msg = sprintf(
        "Found %s software vulnerability: %s",
        [
            input.vulnerabilities.matches[a].vulnerability.severity,
            input.vulnerabilities.matches[a].vulnerability.id,
        ],
    )
    issue := buildIssueJson(
        msg,
        "MAX_SEVERITY",
        3.0,
        input.vulnerabilities.matches[a].vulnerability.id,
        input.vulnerabilities.matches[a].vulnerability.dataSource,
        3.0,
        input.vulnerabilities.matches[a].vulnerability.severity,
    )           
}
      
      ####################################################################
      ##                        HELPER FUNCTIONS                        ##
      ####################################################################
      request_date(now) := date_time if {
          current_date := time.date(now)
          current_time := time.clock(now)
          date_time := sprintf("%d-%d-%dT%d:%d:%d", [
              current_date[0],
              current_date[1],
              current_date[2],
              current_time[0],
              current_time[1],
              current_time[2],
          ])
      }

      buildIssueJson(
      	reference,
      	ruleType,
          apsSeverity,
      	id,
      	dataSource,
      	baseScore,
      	severity,
      ) := issueJson if {
      	issueJson := {
      		"msg": reference,
      		"ruleType": ruleType,
              "apsSeverity": apsSeverity,
      		"id": id,
      		"dataSource": dataSource,
      		"baseScore": baseScore,
      		"severity": severity,
      	}
      }
      