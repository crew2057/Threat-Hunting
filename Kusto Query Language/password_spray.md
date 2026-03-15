## Objective
Monitor login failures from same IP targeting multiple users:
- Look for spike in sign-in attempts from the IP
- Filter the Sign-in failure events and count distinct users targeted based on IP.
- Alert if the particular IP targeted more than 5 accounts and have more than 5 failure attempts within an hour.

## Detection Rule
<pre>
let DisabledUsers=IdentityInfo
| where IsAccountEnabled=="False"
| distinct tolower(AccountUpn);
let timephase= SigninLogs
|where ResultType in (50126,50155,50053,500121,70037) and tolower(UserPrincipalName) !in (DisabledUsers) 
|extend Phase=bin(TimeGenerated,1h)
|summarize Connections_x_phase=count() by IPAddress, Phase
|summarize AvgConnectionsPerPhase=avg(Connections_x_phase), Connections_x_phase = max(Connections_x_phase) by IPAddress;
SigninLogs
| where ResultType in (50126,50155,50053,500121,70037) and tolower(UserPrincipalName) !in (DisabledUsers) 
| lookup timephase on IPAddress
| where Connections_x_phase >= AvgConnectionsPerPhase*3
| summarize Timestamp=max(TimeGenerated), AccountsTargeted = dcount(UserPrincipalName),Account_set=make_set(UserPrincipalName),FailedAttempts = count(),FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by ReportId=hash_md5(IPAddress), IPAddress, UserAgent
| where AccountsTargeted > 5
</pre>

## Playbook
### Overview
The alert was triggered because there was spike in sign-in failure attempts from particular IP and the failed attempts were made for 5 different users (our threshold).

### Resolve Process
- Check for suspicious IP and user agent associated with the incident.
- Check if there was successful sign-in but MFA failure to the impacted users within certain timeframe.
- Look into MFA tool and sign-in logs of the users  who have received received MFA authentication prompts.

### Conclusion
If found suspicious,

- Given, IP doesn’t belong to organization domain, cross check with third party tools if it has been flagged. If so, add that IP to endpoint IOC blocklist.
- If the user is found to be targeted with prompt bombing,
    - Disable User account
    - Prompt user for password reset.
