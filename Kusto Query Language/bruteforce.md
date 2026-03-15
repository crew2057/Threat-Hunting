## Objective
- First trace out the failed sign-in attempt spike.
- Alert on fasthttp useragent match and failure threshold in case of non-interactive sign-in attempts.
- Alert on failure threshold in case of interactive sign-in attempt.

## Detection Rule
<pre>
//Referencing file to get hold into CIDR value associated with IP.
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string)
['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
with (ignoreFirstRecord=true));
//For Removing DisabledUsers from search pool.
let DisabledUsers=IdentityInfo
| where IsAccountEnabled=="False"
| distinct tolower(AccountUpn);
//Bruteforce based on network spike and count of failures within certain time-bound.
let timephase= SigninLogs
|where ResultType in (50126,50155,50053,500121,70037)
|extend Phase=bin(TimeGenerated,1h)
|evaluate ipv4_lookup(CIDRASN,IPAddress,CIDR,return_unmatched=true)
|summarize Connections_x_phase=count() by UserPrincipalName, CIDR, Phase
|summarize AvgConnectionsPerPhase= avg(Connections_x_phase), MaxConnectionInPhase=max(Connections_x_phase), TotalConnections=sum(Connections_x_phase) by UserPrincipalName,CIDR;
let myFunc=(tableName:string ,check:bool){
table(tableName)
| project TimeGenerated, IPAddress, UserPrincipalName, ResultType, UserAgent, AppDisplayName, ResourceDisplayName, LocationDetails
| where ResultType in (50126,50155,50053,500121,70037) and tolower(UserPrincipalName) !in (DisabledUsers) and iff(check,UserAgent contains "fasthttp", true)
| evaluate ipv4_lookup(CIDRASN,IPAddress,CIDR,return_unmatched=true)
| lookup timephase on CIDR, UserPrincipalName
| where MaxConnectionInPhase >= AvgConnectionsPerPhase*3
| summarize FailedAttempts = count(), IPs=make_set(IPAddress),Timestamp=max(TimeGenerated),LocationDetails=make_set(LocationDetails),User_agents=make_set(UserAgent), Applications=make_set(AppDisplayName), Resources=make_set(ResourceDisplayName) by ReportId=hash_md5(strcat(UserPrincipalName,CIDR)),UserPrincipalName, CIDR
| where FailedAttempts >5;
};
let intSignon=myFunc("SigninLogs",false);
let nonIntSignon=myFunc("AADNonInteractiveUserSignInLogs",true);
union intSignon,nonIntSignon
</pre>

## Playbook

### Overview
The alert triggered because there was spike in failure attempts for the user from the particular CIDR and sign-in failure attempts crossed the threshold of 5 attempts.

### Resolve Process
- Check the sign-in events of the user.
    - Look for suspicious IPs and User_agents.
    - Check the applications and resources the user is trying to access.
    - Check timestamp for identifying frequency at which the sign-in attempts are being made.
- Check in MFA tool to see if there have been attempts of prompt bombing.

### Conclusion
If the above information points toward brute force attempts, perform following actions.

- If the IP or CIDR is not associated with the organization domain, cross check with third-party tools to see if they are flagged. If so, then add them to blocklist.
- If the attacker is able to guess the password and is conducting prompt bombing, then
    - Disable the user.
    - Alert user for password reset.
