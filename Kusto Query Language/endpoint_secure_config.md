## Objective
Perform necessary actions to secure endpoint devices by updating various configuration settings.

## Detection Rules
- **Devices on the network which are not on-boarded**
<pre>
DeviceTvmSecureConfigurationAssessment
| join kind=inner DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| where IsApplicable=="1" and IsCompliant!="1" and ConfigurationId =="scid-20000"
| project Timestamp,DeviceId,DeviceName, OSPlatform, ConfigurationId, ConfigurationName, ConfigurationDescription, RiskDescription, RemediationOptions
| sort by Timestamp
</pre>
- **On-boarded Devices having Defender real-time protection disabled or Defender Antivirus not as the primary antivirus solution.**
<pre>
DeviceEvents
| join kind=innerunique DeviceTvmSecureConfigurationAssessment on DeviceId
| where ConfigurationId in ("scid-2012","scid-5090","scid-6090")
| where IsApplicable=="1" and IsCompliant!="1"
| lookup DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| project Timestamp,ReportId,DeviceId,DeviceName, OSPlatform, ConfigurationId, ConfigurationName, ConfigurationDescription, RiskDescription, RemediationOptions
| sort by Timestamp
</pre>
- **On-boarded Devices on network not satisfying secure configuration with high impact of 10.**
<pre>
DeviceEvents
| join kind=innerunique DeviceTvmSecureConfigurationAssessment on DeviceId
| where IsApplicable=="1" and IsCompliant!="1" and ConfigurationImpact =="10"
| lookup DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| project Timestamp,ReportId,DeviceId,DeviceName, OSPlatform, ConfigurationId, ConfigurationImpact, ConfigurationName, ConfigurationDescription, RiskDescription, RemediationOptions
| sort by Timestamp
</pre>

## Playbook
Remediation Options are provided by Defender for each detection rule and we have projected it to be accessible for users.

_**References:**_
- https://learn.microsoft.com/en-us/answers/questions/1836965/kql-query-works-in-editor-but-not-in-custom-detect
