---
title: Engineering Custom Detection Rules in Wazuh Using Sysmon Telemetry
date: August 4, 2024
---
This project examines how endpoint telemetry from Sysmon can be used to build custom detection logic in Wazuh. The focus was on constructing rules that analyze Windows process, network, file, and registry events and convert them into meaningful alerts through structured conditions and contextual filtering.

The test environment consisted of:
- Windows endpoints running Sysmon with the **SwiftOnSecurity configuration**
- Wazuh agents forwarding events from the **Sysmon Operational channel**
- A centralized Wazuh manager responsible for evaluating custom detection rules

Within this environment, Sysmon-generated events were ingested, decoded, and evaluated through Wazuh rule logic. The objective was to design detections that operate on specific event attributes and behavioral patterns rather than simple keyword matching.
This approach allows raw Windows telemetry to be interpreted as actionable security signals by combining event field matching, contextual conditions, and frequency-based escalation.

## Telemetry Foundation: Sysmon Integration

Sysmon was deployed using the SwiftOnSecurity configuration to provide granular telemetry across:
- Event ID 1 – Process Creation
- Event ID 3 – Network Connection
- Event ID 11 – File Creation
- Event ID 12/13/14 – Registry Operations

The Wazuh agent was configured to ingest:

```
Microsoft-Windows-Sysmon/Operational
```

Wazuh evaluates Sysmon telemetry through decoded fields extracted from the event XML (for example `win.eventdata.image`, `win.eventdata.parentImage`, and `win.eventdata.commandLine`). All detections in this project are built on these decoded fields to ensure the rule logic stays consistent and testable.

![Image](https://imgur.com/j6Xsoe6.png)
*Figure 1. Sysmon configuration loaded (snippet showing active rules).*

![Image](https://imgur.com/6DBbDts.png)
*Figure 2. Started Wazuh service and modified config*

Wazuh does not interpret raw Windows event semantics directly; it depends on decoders to extract structured fields from Sysmon’s XML output. If those fields are not parsed correctly, rule conditions will fail or behave unpredictably. All detections in this project rely strictly on decoded field matching rather than raw XML string inspection.

## Detection Engineering Use Cases

Each use case below was treated as an independent detection problem.
The emphasis was on:
- Behavioral reasoning
- Event semantics
- False positive control
- Escalation via repetition

## Use Case 1: Microsoft Management Console (MMC) Abuse

### Threat Context

`mmc.exe` is a signed Microsoft binary used to launch administrative snap-ins (`.msc` files) such as Event Viewer, Services, and Computer Management. In enterprise environments it is commonly executed interactively by administrators. The binary itself is not suspicious. The signal lies in execution pattern and context.
Repeated execution of `mmc.exe` within short intervals may indicate scripted enumeration, privilege validation, or automated inspection activity during post-compromise operations. Attackers frequently leverage native administrative tools to avoid introducing new binaries to disk.
### Detection Strategy
The base rule monitors Sysmon Event ID 1 (Process Creation) where:

```
Image = mmc.exe
```

This captures every execution instance regardless of snap-in type.

The alert description includes:

```
$(win.eventdata.commandLine)
```

This is deliberate. The command line reveals which `.msc` snap-in was launched (e.g., `eventvwr.msc`, `services.msc`). Without embedding this field, an analyst would need to pivot into the raw event to determine intent. Embedding the decoded command line reduces triage steps and allows immediate differentiation between routine administrative access and potentially broad system inspection.

![Image](https://imgur.com/R7dd4UF.png)
*Figure 3. Wazuh rule that detects Microsoft Management Console launch*

![Image](https://imgur.com/XxUg6dJ.png)
*Figure 4. Alert for MMC launch with command line details in Wazuh web interface.*
### Frequency-Based Escalation
In most environments, isolated MMC execution is expected behavior. Alerting on every instance would create noise.

To address this, a secondary rule was chained using:

```
frequency="5"
timeframe="120"
```

The rule triggers when five MMC executions occur within a two-minute window.

This threshold was selected to detect rapid sequential invocation consistent with scripted or automated activity, rather than manual administrative use. Manual interaction typically involves longer intervals between executions.
The escalation rule increases severity only when repetition exceeds the defined threshold. A single execution generates low-priority visibility. Repeated execution shifts the event into abnormal behavior territory.

![Image](https://imgur.com/uih8fzD.png)
*Figure 5. Wazuh rule that detects multiple MMC process creations in 2 min*

![Image](https://imgur.com/XAZYm5q.png)
*Figure 6. Alerts showing detection of multiple MMC processes.*

The intent is not to flag the binary itself, but to detect abnormal execution density over time.

## Use Case 2: DNS Evasion via Unauthorized Resolver

### Threat Context
Endpoint malware often bypasses internal DNS infrastructure by sending queries directly to public resolvers such as:
- 8.8.8.8
- 1.1.1.1    

This technique allows command-and-control domains to be resolved without passing through corporate DNS logging infrastructure. When DNS queries bypass internal resolvers, security teams lose visibility into domain resolution patterns that may indicate beaconing or malware staging.
In environments where endpoints are expected to use a designated internal DNS server, direct queries to external resolvers represent a deviation from normal network behavior.

### Detection Construction
The rule targets **Sysmon Event ID 3 (Network Connection)**, which records outbound network connections initiated by processes on the host.

The detection logic evaluates three conditions:
- `Protocol = udp`
- `DestinationPort = 53`
- `DestinationIp != 172.16.3.100`

`172.16.3.100` represents the authorized internal DNS resolver for the environment. Any UDP connection to port 53 that does not target this resolver is treated as suspicious.

All three conditions must be satisfied simultaneously.

This structure prevents the rule from generating alerts for:
- Legitimate internal DNS queries
- Non-DNS UDP traffic
- Connections where port 53 is used for unrelated services

![Image](https://imgur.com/kaBemc5.png)
*Figure 7. Rule for detecting outbound UDP connection to port 53 with destination other than 172.16.3.100*

![Image](https://imgur.com/uXa7BtW.png)
*Figure 8. Alert - Outbound UDP connection detected to port 53*

The alert description incorporates the decoded field:

```
$(win.eventdata.destinationIp)
```

Including this field allows analysts to immediately see which resolver the endpoint contacted without manually inspecting the raw Sysmon event.
This detection relies on decoded Sysmon fields rather than pattern matching within raw XML, ensuring rule conditions operate on structured network telemetry. 
In production environments, static IP filtering would typically be replaced with an allowlist containing all approved DNS resolvers used by the organization.

## Use Case 3: Suspicious Command Execution Outside Expected Parent

### Threat Context
Utilities such as:
- `ipconfig`
- `net`
- `net1`
- `ping`
- `nslookup`
- `netsh`

are commonly used during system and network reconnaissance. They expose information about network configuration, domain relationships, active connections, and routing behavior. These commands are also routinely used by administrators and normal users. Because of this, the command name itself is not a reliable detection signal.

The execution context provides the meaningful indicator. Under normal conditions, these utilities are launched from interactive shells such as `cmd.exe` or `powershell.exe`. When they appear as child processes of unrelated applications, for example a document viewer, browser, or custom binary, the behavior becomes suspicious. This pattern may occur when malware executes reconnaissance commands through process injection, macro execution, or abuse of legitimate binaries.

### Detection Logic
The detection rule evaluates **Sysmon Event ID 1 (Process Creation)**.

Three conditions are applied:
- `Image` matches one of the monitored utilities (`ipconfig`, `net`, `net1`, `ping`, `nslookup`, `netsh`)
- `ParentImage` **does not equal** `cmd.exe`
- `ParentImage` **does not equal** `powershell.exe`

This logic isolates executions where these commands are launched by unexpected parent processes.

![Image](https://imgur.com/WoMREIa.png)
*Figure 9. Rule for detecting suspicious command*

![Image](https://imgur.com/ckGGJaO.png)
*Figure 10. Alert for suspicious command executions*

Using negative parent matching removes the majority of legitimate administrative activity while preserving visibility into commands executed through abnormal process chains. The rule therefore focuses on execution context rather than simply detecting the presence of the command itself.

## Use Case 4: Suspicious Executable Staging via PowerShell

### Threat Context
PowerShell is frequently used by attackers to download or generate payloads during the early stages of compromise. One common pattern involves writing executable files to user-accessible directories before launching them.
A single executable file creation is not inherently suspicious. Administrative scripts, software installers, and development workflows can legitimately generate executables.
The risk increases when PowerShell repeatedly writes executable files within a short timeframe. This pattern is consistent with automated payload staging, download-and-execute workflows, or droppers unpacking multiple binaries to disk.

### Base Rule
The base rule monitors **Sysmon Event ID 11 (File Creation)**.

Two conditions are applied:
- `ParentImage = powershell.exe`
- `TargetFilename` ends with `.exe`

This captures situations where PowerShell directly writes executable files to disk.

![Image](https://imgur.com/32aQ7Bg.png)
*Figure 11. Rule for detecting single and multiple suspicious file activities*

![Image](https://imgur.com/4A2vOF3.png)
*Figure 12. Alerts for suspicious file activities.*

The alert provides visibility into individual executable creations initiated by PowerShell without immediately assigning high severity.

### Escalation Rule
A second rule applies a frequency threshold to identify repeated executable creation events within a short timeframe. This escalation rule triggers when multiple `.exe` files are created by PowerShell within the defined interval.

![Image](https://imgur.com/K4GkKO8.png)
*Figure 13. Alerts for multiple suspicious file activities.*

The intent is to separate isolated file creation events from repeated staging activity that is more consistent with automated payload deployment.

## Use Case 5: Registry Deletion Burst Detection

### Threat Context
Registry modifications and deletions occur regularly during normal system and application activity. Software installers, uninstallers, and configuration updates frequently remove registry keys as part of their lifecycle. However, large numbers of registry deletions occurring within a short time window can indicate abnormal activity. Attackers may delete registry entries when removing persistence mechanisms, disabling defensive controls, or cleaning artifacts after executing malicious code.
Examples include removing **Run/RunOnce persistence keys**, deleting security configuration values, or clearing traces of previously executed payloads. 
Because isolated registry deletions are common, detection must focus on abnormal volume rather than individual events.

### Rule Architecture
The detection logic uses a two-stage rule structure:

The base rule monitors **Sysmon registry deletion events** and generates a low-severity alert for visibility. This provides awareness of individual registry deletions without assuming malicious intent.

![Image](https://imgur.com/G2QV2HR.png)
*Figure 14. Rule for detecting registry key deletions*

![Image](https://imgur.com/mMmBQTL.png)
*Figure 15. Alerts showing registry key deletions (both legitimate and suspicious)*


A second rule applies a **frequency threshold**, triggering when multiple registry deletion events occur within a defined timeframe.

![Image](https://imgur.com/sJEHxCS.png)
*Figure 16. Alert showing multiple registry key deletions*

This escalation model distinguishes routine registry cleanup from rapid deletion patterns that may indicate persistence removal or post-exploitation activity.

## Detection Engineering Principles Demonstrated

Across the implemented use cases, several detection design principles were applied when constructing the Wazuh rules.
#### **Field-level matching**
All rule conditions operate on decoded Sysmon fields such as `win.eventdata.image`, `parentImage`, and `destinationIp`. Matching against structured fields is more reliable than searching raw XML event content and allows rules to evaluate specific attributes of the event.

#### **Dynamic context in alerts**
Relevant decoded fields are embedded directly into alert descriptions. This allows analysts to see important details, such as command line arguments or destination IP addresses, without opening the raw log entry. Providing contextual information inside the alert reduces investigation steps during triage.
#### **Process relationship analysis**
Several detections rely on parent-child process relationships. Evaluating the parent process provides additional context about how a command was launched, allowing the rule to differentiate normal interactive use from execution triggered by unrelated applications.

#### **Multi-condition rule logic**
Most detections combine multiple event attributes rather than relying on a single indicator. For example, network detections evaluate protocol, destination port, and destination IP simultaneously. This reduces false positives by ensuring alerts are generated only when multiple behavioral conditions are satisfied.

#### **Frequency-based behavioral thresholds**
Certain behaviors are only suspicious when repeated within a short timeframe. Frequency thresholds were used to detect bursts of activity, such as repeated administrative tool launches or rapid file creation events.

#### **Severity escalation**
Base rules provide visibility into individual events. Escalation rules increase alert severity when event frequency crosses a defined threshold. This structure helps separate routine activity from patterns that may indicate automated or scripted behavior.
The rules were validated by executing both benign and suspicious scenarios to verify rule behavior. Legitimate administrative activity was tested to confirm that alerts were not generated unnecessarily, while scripted or repeated actions were used to trigger escalation conditions.

## Limitations

The environment used for testing did not reflect the telemetry diversity typically present in production enterprise networks.

Several limitations should be considered:
- The DNS detection relies on a **static resolver allowlist**, which would not scale well in environments with multiple internal DNS servers
- Endpoint software diversity was limited, which restricts the ability to evaluate false positives caused by legitimate applications
- Testing was performed on a small number of hosts rather than across high-volume endpoint telemetry    
- The detections operate as standalone rules and were not correlated with additional host or network telemetry sources

In a production deployment, several adjustments would be necessary:
- Establishing baseline behavioral patterns across endpoints
- Maintaining dynamic allowlists for infrastructure services such as DNS
- Tuning alert severity and thresholds based on real telemetry volume
- Evaluating rule performance under high log ingestion rates

## Conclusion

This project focuses on constructing custom Wazuh detection rules using Sysmon telemetry as the primary data source. Rather than relying on prebuilt detection content, the rules were designed around specific behavioral patterns observed in endpoint activity. Each rule evaluates structured event fields, applies contextual filtering where appropriate, and uses frequency thresholds to identify abnormal repetition.

The resulting detections illustrate how endpoint telemetry can be converted into actionable alerts while controlling noise through rule logic and contextual conditions.