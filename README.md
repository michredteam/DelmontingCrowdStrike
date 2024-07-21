
![212748830-4c709398-a386-4761-84d7-9e10b98fbe6e](https://github.com/user-attachments/assets/f73e24fc-3b8b-4df2-bf34-f1e4f8b18f0c)

CrowdStrike suffered an error in their Falcon driver on Friday, July 19, 2024, due to human error. The failure to check the status of a pointer caused BSODs (Blue Screen of Death) worldwide for those with the enterprise solution installed.



## Error Cause

So what happened is that the programmer forgot to check that the object it's working with isn't valid, it tried to access one of the objects member variables...


NULL + 0x9C = 0x9C = 156

That's an invalid region of memory.

And what's bad about this is that this is a special program called a system driver, which has PRIVLIDGED access to the computer. So the operating system is forced to, out of an abundance of caution, crash immediately

If the programmer had done a check for NULL, or if they used modern tooling that checks these sorts of things, it could have been caught. But somehow it made it into production and then got pushed as a forced update by Crowdstrike... OOPS!

### Life Lesson: 

Rewriting their system driver from its current state in C++ to a more modern language like Rust, which doesn't have this problem.

## Details:

Symptoms include hosts experiencing a bugcheck or blue screen error related to the Falcon sensor. Windows hosts that have not been impacted do not require any action as the problematic channel file has been reverted. Windows hosts that are brought online after 0527 UTC will also not be impacted.

This issue is not affecting Mac- or Linux-based hosts.

Channel file "C-00000291*.sys" with a timestamp of 0527 UTC or later is the reverted (good) version. Channel file "C-00000291*.sys" with a timestamp of 0409 UTC is the problematic version.

Note: It is normal for multiple "C-00000291*.sys" files to be present in the CrowdStrike directory. As long as one of the files in the folder has a timestamp of 0527 UTC or later, that will be the active content.

It helps identify if an endpoint received a specific configuration file during an impacted time window and if it was online during that period.

```
// Get ConfigStateUpdate and SensorHeartbeat events
#event_simpleName=/^(ConfigStateUpdate|SensorHeartbeat)$/
event_platform=Win
// Narrow search to Channel File 291 and extract version number; accept
all SensorHeartbeat events
| case{
#event_simpleName=ConfigStateUpdate | regex("\|1,123,(?
<CFVersion>.*?)\|", field=ConfigStateData, strict=false) |
parseInt(CFVersion, radix=16);
#event_simpleName=SensorHeartbeat | rename([[@timestamp, LastSeen]]);
}
// Restrict results to hosts that were online during impacted time window
| case{
#event_simpleName=ConfigStateUpdate | @timestamp>1721362140000 AND
@timestamp < 1721366820000 | CSUcounter:=1;
#event_simpleName=SensorHeartbeat | LastSeen>1721362140000 AND
LastSeen<1721366820000 | SHBcounter:=1;
*;
}
| default(value="0", field=[CSUcounter, SHBcounter])
// Make sure both ConfigState update and SensorHeartbeat have happened
| selfJoinFilter(field=[cid, aid, ComputerName], where=
[{ConfigStateUpdate}, {SensorHeartbeat}])
// Aggregate results
| groupBy([cid, aid], function=([{selectFromMax(field="@timestamp",
include=[CFVersion])}, {selectFromMax(field="@timestamp", include=
[@timestamp]) | rename(field="@timestamp", as="LastSeen")},
max(CSUcounter, as=CSUcounter), max(SHBcounter, as=SHBcounter)]),
limit=max)
// Perform check on selfJoinFilter
| CFVersion=* LastSeen=*
// ////////////////////////////////////////////////////////// //
// UPDATE THE LINE BELOW WITH THE IMPACTED CHANNEL FILE NUMBER //
// ////////////////////////////////////////////////////////// //
| in(field="CFVersion", values=[0,31])
// Calculate time between last seen and now
| LastSeenDelta:=now()-LastSeen
// Optional threshold; 3600000 is one hour; this can be adjusted
| LastSeenDelta>3600000
// Calculate duration between last seen and now
| LastSeenDelta:=formatDuration("LastSeenDelta", precision=2)
// Convert LastSeen time to human-readable format
| LastSeen:=formatTime(format="%F %T", field="LastSeen")
// Enrich aggregation with aid_master details
| aid=~match(file="aid_master_main.csv", column=[aid])
| aid=~match(file="aid_master_details.csv", column=[aid], include=
[FalconGroupingTags, SensorGroupingTags])
// Convert FirstSeen time to human-readable format
| FirstSeen:=formatTime(format="%F %T", field="FirstSeen")
// Move ProductType to human-readable format and add formatting
| $falcon/helper:enrich(field=ProductType)
| drop([Time])
| default(value="-", field=[MachineDomain, OU, SiteName,
FalconGroupingTags, SensorGroupingTags], replaceEmpty=true)
// Create conditions to check for impact
| case{
LastSeenDelta>3600000 | Details:="OK: Endpoint seen in past
hour.";
CSUcounter=0 AND SHBcounter=0 | Details:="OK: Endpoint did not receive
channel file during impacted window. Endpoint was offline.";
CSUcounter=0 AND SHBcounter=1 | Details:="OK: Endpoint did not receive
channel file during impacted window. Endpoint was online.";
CSUcounter=1 AND SHBcounter=1 | Details:="CHECK: Endpoint received
channel file during impacted window. Endpoint was online. Endpoint has not
been seen online in past hour.";
}
// Create one final groupBy for easier export to CSV
| groupBy([cid, aid, ComputerName, LastSeen, CFVersion, LastSeenDelta,
Details, AgentVersion, aip, event_platform, FalconGroupingTags,
LocalAddressIP4, MAC, MachineDomain, OU, ProductType, SensorGroupingTags,
SiteName, SystemManufacturer,SystemProductName, Version], limit=max)

```
## In Azure: 
```
az vm run-command create --name "myRunCommand" --vm-name $myVM --resource-group $myRG --script "Remove-Item C:\Windows\System32\drivers\CrowdStrike\C-00000291*.sys -Force"
```
