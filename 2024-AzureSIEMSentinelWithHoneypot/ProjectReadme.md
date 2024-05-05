##   Tutorial on Youtube: [SIEM Tutorial for Beginner | Azure Sentinel Tutorial MAP with LIVE CYBER ATTACKS](https://www.youtube.com/watch?v=RoZeVbbZ0o0)
Project credit to Josh Madakore, a Youtuber that makes ton of great security videos.

## High Level Steps
1. Get an account for Azure, the Microsoft Cloud Service.
1. In Azure, create a Virtual Machine and this will be the Honeypot.
1. Configure the firewall rule of the Honeypot
    1. In Honeypot VM configuration, the NIC(Network Interface Card) Network Security Group, create a Network Security Group and configure the firewall rule to allow any source to connect to any destination of all ports.
    1. When login to the Honeypot, go to the firewall and turn them off for all of the profiles (Domain, Private & Public).
    1. Can verify through pinging the public IP Address.
    1. This configuration is juicy for the hackers all over the world, from a script kiddie to cybercriminals, and this will be the firewall for the Honeypot.
1. In Azure, create a Log Analytics Workspace, connects to the Honeypot to handle all the logs and do some data processing.
1. In Azure, enable the Honeypot's log from the Microsoft Defender for the Cloud, aka Security Center (the old name).
1. In Azure, create an Azure Sentinel (This is the SIEM tool in Azure) and add it to the Log Analytics Workspace.
1. Once the logs are flowing to the Sentinel, we will create a new workbook, add a query widget and use the query in Notes.8. to get all the required fields from the logs.
1. Configure the Azure Sentinel Workbook query, to visualize the data in a map view, set the parameters so the log data can be displayed as an attack heat map.

## Notes
1. The time I work on this Project is in April 2024.  Things may change from the past and in the future.
1. To connect to the Azure Windows virtual machine from my Macbook Air:
    1. Installed `Microsoft Remote Desktop`
    1. From Azure VM: click connect, select through RDP (Remote Desktop Protocol) and choose the Microsoft Remote Desktop
1. Inside the Honeypot, try to make one login with the wrong credentials so we can observe the behavior.
1. The logs on the Honeypot can be found from: Event Viewer > Windows Logs > Security.  The log contains the source IP which we will then use to discover the geolocation where the attack came from.
1. Use a 3rd party service provider: https://ipgeolocation.io to find the geolocation of the IP addresses.
1. Inside the Honeypot, turn off the firewall for all profiles (Domain, Private & Public)
1. Copy or download the powershell script to the Honeypot. [link](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1)  (Thanks Josh Madakore for sharing this!)
    1. The script is taking the Failed login attempts from the Security Log.
    1. Send the IP Address to the ipgeolocation API and get the geolocation, country, etc. information back.
    1. Store the geo information in a file that will then be handled by the Azure Log Analytics.
    1. Note this script is running a `while ($true)` loop, make sure to exit the script when you are done with capturing failed login and sending to the API.
1. Configure the query to grab the log we need and extract the required fields from the raw log data into custom fields for display:
```
  FAILED_RDP_WITH_GEO_CL
  | extend 
  timestamp = todatetime(extract("timestamp:(.*?),",1,RawData)),
  latitude = toreal(extract("latitude:(.*?),",1,RawData)),
  longitude = toreal(extract("longitude:(.*?),",1,RawData)),
  destinationhost = extract("destinationhost:(.*?),",1,RawData),
  username = extract("username:(.*?),",1,RawData),
  sourcehost = extract("sourcehost:(.*?),",1,RawData),
  state = extract("state:(.*?),",1,RawData),
  country = extract("country:(.*?),",1,RawData),
  label = extract("label:(.*?),",1,RawData)
  | project latitude, longitude, destinationhost, username, sourcehost, state, country, label, timestamp
```


 