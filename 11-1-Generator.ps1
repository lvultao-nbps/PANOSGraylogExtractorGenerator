#Requires -version 7
#This script will generate the JSON extractor needed to parse PAN-OS syslog into something useful in Graylog
#Strings are taken from https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions.html
#credit: https://github.com/jamesfed/PANOSGraylogExtractorGenerator/blob/master/10-1-Generator.ps1
$PANOSVersion = "11.1"
$OutputPath = "C:\Temp\$PANOSVersion.json"

#Get the strings into objects
#from 11.1 docs
$SyslogDefinitions = @(
    @{
        LogType        = "Traffic"          
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, Protocol, Action, Bytes, Bytes Sent, Bytes Received, Packets, Start Time, Elapsed Time, Category, FUTURE_USE, Sequence Number, Action Flags, Source Country, Destination Country, FUTURE_USE, Packets Sent, Packets Received, Session End Reason, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Action Source, Source VM UUID, Destination VM UUID, Tunnel ID/IMSI, Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type, SCTP Association ID, SCTP Chunks, SCTP Chunks Sent, SCTP Chunks Received, Rule UUID, HTTP/2 Connection, App Flap Count, Policy ID, Link Switches, SD-WAN Cluster, SD-WAN Device Type, SD-WAN Cluster Type, SD-WAN Site, Dynamic User Group Name, XFF Address, Source Device Category, Source Device Profile, Source Device Model, Source Device Vendor, Source Device OS Family, Source Device OS Version, Source Hostname, Source Mac Address, Destination Device Category, Destination Device Profile, Destination Device Model, Destination Device Vendor, Destination Device OS Family, Destination Device OS Version, Destination Hostname, Destination Mac Address, Container ID, POD Namespace, POD Name, Source External Dynamic List, Destination External Dynamic List, Host ID, Serial Number, Source Dynamic Address Group, Destination Dynamic Address Group, Session Owner, High Resolution Timestamp, A Slice Service Type, A Slice Differentiator, Application Subcategory, Application Category, Application Technology, Application Risk, Application Characteristic, Application Container, Tunneled Application, Application SaaS, Application Sanctioned State, Offloaded, Flow Type, Cluster Name, AI Traffic, AI Forward Error, K8S Cluster ID, tcp_rtt_c2s, tcp_rtt_s2c, total_n_ooseq_c2s, total_n_ooseq_s2c, tcp_retransit_cnt_c2s, tcp_retransit_cnt_s2c, tcp_zero_window_cnt_c2s, tcp_zero_window_cnt_s2c, Source Adv DevID, Destination Adv DevID".Split(",")
        matchCondition = ",TRAFFIC,"
    },
    @{
        LogType        = "Threat"           
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, IP Protocol, Action, URL/Filename, Threat ID, Category, Severity, Direction, Sequence Number, Action Flags, Source Location, Destination Location, FUTURE_USE, Content Type, PCAP_ID, File Digest, Cloud, URL Index, User Agent, File Type, X-Forwarded-For, Referer, Sender, Subject, Recipient, Report ID, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, FUTURE_USE, Source VM UUID, Destination VM UUID, HTTP Method, Tunnel ID/IMSI, Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type, Threat Category, Content Version, FUTURE_USE, SCTP Association ID, Payload Protocol ID, HTTP Headers, URL Category List, Rule UUID, HTTP/2 Connection, Dynamic User Group Name, XFF Address, Source Device Category, Source Device Profile, Source Device Model, Source Device Vendor, Source Device OS Family, Source Device OS Version, Source Hostname, Source MAC Address, Destination Device Category, Destination Device Profile, Destination Device Model, Destination Device Vendor, Destination Device OS Family, Destination Device OS Version, Destination Hostname, Destination MAC Address, Container ID, POD Namespace, POD Name, Source External Dynamic List, Destination External Dynamic List, Host ID, Serial Number, Domain EDL, Source Dynamic Address Group, Destination Dynamic Address Group, Partial Hash, High Resolution Timestamp, Reason, Justification, A Slice Service Type, Application Subcategory, Application Category, Application Technology, Application Risk, Application Characteristic, Application Container, Tunneled Application, Application SaaS, Application Sanctioned State, Cloud Report ID, Flow Type, Cluster Name".Split(",")
        matchCondition = ",THREAT,(?!url|data|dlp|file)[^,]*," #all other threat not url or data filtering
    },
    @{
        LogType        = "URLFiltering"         
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, IP Protocol, Action, URL/Filename, Threat ID, Category, Severity, Direction, Sequence Number, Action Flags, Source Country, Destination Country, FUTURE_USE, Content Type, PCAP_ID, File Digest, Cloud, URL Index, User Agent, File Type, X-Forwarded-For, Referer, Sender, Subject, Recipient, Report ID, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, FUTURE_USE, Source VM UUID, Destination VM UUID, HTTP Method, Tunnel ID/IMSI, Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type, Threat Category, Content Version, FUTURE_USE, SCTP Association ID, Payload Protocol ID, HTTP Headers, URL Category List, Rule UUID, HTTP/2 Connection, Dynamic User Group Name, XFF Address, Source Device Category, Source Device Profile, Source Device Model, Source Device Vendor, Source Device OS Family, Source Device OS Version, Source Hostname, Source MAC Address, Destination Device Category, Destination Device Profile, Destination Device Model, Destination Device Vendor, Destination Device OS Family, Destination Device OS Version, Destination Hostname, Destination MAC Address, Container ID, POD Namespace, POD Name, Source External Dynamic List, Destination External Dynamic List, Host ID, Serial Number, Domain EDL, Source Dynamic Address Group, Destination Dynamic Address Group, Partial Hash, High Resolution Timestamp, Reason, Justification, A Slice Service Type, Application Subcategory, Application Category, Application Technology, Application Risk, Application Characteristic, Application Container, Tunneled Application, Application SaaS, Application Sanctioned State, Cloud Report ID, Cluster Name, Flow Type".Split(",")
        matchCondition = ",THREAT,url,"
    },
    @{
        LogType        = "DataFiltering"        
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, IP Protocol, Action, URL/Filename, Threat ID, Category, Severity, Direction, Sequence Number, Action Flags, Source Country, Destination Country, FUTURE_USE, Content Type, PCAP_ID, File Digest, Cloud, URL Index, User Agent, File Type, X-Forwarded-For, Referer, Sender, Subject, Recipient, Report ID, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, FUTURE_USE, Source VM UUID, Destination VM UUID, HTTP Method, Tunnel ID/IMSI, Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type, Threat Category, Content Version, FUTURE_USE, SCTP Association ID, Payload Protocol ID, HTTP Headers, URL Category List, Rule UUID, HTTP/2 Connection, Dynamic User Group Name, XFF Address, Source Device Category, Source Device Profile, Source Device Model, Source Device Vendor, Source Device OS Family, Source Device OS Version, Source Hostname, Source MAC Address, Destination Device Category, Destination Device Profile, Destination Device Model, Destination Device Vendor, Destination Device OS Family, Destination Device OS Version, Destination Hostname, Destination MAC Address, Container ID, POD Namespace, POD Name, Source External Dynamic List, Destination External Dynamic List, Host ID, Serial Number, Domain EDL, Source Dynamic Address Group, Destination Dynamic Address Group, Partial Hash, High Resolution Timestamp, Reason, Justification, A Slice Service Type, Application Subcategory, Application Category, Application Technology, Application Risk, Application Characteristic, Application Container, Tunneled Application, Application SaaS, Application Sanctioned State, Cloud Report ID, Cluster Name, Flow Type".Split(",")
        matchCondition = ",THREAT,(data|dlp|dlp-non-file|file),"
    },
    @{
        LogType        = "HIPMatch"             
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source User, Virtual System, Machine Name, Operating System, Source Address, HIP, Repeat Count, HIP Type, FUTURE_USE, FUTURE_USE, Sequence Number, Action Flags, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Virtual System ID, IPv6 Source Address, Host ID, User Device Serial Number, Device MAC Address, High Resolution Timestamp, Cluster Name".Split(",")
        matchCondition = ",HIP-MATCH,"
    },
    @{
        LogType        = "GlobalProtect"        
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Virtual System, Event ID, Stage, Authentication Method, Tunnel Type, Source User, Source Region, Machine Name, Public IP, Public IPv6, Private IP, Private IPv6, Host ID, Serial Number, Client Version, Client OS, Client OS Version, Repeat Count, Reason, Error, Description, Status, Location, Login Duration, Connect Method, Error Code, Portal, Sequence Number, Action Flags, High Res Timestamp, Selection Type, Response Time, Priority, Attempted Gateways, Gateway, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Virtual System ID, Cluster Name".Split(",")
        matchCondition = ",GLOBALPROTECT,"
    },
    @{
        LogType        = "IPTag"                
        format         = "FUTURE_USE , Receive Time, Serial, Type, Threat/Content Type, FUTURE_USE, Generate Time, Virtual System, Source IP, Tag Name , Event ID, Repeat Count , Timeout, Data Source Name, Data Source Type, Data Source Subtype, Sequence Number, Action Flags, DG Hierarchy Level 1 , DG Hierarchy Level 2, DG Hierarchy Level 3, DG Hierarchy Level 4, Virtual System Name, Device Name, Virtual System ID, High Resolution Timestamp, Cluster Name".Split(",")
        matchCondition = ",IPTAG,"
    },
    @{
        LogType        = "UserID"               
        format         = "FUTURE_USER, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Virtual System, Source IP, User, Data Source Name, Event ID, Repeat Count, Time Out Threshold, Source Port, Destination Port, Data Source, Data Source Type, Sequence Number, Action Flags, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Virtual System ID, Factor Type, Factor Completion Time, Factor Number, User Group Flags, User by Source, Tag Name, High Resolution Timestamp, Origin Data Source, FUTURE_USE, Cluster Name".Split(",")
        matchCondition = ",USERID,"
    },
    @{
        LogType        = "Decryption"           
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, Config Version, Generate Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, Time Logged, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, IP Protocol, Action, Tunnel, FUTURE_USE, FUTURE_USE, Source VM UUID, Destination VM UUID, UUID for rule, Stage for Client to Firewall, Stage for Firewall to Server, TLS Version, Key Exchange Algorithm, Encryption Algorithm, Hash Algorithm, Policy Name, Elliptic Curve, Error Index, Root Status, Chain Status, Proxy Type, Certificate Serial Number, Fingerprint, Certificate Start Date, Certificate End Date, Certificate Version, Certificate Size, Common Name Length, Issuer Common Name Length, Root Common Name Length, SNI Length, Certificate Flags, Subject Common Name, Issuer Subject Common Name, Root Subject Common Name, Server Name Indication, Error, Container ID, POD Namespace, POD Name, Source External Dynamic List, Destination External Dynamic List, Source Dynamic Address Group, Destination Dynamic Address Group, High Res Timestamp, Source Device Category, Source Device Profile, Source Device Model, Source Device Vendor, Source Device OS Family, Source Device OS Version, Source Hostname, Source Mac Address, Destination Device Category, Destination Device Profile, Destination Device Model, Destination Device Vendor, Destination Device OS Family, Destination Device OS Version, Destination Hostname, Destination Mac Address, Sequence Number, Action Flags, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Virtual System ID, Application Subcategory, Application Category, Application Technology, Application Risk, Application Characteristic, Application Container, Application SaaS, Application Sanctioned State, Cluster Name".Split(",")
        matchCondition = ",DECRYPTION,"
    },
    @{
        LogType        = "TunnelInspection"     
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Subtype, FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, Protocol, Action, Severity, Sequence Number, Action Flags, Source Location, Destination Location, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Tunnel ID/IMSI, Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel, Bytes, Bytes Sent, Bytes Received, Packets, Packets Sent, Packets Received, Maximum Encapsulation, Unknown Protocol, Strict Check, Tunnel Fragment, Sessions Created, Sessions Closed, Session End Reason, Action Source, Start Time, Elapsed Time, Tunnel Inspection Rule, Remote User IP, Remote User ID, Rule UUID, PCAP ID, Dynamic User Group, Source External Dynamic List, Destination External Dynamic List, High Resolution Timestamp, A Slice Differentiator, A Slice Service Type, PDU Session ID, Application Subcategory, Application Category, Application Technology, Application Risk, Application Characteristic, Application Container, Application SaaS, Application Sanctioned State, Cluster Name".Split(",")
        matchCondition = ",(START|END),(Start|End|Drop|Deny),"
    },
    @{
        LogType        = "SCTP"                 
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, FUTURE_USE, FUTURE_USE, Generated Time, Source Address, Destination Address, FUTURE_USE, FUTURE_USE, Rule Name, FUTURE_USE, FUTURE_USE, FUTURE_USE, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, IP Protocol, Action, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Sequence Number, FUTURE_USE, SCTP Association ID, Payload Protocol ID, Severity, SCTP Chunk Type, FUTURE_USE, SCTP Verification Tag 1, SCTP Verification Tag 2, SCTP Cause Code, Diameter App ID, Diameter Command Code, Diameter AVP Code, SCTP Stream ID, SCTP Association End Reason, Op Code, SCCP Calling Party SSN, SCCP Calling Party Global Title, SCTP Filter, SCTP Chunks, SCTP Chunks Sent, SCTP Chunks Received, Packets, Packets Sent, Packets Received, UUID for rule, High Resolution Timestamp".Split(",")
        matchCondition = ",SCTP,"
    },
    @{
        LogType        = "Authentication"       
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Virtual System, Source IP, User, Normalize User, Object, Authentication Policy, Repeat Count, Authentication ID, Vendor, Log Action, Server Profile, Description, Client Type, Event Type, Factor Number, Sequence Number, Action Flags, Device Group Hierarchy 1, Device Group Hierarchy 2, Device Group Hierarchy 3, Device Group Hierarchy 4, Virtual System Name, Device Name, Virtual System ID, Authentication Protocol, UUID for rule, High Resolution Timestamp, Source Device Category, Source Device Profile, Source Device Model, Source Device Vendor, Source Device OS Family, Source Device OS Version, Source Hostname, Source Mac Address, Region, FUTURE_USE, User Agent, Session ID, Cluster Name".Split(",")
        matchCondition = ",AUTHENTICATION,"
    },
    @{
        LogType        = "Config"               
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Subtype, FUTURE_USE, Generated Time, Host, Virtual System, Command, Admin, Client, Result, Configuration Path, Before Change Detail, After Change Detail, Sequence Number, Action Flags, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Device Group, Audit Comment, FUTURE_USE, High Resolution Timestamp ".Split(",")
        matchCondition = ",CONFIG,"
    },
    @{
        LogType        = "System"               
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Content/Threat Type, FUTURE_USE, Generated Time, Virtual System, Event ID, Object, FUTURE_USE, FUTURE_USE, Module, Severity, Description, Sequence Number, Action Flags, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, FUTURE_USE, FUTURE_USE, High Resolution Timestamp".Split(",")
        matchCondition = ",SYSTEM,"
    },
    @{
        LogType        = "CorrelatedEvents"     
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Content/Threat Type, FUTURE_USE, Generated Time, Source Address. Source User, Virtual System, Category, Severity, Device Group Hierarchy Level 1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group Hierarchy Level 4, Virtual System Name, Device Name, Virtual System ID, Object Name, Object ID, Evidence".Split(",")
        matchCondition = ",CORRELATION,"
    },
    @{
        LogType        = "GTP"                  
        format         = "FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated Time, Source Address, Destination Address, FUTURE_USE, FUTURE_USE, Rule Name, FUTURE_USE, FUTURE_USE, Application, Virtual System, Source Zone, Destination Zone, Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, FUTURE_USE, Source Port, Destination Port, FUTURE_USE, FUTURE_USE, FUTURE_USE, Protocol, Action, GTP Event Type, MSISDN, Access Point Name, Radio Access Technology, GTP Message Type, End User IP Address, Tunnel Endpoint Identifier1, Tunnel Endpoint Identifier2, GTP Interface, GTP Cause, Severity, Serving Country MCC, Serving Network MNC, Area Code, Cell ID, GTP Event Code, FUTURE_USE, FUTURE_USE, Source Location, Destination Location, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, Tunnel ID/IMSI, Monitor Tag/IMEI, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, FUTURE_USE, Start Time, Elapsed Time, Tunnel Inspection Rule, Remote User IP, Remote User ID, UUID for rule, PCAP ID, High Resolution Timestamp, A Slice Service Type, A Slice Differentiator, Application Subcategory, Application Category, Application Technology, Application Risk, Application Characteristic, Application Container, Application SaaS, Application Sanctioned State".Split(",")
        matchCondition = ",GTP,"
    },
    @{
        LogType        = "Audit"            
        format         = "Serial Number, Generate Time, Threat/Content Type, FUTURE_USE, Event ID, Object, CLI Command, Severity".Split(",")
        matchCondition = ",AUDIT,"
    }
)



#Work out all the traffic strings
$extractorResults = @()
$SyslogDefinitions | ForEach-Object {

    $LogType = $PSItem.LogType
    $LogFormat = $PSItem.format
    $matchCondition = $PSItem.matchCondition

    $Index = 1
    
    foreach ($value in $LogFormat) {
        $value = $value.trim().replace(" ", "").replace("/", "").replace("_", "").replace("IP", "_IP")
        if ($value -notmatch "FUTUREUSE") {
            $extractorResults += @{
                title            = "$($LogType)_$($value)"
                extractor_type   = "split_and_index"
                converters       = @()
                order            = 0
                cursor_strategy  = "copy"
                source_field     = "message"
                target_field     = $value
                extractor_config = @{
                    index    = $Index
                    split_by = ","
                }
                condition_type   = "string"
                condition_value  = $matchCondition
            }
        }
        
        $Index++
    }

}

$ExtractorJSON = @{
    extractors = $extractorResults
    version    = "7.0.4"
} | ConvertTo-Json -Depth 10 | Tee-Object -FilePath $OutputPath | Write-Host
"File was saved to: $OutputPath"
