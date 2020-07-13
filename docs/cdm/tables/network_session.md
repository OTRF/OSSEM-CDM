# network_session

Event fields used to define network sessions in an endpoint.

## Attributes

| Entity | Name | Type | Description | Sample Value |
|:---|:---|:---|:---|:---|
 | cloud | cloud_app_id | String | The ID of the destination application for an HTTP application as identified by a proxy. This value is usually specific to the proxy used | 124 |
 | cloud | cloud_app_name | string | The name of the destination application for an HTTP application as identified by a proxy | Facebook |
 | cloud | cloud_app_operation | string | The operation the user performed in the context of the destination application for an HTTP application as identified by a proxy. This value is usually specific to the proxy used. | DeleteFile |
 | cloud | cloud_app_risk_level | string | The risk level associated with an HTTP application as identified by a proxy. This value is usually specific to the proxy used. | High |
 | destination | dst_bytes | integer | network bytes sent by the dst_ip_addr. Another field can also be provided after extending the IP entity. We can also define the dst_ip_bytes field. | 100 |
 | destination | dst_city | string | The city associated with the destination IP address | Burlington |
 | destination | dst_country | country | The country associated with the destination IP address | USA |
 | destination | dst_domain | string | The (DNS) hierarchy that encompasses multiple hosts (i.e a Windows Active Directory environment). | bigwheel.corporation.local |
 | destination | dst_host_domain | string | Name of the domain the host is part of or joined. | hunt.wardog.com |
 | destination | dst_host_fqdn | string | The fully qualified domain name of the host | WKHR001.hunt.wardog.com |
 | destination | dst_host_interface_guid | string | GUID of the network interface which was used for authentication request | {2BB33827-6BB6-48DB-8DE6-DB9E0B9F9C9B} |
 | destination | dst_host_interface_name | string | the name (description) of the network interface that was used for authentication request. You can get the list of all available network adapters using "ipconfig /all" command | Microsoft Hyper-V Network Adapter |
 | destination | dst_host_name | string | The name of a host, device, node, or entity that is separate from the FQDN and Domain. | WKHR001 |
 | destination | dst_ip_addr | ip | IP address. | 192.168.1.2 |
 | destination | dst_ip_bytes | integer | network IP (header) bytes sent by the either the source or destination ip address | 100 |
 | destination | dst_ip_dhcp_assigned_ip_addr | ip | IP address assigned by the DHCP server. | 192.168.1.2 |
 | destination | dst_latitude | real | The latitude of the geographical coordinate associated with the destination IP address | 44.475833 |
 | destination | dst_longitude | real | The longitude of the geographical coordinate associated with the destination IP address | -73.211944 |
 | destination | dst_mac_address | mac | MAC address of the endpoint where the log was created | 00:11:22:33:44:55 |
 | destination | dst_nat_ip_addr | ip | If reported by an intermediary NAT device such as a firewall, the IP address used by the NAT device for communication with the source. | 10.1.1.14 |
 | destination | dst_nat_port | integer | If reported by an intermediary NAT device such as a firewall, the port used by the NAT device for communication with the source | 443 |
 | destination | dst_packets | integer | The number of packets sent from the destination to the source for the connection or session. The meaning of a packet is defined by the reporting device | 446 |
 | destination | dst_port_number | integer | Source port number used in a network connection. | 138 |
 | destination | dst_resource_group | string | The ID of the group to which the destination device belongs. This might be an AWS account, or an Azure subscription or Resource Group | DatabaseVMs |
 | destination | dst_resource_id | string | The resource Id of the destination device | /subscriptions/33333333-8888-4444-a115-aaaaaaaaaaaa/resourcegroups/shokobo/providers/microsoft.compute/virtualmachines/sysmachine2 |
 | destination | dst_resource_id | string | The resource ID of the device generating the message | /subscriptions/3c1bb38c-82e3-4f8d-a115-a7110ba70d05/resourcegroups/contoso77/providers/microsoft.compute/virtualmachines/syslogserver1 |
 | destination | dst_user_aadid | string | The User Azure AD ID of the identity associated with the session’s destination. | 5e8b0f4d-2cd4-4e17-9467-b0f6a5c0c4d0 |
 | destination | dst_zone | string | The network zone of the destination, as defined by the reporting device. | dmz |
 | device | dvc_action | string | If reported by an intermediary device such as a firewall, the action taken by device. | allow |
 | device | dvc_inbound_interface | string | If reported by an intermediary device such as a firewall, the network interface used by it for the connection to the source device | eth0 |
 | device | dvc_outbound_interface | string | If reported by an intermediary device such as a firewall, the network interface used by it for the connection to the destination device. | Ethernet 4 |
 | event | event_count | integer | The number of aggregated events, if applicable | 10 |
 | event | event_endtime | datetime | The time in which the event ended | 2017-04-12 12:00:00 |
 | event | event_message | string | A general message or description, either included in, or generated from the record | TCP access denied |
 | event | event_original_message | string | The (original) log message from the source before any ETL manipulations/modifications | a long message |
 | event | event_original_uid | string | Original unique ID specific to the log/event as recorded from the source. | CMzY3i4YoNZ3mT5yu5 |
 | event | event_original_uid | string | Original unique ID specific to the log/event as recorded from the source. | CMzY3i4YoNZ3mT5yu5 |
 | event | event_severity | string | The severity of the event as defined manually or usually via the original log, commonly this would be syslog severity. The number codes should be converted to their corresponding string value. | high |
 | event | event_start_time | datetime | The time in which the event stated | 2017-01-21 09:12:34 |
 | event | event_start_time | datetime | The time in which the event stated | 2017-01-21 09:12:34 |
 | event | event_time_ingested | datetime | The time the event was ingested to SIEM or data pipeline. | 2157-01-21 09:12:34 |
 | event | event_uid | string | Original unique ID specific to the log/event assigned to the event (not original). | CMzY3i4YoNZ3mT5yu5 |
 | file | file_extension | string | The file extension of a file (.txt, .exe, etc) | exe |
 | file | file_link_name | string | path of the hard link | C:\Docs\My.exe |
 | file | file_name | string | name of a file without its full path. | a.exe |
 | file | file_path | string | full path of a file including the name of the file | C:\users\wardog\z.exe |
 | file | file_previous_name | string | The file's previous name | C:\\Windows\system32\cmd.exe |
 | file | file_size | string | Specifies the size of a file, in bytes | 45 |
 | file | file_symlink_name | string | path of the symlink | C:\Docs\My.exe |
 | file | file_system_block_size | integer | Block size of filesystem |  |
 | hash | hash_imphash | string | IMPHASH hash of the image/binary/file | 2505BD03D7BD285E50CE89CEC02B333B |
 | hash | hash_md5 | string | MD5 hash of the image/binary/file | 6A255BEBF3DBCD13585538ED47DBAFD7 |
 | hash | hash_sha1 | string | SHA1 hash of the image/binary/file | B0BF5AC2E81BBF597FAD5F349FEEB32CAC449FA2 |
 | hash | hash_sha256 | string | SHA256 hash of the image/binary/file | 4668BB2223FFB983A5F1273B9E3D9FA2C5CE4A0F1FB18CA5C1B285762020073C |
 | hash | hash_sha512 | string | SHA512 hash of the image/binary/file | 1AD1D79F85D8F6A50EA282F63898D652661DAA0C1FD361C22647CABC98A70E8CBCE83200D579D10DD0A3D46BE9496DCDFDDF28B0C5E9709343B032A8796FBECB |
 | http | http_content_type | string | The HTTP Response content type header for HTTP/HTTPS network sessions. |  |
 | http | http_referrer_original | string | HTTP header "Referer". The HTTP referer header for HTTP/HTTPS network sessions. | https://sub.domain.tld/path/a/b/JavaScript |
 | http | http_request_method | string | Type of HTTP request that was made. Other examples could be (anything) PUT, POST, HEAD, DELETE | GET |
 | http | http_request_time | integer | The amount of time in milliseconds it took to send the request to the server, if applicable. | 700 |
 | http | http_response_time | inte | The amount of time in milliseconds it took to receive a response in the server, if applicable. | 800 |
 | http | http_status_code | integer | HTTP Server reply code | 200 |
 | http | http_xff | string | The HTTP X-Forwarded-For header for HTTP/HTTPS network sessions. | 203.0.113.195 |
 | icmp | icmp_code | integer | For an ICMP message, ICMP message type numeric value (RFC 2780 or RFC 4443). | 34 |
 | icmp | icmp_type | string | For an ICMP message, ICMP message type text representation (RFC 2780 or RFC 4443) | Destination Unreachable |
 | network | network_application_protocol | string | Layer 7 (application) in the OSI model. Ex: HTTP,SMB,FTP,SSH, etc. | HTTP |
 | network | network_application_protocol | string | Layer 7 (application) in the OSI model. Ex: HTTP,SMB,FTP,SSH, etc. | HTTP |
 | network | network_bytes | long | Total bytes for the session. If this field does not exist in the log source, then its possible in your ETL pipeline to combine the source and destination bytes | 102034 |
 | network | network_direction | string | User/Device defined name of the direction of the connection | outbound |
 | network | network_ip_bytes | long | Total IP bytes, according to ip headers, for the session. If this field does not exist in the log source, then its possible in your ETL pipeline to combine the source and destination bytes | 14564 |
 | network | network_missed_bytes | long | bytes that a network sensor or other system/application may have missed | 5 |
 | network | network_packets | long | Total packets for the session. If this field does not exist in the log source, then its possible in your ETL pipeline to combine the source and destination packets | 143 |
 | network | network_protocol | string | Transport layer in the OSI model. Also known as, IP Protocol. Ex: TCP,UDP,ICMP,ICMP-v6, etc. Convert to lowercase | tcp |
 | network | network_session_id | string | The session identifier as reported by the reporting device. Typically, not available for connections. | S198_13_1_27_12321_D205_13_1_27_443_0012 |
 | operation | op_name | string | The activity associated with the record. Possible specific values are determined by the relevant schema. | Traffic |
 | result | result_reason_type | string | Reason for the result reported in ResultType | Traffic |
 | result | result_type | string | The result reported for the activity. Empty value when not applicable. | Success |
 | reporter | rptr_host_ip_addr | ip | The IP address of the device generating the record | 211.209.13.12 |
 | reporter | rptr_host_name | string | The device name of the device generating the message | syslogserver1.contoso.com |
 | reporter | rptr_mac | string | The MAC address of the network interface of the reporting device from which the event was send | 06:10:9f:eb:8f:14 |
 | reporter | rptr_product | string | The product generating the event. | OfficeSharepoint |
 | reporter | rptr_product_ver | string | The version of the product generating the event | 0.2 |
 | reporter | rptr_report_url | string | url of the full analysis report, if applicable | https://192.168.1.1/reports/ade-123-afa.log |
 | reporter | rptr_resource_group | string | The resource group to which the device generating the record belongs. This might be an AWS account, or an Azure subscription or Resource Group | DBVM |
 | reporter | rptr_resource_id | string | The resource ID of the device generating the message. | /subscriptions/aaabbbcc-dddd-eeee-1234-1234567890ab/resourcegroups/shokobo/providers/microsoft.compute/virtualmachines/sysmachine |
 | reporter | rptr_vendor | string | The vendor of the product generating the event | Microsoft |
 | rule | rule_name | string | The name or ID of the rule by which DeviceAction was decided upon | Any Any Drop |
 | rule | rule_number | string | Matched rule number | 7 |
 | schema | schema_Ver | real | Azure Sentinel Schema Version | 0.1 |
 | source | src_bytes | integer | network bytes sent by the src_ip_addr | 100 |
 | source | src_city | string | The city associated with the source IP address | Burlington |
 | source | src_country | country | The country associated with the source IP address | USA |
 | source | src_domain | string | The (DNS) hierarchy that encompasses multiple hosts (i.e a Windows Active Directory environment). | bigwheel.corporation.local |
 | source | src_host_domain | string | Name of the domain the host is part of or joined. | hunt.wardog.com |
 | source | src_host_fqdn | string | The fully qualified domain name of the host | WKHR001.hunt.wardog.com |
 | source | src_host_interface_guid | string | GUID of the network interface which was used for authentication request | {2BB33827-6BB6-48DB-8DE6-DB9E0B9F9C9B} |
 | source | src_host_interface_name | string | the name (description) of the network interface that was used for authentication request. You can get the list of all available network adapters using "ipconfig /all" command | Microsoft Hyper-V Network Adapter |
 | source | src_host_model | string | The model of the source device | Samsung Galaxy Note 10 |
 | source | src_host_name | string | The name of a host, device, node, or entity that is separate from the FQDN and Domain. | WKHR001 |
 | source | src_host_os | string | The OS of the source device | iOS |
 | source | src_host_type | string | The type of the source device | mobile |
 | source | src_ip_addr | ip | IP address. | 192.168.1.2 |
 | source | src_ip_bytes | integer | network IP (header) bytes sent by the either the source or destination ip address | 100 |
 | source | src_ip_dhcp_assigned_ip_addr | ip | IP address assigned by the DHCP server. | 192.168.1.2 |
 | source | src_latitude | real | The latitude of the geographical coordinate associated with the source IP address | 44.475833 |
 | source | src_longitude | real | The longitude of the geographical coordinate associated with the source IP address | -73.211944 |
 | source | src_mac_address | mac | MAC address of the endpoint where the log was created | 00:11:22:33:44:55 |
 | source | src_nat_ip_addr | ip | If reported by an intermediary NAT device such as a firewall, the IP address used by the NAT device for communication with the destination | 12.56.23.12 |
 | source | src_nat_port | integer | If reported by an intermediary NAT device such as a firewall, the port used by the NAT device for communication with the destination | 389 |
 | source | src_port | integer | The IP port from which the connection originated. May not be relevant for a session comprising multiple connections. | 12341 |
 | source | src_port_number | integer | Source port number used in a network connection. | 138 |
 | source | src_region | string | The region within a country associated with the source IP address | Vermont |
 | source | src_resource_group | string | The ID of the group to which the source device belongs. This might be an AWS account, or an Azure subscription or Resource Group | Hosts |
 | source | src_resource_id | string | The resource ID of the device generating the message | /subscriptions/3c1bb38c-82e3-4f8d-a115-a7110ba70d05/resourcegroups/contoso77/providers/microsoft.compute/virtualmachines/syslogserver1 |
 | source | src_user_aadid | string | The User Azure AD ID of the identity associated with the session’s source. | 5e8b0f4d-2cd4-4e17-9467-b0f6a5c0c4d0 |
 | source | src_user_domain | string | subject's domain or computer name of the account that performed the main action in the event | WIN-GG82ULGC9GO |
 | source | src_user_domain | string | subject's domain or computer name of the account that performed the main action in the event | WIN-GG82ULGC9GO |
 | source | src_user_name | string | Name of the account that performed the main action in the event. (i.e. user_name authenticated to the box x or user_name spawned a process) | DESKTOP-WARDOG\wardog |
 | source | src_user_network_account_domain | string | Domain for the user that will be used for outbound (network) connections. Valid only for NewCredentials logon type. If not NewCredentials logon, then this will be a "-" string. | - |
 | source | src_user_reporter_domain | string | subject's domain or computer name of the account that reported information about the main event | WORKGROUP |
 | source | src_user_sid | string | Security identifier of the account that performed the main action in the event | S-1-5-21-1377283216-344919071-3415362939-500 |
 | source | src_user_sid_list | string | the list of special group SIDs, which New Logon\Security ID is a member of. | {S-1-5-21-3457937927-2839227994-823803824-512} |
 | source | src_user_upn | string | UPN of the account for which delegation was requested. | dadmin@contoso |
 | source | src_zone | string | The network zone of the source, as defined by the reporting device. | dmz |
 | threat | threat_category | string | The category of a threat identified by a security system such as Web Security Gateway of an IPS and is associated with this network session. | Trojan |
 | threat | threat_id | string | The ID of a threat identified by a security system such as Web Security Gateway of an IPS and is associated with this network session. | tr.076 |
 | threat | threat_name | string | The name of the threat or malware identified | Win32.Small.ahif(90603579) |
 | url | url_category | string | The defined grouping of a URL (or could be just based on the domain in the URL) related to what it is (ie: adult, news, advertising, parked domains, etc) | Search Engines |
 | url | url_dst_host_name | string | Copied from the host_name | google.com |
 | url | url_host_name | string | The domain/host/hostname of the URL. This could be an IP address or any variation of a value but is more than likely a domain/hostname | google.com |
 | url | url_original | string | The entirety of the URL combined together and or the URL in the truest form from the log source. Some log sources will already parse out portions of the URL into their respective fields. Other logs will even parse out the portions of the URL into their respective field but also include the "original" URL. Always try to include this field, because HTTP/URLs never truly have to conform to any RFC/implementation and thus any parsing/logging implementation could have any number of assumptions/mistakes - therefore it is best to keep a original value | ftp://BigwheelPassword:BigwheelBobUser@google.com:8088/common/Current/client/search/greatsearch.php?hash=215696fc36392ca70f89228b98060afb%20processname=example.exe#gid=l1k4h |
 | user_agent | user_agent_original | string | The User agent seen in an HTTP request | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36 |
