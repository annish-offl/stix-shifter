# Azure Sentinel - ISC UDS Connector

### Data Source 
Microsoft Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution. Azure Sentinel delivers intelligent security analytics and threat intelligence across the enterprise, providing a single solution for alert detection, threat visibility, proactive hunting, and threat response.

##### Microsoft Graph API (v1.0)
List security alerts (GET call) https://graph.microsoft.com/v1.0/security/ <br/>
`Ref: https://docs.microsoft.com/en-us/graph/api/resources/alert?view=graph-rest-beta`

Query Parameter: 
$filter (OData V4.0 support) <br/>

Note: The Microsoft Graph Security API provides a unified interface and schema to integrate with security solutions from Microsoft and ecosystem partners. The security alerts from various partners are available and the schema comprises information about the fileStates, processes, networkConnections and userStates. <br/>
`Schema Ref: https://docs.microsoft.com/en-us/graph/api/alert-get?view=graph-rest-beta&tabs=http#example`

### Format for calling stix-shifter from the command line

python main.py `<translator_module>` `<query or result>` `<STIX identity object>` `<data>`

## Example I - Converting from STIX patterns to OData V4 queries (STIX attributes)
STIX to sentinel field mapping is defined in `from_stix_map.json` <br/>

This example input pattern:

`translate azure_sentinel query ‘{}’ "[process:name = 'svchost.exe'] START t'2019-01-01T08:43:10Z' STOP t'2019-12-31T08:43:10Z'"`

Returns the following Odata(native) query:

`{'queries': ["(processes/any(query1:tolower(query1/name) eq 'svchost.exe')) and (eventDateTime ge 2019-01-01T08:43:10Z and eventDateTime le 2019-12-31T08:43:10Z)"]}
`
## Example I - Converting from Azure sentinel alerts to STIX (STIX attributes)

Sentinel data to STIX mapping is defined in `to_stix_map.json`

Sample data:

`translate
azure_sentinel
results
"{\"type\":\"identity\",\"id\":\"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff\",\"name\":\"azure_sentinel\",\"identity_class\":\"events\"}"
"[{\"id\": \"2518255519019388960_5cc61270-5bd7-42df-b048-2a5eee65357f\", \"azureTenantId\": \"b73e5ba8-34d5-495a-9901-06bdb84cf13e\", \"azureSubscriptionId\": \"083de1fb-cd2d-4b7c-895a-2b5af1d091e8\", \"tags\": [], \"category\": \"SuspiciousSVCHost\", \"comments\": [], \"createdDateTime\": \"2019-12-19T09:48:40.7807272Z\", \"description\": \"The system process SVCHOST was observed running in an abnormal context. Malware often use SVCHOST to masquerade its malicious activity.\", \"detectionIds\": [], \"eventDateTime\": \"2019-12-19T09:48:18.0611039Z\", \"lastModifiedDateTime\": \"2019-12-19T09:48:42.2043247Z\", \"recommendedActions_0\": \"1. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx)\", \"recommendedActions_1\": \"2. Make sure the machine is completely updated and has an updated anti-malware application installed\", \"recommendedActions_2\": \"3. Run a full anti-malware scan and verify that the threat was removed\", \"recommendedActions_3\": \"4. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx)\", \"recommendedActions_4\": \"5. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)\", \"severity\": \"high\", \"sourceMaterials_0\": \"https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518255519019388960_5cc61270-5bd7-42df-b048-2a5eee65357f/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/centralus\", \"status\": \"newAlert\", \"title\": \"Suspicious SVCHOST process executed\", \"vendorInformation_provider\": \"ASC\", \"vendorInformation_subProvider\": \"Detection\", \"vendorInformation_vendor\": \"Microsoft\", \"cloudAppStates\": [], \"hostStates_0_netBiosName\": \"WINSRV-TARGET\", \"hostStates_0_os\": \"Windows\", \"historyStates\": [], \"malwareStates\": [], \"networkConnections\": [], \"processes_0_commandLine\": \"\", \"processes_1_accountName\": \"testadmin\", \"processes_1_commandLine\": \"c:\\job\\svchost.exe\", \"processes_1_createdDateTime\": \"2019-12-19T09:48:18.0611039Z\", \"processes_1_name\": \"svchost.exe\", \"processes_1_path\": \"c:\\job\\svchost.exe\", \"registryKeyStates\": [], \"triggers\": [], \"userStates_0_accountName\": \"testadmin\", \"userStates_0_domainName\": \"winsrv-target\", \"userStates_0_emailRole\": \"unknown\", \"userStates_0_logonId\": \"0x8869d3\", \"userStates_0_onPremisesSecurityIdentifier\": \"S-1-5-21-1892577120-2195645935-2669380810-500\", \"userStates_0_userPrincipalName\": \"testadmin@WINSRV-TARGET\", \"vulnerabilityStates\": [], \"event_count\": \"1\"}, {\"id\": \"2518258113113268043_0f54bc18-961c-48b7-8900-051e40dc8d22\", \"azureTenantId\": \"b73e5ba8-34d5-495a-9901-06bdb84cf13e\", \"azureSubscriptionId\": \"083de1fb-cd2d-4b7c-895a-2b5af1d091e8\", \"tags\": [], \"category\": \"SuspiciousSVCHOSTRareGroup\", \"comments\": [], \"createdDateTime\": \"2019-12-16T09:44:58.7936988Z\", \"description\": \"The system process SVCHOST was observed running a rare service group. Malware often use SVCHOST to masquerade its malicious activity.\", \"detectionIds\": [], \"eventDateTime\": \"2019-12-16T09:44:48.6731956Z\", \"lastModifiedDateTime\": \"2019-12-16T09:45:00.5345972Z\", \"recommendedActions_0\": \"1. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx)\", \"recommendedActions_1\": \"2. Make sure the machine is completely updated and has an updated anti-malware application installed\", \"recommendedActions_2\": \"3. Run a full anti-malware scan and verify that the threat was removed\", \"recommendedActions_3\": \"4. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx)\", \"recommendedActions_4\": \"5. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)\", \"severity\": \"informational\", \"sourceMaterials\": [], \"status\": \"newAlert\", \"title\": \"Rare SVCHOST service group executed\", \"vendorInformation_provider\": \"ASC\", \"vendorInformation_subProvider\": \"Detection\", \"vendorInformation_vendor\": \"Microsoft\", \"cloudAppStates\": [], \"hostStates_0_netBiosName\": \"TEST-WINDOW-UPD\", \"hostStates_0_os\": \"Windows\", \"historyStates\": [], \"malwareStates\": [], \"networkConnections\": [], \"processes_0_commandLine\": \"\", \"processes_0_name\": \"services.exe\", \"processes_0_path\": \"c:\\windows\\system32\\services.exe\", \"processes_1_accountName\": \"TEST-WINDOW-UPD$\", \"processes_1_commandLine\": \"c:\\windows\\system32\\svchost.exe -k clipboardsvcgroup -p -s cbdhsvc\", \"processes_1_createdDateTime\": \"2019-12-16T09:44:48.6731956Z\", \"processes_1_name\": \"svchost.exe\", \"processes_1_parentProcessName\": \"services.exe\", \"processes_1_path\": \"c:\\windows\\system32\\svchost.exe\", \"registryKeyStates\": [], \"triggers\": [], \"userStates_0_accountName\": \"TEST-WINDOW-UPD$\", \"userStates_0_domainName\": \"WORKGROUP\", \"userStates_0_emailRole\": \"unknown\", \"userStates_0_logonId\": \"0x3e7\", \"userStates_0_onPremisesSecurityIdentifier\": \"S-1-5-18\", \"userStates_0_userPrincipalName\": \"TEST-WINDOW-UPD$@TEST-WINDOW-UPD\", \"vulnerabilityStates\": [], \"event_count\": \"1\"}, {\"id\": \"2518268485253060642_52b1a353-2fd8-4c45-8f8a-94db98dca29d\", \"azureTenantId\": \"b73e5ba8-34d5-495a-9901-06bdb84cf13e\", \"azureSubscriptionId\": \"083de1fb-cd2d-4b7c-895a-2b5af1d091e8\", \"tags\": [], \"category\": \"SuspiciousSVCHOSTRareGroup\", \"comments\": [], \"createdDateTime\": \"2019-12-04T09:38:05.2024952Z\", \"description\": \"The system process SVCHOST was observed running a rare service group. Malware often use SVCHOST to masquerade its malicious activity.\", \"detectionIds\": [], \"eventDateTime\": \"2019-12-04T09:37:54.6939357Z\", \"lastModifiedDateTime\": \"2019-12-04T09:38:06.7571701Z\", \"recommendedActions_0\": \"1. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx)\", \"recommendedActions_1\": \"2. Make sure the machine is completely updated and has an updated anti-malware application installed\", \"recommendedActions_2\": \"3. Run a full anti-malware scan and verify that the threat was removed\", \"recommendedActions_3\": \"4. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx)\", \"recommendedActions_4\": \"5. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)\", \"severity\": \"informational\", \"sourceMaterials\": [], \"status\": \"newAlert\", \"title\": \"Rare SVCHOST service group executed\", \"vendorInformation_provider\": \"ASC\", \"vendorInformation_subProvider\": \"Detection\", \"vendorInformation_vendor\": \"Microsoft\", \"cloudAppStates\": [], \"hostStates_0_netBiosName\": \"TEST-WINDOW\", \"hostStates_0_os\": \"Windows\", \"historyStates\": [], \"malwareStates\": [], \"networkConnections\": [], \"processes_0_commandLine\": \"\", \"processes_0_name\": \"services.exe\", \"processes_0_path\": \"c:\\windows\\system32\\services.exe\", \"processes_1_accountName\": \"test-window$\", \"processes_1_commandLine\": \"c:\\windows\\system32\\svchost.exe -k clipboardsvcgroup -p -s cbdhsvc\", \"processes_1_createdDateTime\": \"2019-12-04T09:37:54.6939357Z\", \"processes_1_name\": \"svchost.exe\", \"processes_1_parentProcessName\": \"services.exe\", \"processes_1_path\": \"c:\\windows\\system32\\svchost.exe\", \"registryKeyStates\": [], \"triggers\": [], \"userStates_0_accountName\": \"test-window$\", \"userStates_0_domainName\": \"WORKGROUP\", \"userStates_0_emailRole\": \"unknown\", \"userStates_0_logonId\": \"0x3e7\", \"userStates_0_onPremisesSecurityIdentifier\": \"S-1-5-18\", \"userStates_0_userPrincipalName\": \"test-window$@TEST-WINDOW\", \"vulnerabilityStates\": [], \"event_count\": \"1\"}]"`
Will return the following STIX observable:

```json
{
    "type": "bundle",
    "id": "bundle--0474ebda-5e6e-4cc4-abd9-13195db0bd3a",
    "objects": [
        {
            "type": "identity",
            "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "name": "azure_sentinel",
            "identity_class": "events"
        },
        {
            "id": "observed-data--b4e4b265-7ea6-4e74-b4ef-e62f8f0f99e4",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:02:44.388Z",
            "modified": "2020-01-03T10:02:44.388Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "svchost.exe",
                    "parent_directory_ref": "2"
                },
                "1": {
                    "type": "process",
                    "name": "svchost.exe",
                    "binary_ref": "0"
                },
                "2": {
                    "type": "directory",
                    "path": "c:\\job"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518255519019388960_5cc61270-5bd7-42df-b048-2a5eee65357f",
                "title": "Suspicious SVCHOST process executed",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-19T09:48:18.0611039Z",
            "last_observed": "2019-12-19T09:48:18.0611039Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--7f275bee-96f8-4074-af75-d116506bd4d9",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:02:44.390Z",
            "modified": "2020-01-03T10:02:44.390Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "services.exe",
                    "parent_directory_ref": "2"
                },
                "1": {
                    "type": "process",
                    "name": "services.exe",
                    "binary_ref": "0"
                },
                "2": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "3": {
                    "type": "file",
                    "name": "svchost.exe",
                    "parent_directory_ref": "5"
                },
                "4": {
                    "type": "process",
                    "name": "svchost.exe",
                    "parent_ref": "1",
                    "binary_ref": "3"
                },
                "5": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "6": {
                    "type": "user-account",
                    "user_id": "TEST-WINDOW-UPD$"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518258113113268043_0f54bc18-961c-48b7-8900-051e40dc8d22",
                "title": "Rare SVCHOST service group executed",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-16T09:44:48.6731956Z",
            "last_observed": "2019-12-16T09:44:48.6731956Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--fed4287e-60b8-413e-aa0a-a511ed860f78",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:02:44.394Z",
            "modified": "2020-01-03T10:02:44.394Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "services.exe",
                    "parent_directory_ref": "2"
                },
                "1": {
                    "type": "process",
                    "name": "services.exe",
                    "binary_ref": "0"
                },
                "2": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "3": {
                    "type": "file",
                    "name": "svchost.exe",
                    "parent_directory_ref": "5"
                },
                "4": {
                    "type": "process",
                    "name": "svchost.exe",
                    "parent_ref": "1",
                    "binary_ref": "3"
                },
                "5": {
                    "type": "directory",
                    "path": "c:\\windows\\system32"
                },
                "6": {
                    "type": "user-account",
                    "user_id": "test-window$"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518268485253060642_52b1a353-2fd8-4c45-8f8a-94db98dca29d",
                "title": "Rare SVCHOST service group executed",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-04T09:37:54.6939357Z",
            "last_observed": "2019-12-04T09:37:54.6939357Z",
            "number_observed": 1
        }
    ]
}
```


## Example II - Converting from STIX patterns to OData V4 queries (Custom attributes)
STIX to sentinel field mapping is defined in `from_stix_map.json` <br/>

This example input pattern:

`translate azure_sentinel query '{} "[x_com_msazure_sentinel_alert:provider = 'ASC'] START t'2019-01-01T08:43:10Z' STOP t'2019-12-31T08:43:10Z'"`

Returns the following Odata(native) query:

`{'queries': ["(vendorInformation/provider eq 'ASC') and (eventDateTime ge 2019-01-01T08:43:10Z and eventDateTime le 2019-12-31T08:43:10Z)"]}`

## Example II - Converting from Azure sentinel alerts to STIX (Custom attributes)

Sentinel data to STIX mapping is defined in `to_stix_map.json`

Sample data:

`translate azure_sentinel results "{\"type\":\"identity\",\"id\":\"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff\",\"name\":\"azure_sentinel\",\"identity_class\":\"events\"}" "[{'id': '2518254730385772806_da637123660281149084_-953649836:4wVg68RS3EYNc3Qb7xJUNrYw9KEUBA1wZ3IVwRA0hmg=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Suspected credential theft activity', 'comments': [], 'createdDateTime': '2019-12-20T07:45:03.1726913Z', 'description': 'This program exhibits suspect characteristics potentially associated with credential theft.  Once obtained, these credentials are often used in lateral movement activities to infiltrate other machines and servers in the network.', 'detectionIds': [], 'eventDateTime': '2019-12-20T07:42:41.4227193Z', 'lastModifiedDateTime': '2019-12-20T07:45:06.1246819Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'medium', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518254730385772806_da637123660281149084_-953649836:4wVg68RS3EYNc3Qb7xJUNrYw9KEUBA1wZ3IVwRA0hmg=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660281149084_-953649836', 'status': 'newAlert', 'title': 'Suspected credential theft activity', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'cmd.exe', 'fileStates_0_path': 'C:\\Windows\\System32\\cmd.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': '6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b', 'fileStates_0_sha256': '6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518254730385772806_da637123660281149084_-953649836:JGqJp4SlSroeE_6c3bZL6R6oWUal2lFJRO3d6N8jgyk=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Suspected credential theft activity', 'comments': [], 'createdDateTime': '2019-12-20T07:45:03.5008384Z', 'description': 'This program exhibits suspect characteristics potentially associated with credential theft.  Once obtained, these credentials are often used in lateral movement activities to infiltrate other machines and servers in the network.', 'detectionIds': [], 'eventDateTime': '2019-12-20T07:42:41.4227193Z', 'lastModifiedDateTime': '2019-12-20T07:45:06.0810972Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'medium', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518254730385772806_da637123660281149084_-953649836:JGqJp4SlSroeE_6c3bZL6R6oWUal2lFJRO3d6N8jgyk=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660281149084_-953649836', 'status': 'newAlert', 'title': 'Suspected credential theft activity', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'mimikatz.exe', 'fileStates_0_path': 'C:\\tools\\mimikatz-master\\lib\\x64\\mimikatz.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'fileStates_0_sha256': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518254730385772806_da637124247028408126_-1879876458:BBCp8DC2k8qr4fp7Msgx48xH9gEpcDzr23iW5U13eOY=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Malicious credential theft tool execution detected', 'comments': [], 'createdDateTime': '2019-12-20T07:45:02.5907596Z', 'description': "A known credential theft tool execution command line was detected.\nEither the process itself or its command line indicated an intent to dump users' credentials, keys, plain-text passwords and more.", 'detectionIds': [], 'eventDateTime': '2019-12-20T07:42:41.4227193Z', 'lastModifiedDateTime': '2019-12-20T07:45:06.0787927Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'high', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518254730385772806_da637124247028408126_-1879876458:BBCp8DC2k8qr4fp7Msgx48xH9gEpcDzr23iW5U13eOY=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637124247028408126_-1879876458', 'status': 'newAlert', 'title': 'Malicious credential theft tool execution detected', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'mimikatz.exe', 'fileStates_0_path': 'C:\\tools\\mimikatz-master\\lib\\x64\\mimikatz.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'fileStates_0_sha256': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518254749537640003_da637123660281149084_-953649836:DZoKKwpp8DW6oF3Qs7ofnbkJihHMQSZR7jb02CnqdYU=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Suspected credential theft activity', 'comments': [], 'createdDateTime': '2019-12-20T07:14:28.0521419Z', 'description': 'This program exhibits suspect characteristics potentially associated with credential theft.  Once obtained, these credentials are often used in lateral movement activities to infiltrate other machines and servers in the network.', 'detectionIds': [], 'eventDateTime': '2019-12-20T07:10:46.2359996Z', 'lastModifiedDateTime': '2019-12-20T07:14:31.5453569Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'medium', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518254749537640003_da637123660281149084_-953649836:DZoKKwpp8DW6oF3Qs7ofnbkJihHMQSZR7jb02CnqdYU=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660281149084_-953649836', 'status': 'newAlert', 'title': 'Suspected credential theft activity', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'mimikatz.exe', 'fileStates_0_path': 'C:\\tools\\x64\\mimikatz.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'fileStates_0_sha256': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518254749496473232_da637123660275108740_1307429309:OMwAtExvCXaspczkTQBVXBsi2dv0wWIN9FDBz7OdYPA=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Malicious credential theft tool execution detected', 'comments': [], 'createdDateTime': '2019-12-20T07:14:27.8523166Z', 'description': "A known credential theft tool execution command line was detected.\nEither the process itself or its command line indicated an intent to dump users' credentials, keys, plain-text passwords and more.", 'detectionIds': [], 'eventDateTime': '2019-12-20T07:10:50.3526767Z', 'lastModifiedDateTime': '2019-12-20T07:14:31.2843135Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'high', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518254749496473232_da637123660275108740_1307429309:OMwAtExvCXaspczkTQBVXBsi2dv0wWIN9FDBz7OdYPA=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660275108740_1307429309', 'status': 'newAlert', 'title': 'Malicious credential theft tool execution detected', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'mimikatz.exe', 'fileStates_0_path': 'C:\\tools\\x64\\mimikatz.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'fileStates_0_sha256': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518254749537640003_da637123660281149084_-953649836:3f_1OC23WuGNSs1hCfnrXClrrAx1IFQudnU9lMzh_uk=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Suspected credential theft activity', 'comments': [], 'createdDateTime': '2019-12-20T07:14:27.8334132Z', 'description': 'This program exhibits suspect characteristics potentially associated with credential theft.  Once obtained, these credentials are often used in lateral movement activities to infiltrate other machines and servers in the network.', 'detectionIds': [], 'eventDateTime': '2019-12-20T07:10:46.2359996Z', 'lastModifiedDateTime': '2019-12-20T07:14:30.3646432Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'medium', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518254749537640003_da637123660281149084_-953649836:3f_1OC23WuGNSs1hCfnrXClrrAx1IFQudnU9lMzh_uk=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660281149084_-953649836', 'status': 'newAlert', 'title': 'Suspected credential theft activity', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'cmd.exe', 'fileStates_0_path': 'C:\\Windows\\System32\\cmd.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': '6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b', 'fileStates_0_sha256': '6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518255317590087645_da637123660281149084_-953649836:s8JiygMV1ntGagdMudjSLVknmDJpM2Py5TywIR050Jc=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Suspected credential theft activity', 'comments': [], 'createdDateTime': '2019-12-19T15:27:07.7711541Z', 'description': 'This program exhibits suspect characteristics potentially associated with credential theft.  Once obtained, these credentials are often used in lateral movement activities to infiltrate other machines and servers in the network.', 'detectionIds': [], 'eventDateTime': '2019-12-19T15:24:00.9912354Z', 'lastModifiedDateTime': '2019-12-19T15:27:13.7326316Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'medium', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518255317590087645_da637123660281149084_-953649836:s8JiygMV1ntGagdMudjSLVknmDJpM2Py5TywIR050Jc=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660281149084_-953649836', 'status': 'newAlert', 'title': 'Suspected credential theft activity', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'cmd.exe', 'fileStates_0_path': 'C:\\Windows\\System32\\cmd.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': '6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b', 'fileStates_0_sha256': '6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518255317590087645_da637123660275108740_1307429309:aLzgnH1c+c34Pr34M9XKv3kw3+eFR_4KTtOfRwzPEsc=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Malicious credential theft tool execution detected', 'comments': [], 'createdDateTime': '2019-12-19T15:27:07.1046226Z', 'description': "A known credential theft tool execution command line was detected.\nEither the process itself or its command line indicated an intent to dump users' credentials, keys, plain-text passwords and more.", 'detectionIds': [], 'eventDateTime': '2019-12-19T15:24:00.9912354Z', 'lastModifiedDateTime': '2019-12-19T15:27:13.7301763Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'high', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518255317590087645_da637123660275108740_1307429309:aLzgnH1c+c34Pr34M9XKv3kw3+eFR_4KTtOfRwzPEsc=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660275108740_1307429309', 'status': 'newAlert', 'title': 'Malicious credential theft tool execution detected', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'mimikatz.exe', 'fileStates_0_path': 'C:\\tools\\x64\\mimikatz.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'fileStates_0_sha256': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}, {'id': '2518255317590087645_da637123660281149084_-953649836:QZwuEMZFw_9KajuFRp9Dkq9ypMgKuspzliv+0DPbS64=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df', 'azureTenantId': 'b73e5ba8-34d5-495a-9901-06bdb84cf13e', 'azureSubscriptionId': '083de1fb-cd2d-4b7c-895a-2b5af1d091e8', 'tags': [], 'category': 'Suspected credential theft activity', 'comments': [], 'createdDateTime': '2019-12-19T15:27:08.504905Z', 'description': 'This program exhibits suspect characteristics potentially associated with credential theft.  Once obtained, these credentials are often used in lateral movement activities to infiltrate other machines and servers in the network.', 'detectionIds': [], 'eventDateTime': '2019-12-19T15:24:00.9912354Z', 'lastModifiedDateTime': '2019-12-19T15:27:13.4695022Z', 'recommendedActions_0': '1. Make sure the machine is completely updated and all your software has the latest patch.', 'recommendedActions_1': '2. Contact your incident response team. NOTE: If you don’t have an incident response team, contact Microsoft Support for architectural remediation and forensic.', 'recommendedActions_2': '3. Install and run Microsoft’s Malicious Software Removal Tool (see https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx).', 'recommendedActions_3': '4. Run Microsoft’s Autoruns utility and try to identify unknown applications that are configured to run at login (see https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx).', 'recommendedActions_4': '5. Run Process Explorer and try to identify unknown running processes (see https://technet.microsoft.com/en-us/sysinternals/bb896653.aspx).', 'severity': 'medium', 'sourceMaterials_0': 'https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2518255317590087645_da637123660281149084_-953649836:QZwuEMZFw_9KajuFRp9Dkq9ypMgKuspzliv+0DPbS64=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df/subscriptionId/083de1fb-cd2d-4b7c-895a-2b5af1d091e8/resourceGroup/eastUS/referencedFrom/alertDeepLink/location/westeurope', 'sourceMaterials_1': 'https://securitycenter.windows.com/alert/da637123660281149084_-953649836', 'status': 'newAlert', 'title': 'Suspected credential theft activity', 'vendorInformation_provider': 'ASC', 'vendorInformation_subProvider': 'MDATP', 'vendorInformation_vendor': 'Microsoft', 'cloudAppStates': [], 'fileStates_0_name': 'mimikatz.exe', 'fileStates_0_path': 'C:\\tools\\x64\\mimikatz.exe', 'fileStates_0_fileHash_hashType': 'sha256', 'fileStates_0_fileHash_hashValue': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'fileStates_0_sha256': 'bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde', 'hostStates_0_netBiosName': 'winsrv-target', 'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [], 'userStates_0_accountName': 'testadmin', 'userStates_0_domainName': 'winsrv-target', 'userStates_0_emailRole': 'unknown', 'userStates_0_userPrincipalName': 'testadmin@winsrv-target', 'vulnerabilityStates': [], 'event_count': '1'}]"`


Will return the following STIX observable:

```json
{
    "type": "bundle",
    "id": "bundle--85f43de7-4165-4917-9eee-29e64628502b",
    "objects": [
        {
            "type": "identity",
            "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "name": "azure_sentinel",
            "identity_class": "events"
        },
        {
            "id": "observed-data--b7f6f0e1-cbd0-4930-abc1-94a818f07df9",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.494Z",
            "modified": "2020-01-03T10:37:11.494Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "cmd.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\Windows\\System32"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518254730385772806_da637123660281149084_-953649836:4wVg68RS3EYNc3Qb7xJUNrYw9KEUBA1wZ3IVwRA0hmg=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Suspected credential theft activity",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-20T07:42:41.4227193Z",
            "last_observed": "2019-12-20T07:42:41.4227193Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--4d6a655b-aea8-48dd-b320-e488362d96d5",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.497Z",
            "modified": "2020-01-03T10:37:11.497Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "mimikatz.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\tools\\mimikatz-master\\lib\\x64"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518254730385772806_da637123660281149084_-953649836:JGqJp4SlSroeE_6c3bZL6R6oWUal2lFJRO3d6N8jgyk=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Suspected credential theft activity",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-20T07:42:41.4227193Z",
            "last_observed": "2019-12-20T07:42:41.4227193Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--9ff66153-1bc7-4a29-a4d7-ac2c369bdbc3",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.499Z",
            "modified": "2020-01-03T10:37:11.499Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "mimikatz.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\tools\\mimikatz-master\\lib\\x64"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518254730385772806_da637124247028408126_-1879876458:BBCp8DC2k8qr4fp7Msgx48xH9gEpcDzr23iW5U13eOY=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Malicious credential theft tool execution detected",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-20T07:42:41.4227193Z",
            "last_observed": "2019-12-20T07:42:41.4227193Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--327c615d-743c-4356-9fef-d13fde3266c8",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.500Z",
            "modified": "2020-01-03T10:37:11.500Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "mimikatz.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\tools\\x64"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518254749537640003_da637123660281149084_-953649836:DZoKKwpp8DW6oF3Qs7ofnbkJihHMQSZR7jb02CnqdYU=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Suspected credential theft activity",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-20T07:10:46.2359996Z",
            "last_observed": "2019-12-20T07:10:46.2359996Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--10ba0679-ebc1-4835-8372-da41b4ff80a4",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.502Z",
            "modified": "2020-01-03T10:37:11.502Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "mimikatz.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\tools\\x64"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518254749496473232_da637123660275108740_1307429309:OMwAtExvCXaspczkTQBVXBsi2dv0wWIN9FDBz7OdYPA=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Malicious credential theft tool execution detected",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-20T07:10:50.3526767Z",
            "last_observed": "2019-12-20T07:10:50.3526767Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--69abf25f-9b9b-4d59-bbff-ebbd2eb0ad6a",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.503Z",
            "modified": "2020-01-03T10:37:11.503Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "cmd.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\Windows\\System32"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518254749537640003_da637123660281149084_-953649836:3f_1OC23WuGNSs1hCfnrXClrrAx1IFQudnU9lMzh_uk=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Suspected credential theft activity",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-20T07:10:46.2359996Z",
            "last_observed": "2019-12-20T07:10:46.2359996Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--7bb69986-d7bf-474d-a3da-28849e7bc540",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.505Z",
            "modified": "2020-01-03T10:37:11.505Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "cmd.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "6f88fb88ffb0f1d5465c2826e5b4f523598b1b8378377c8378ffebc171bad18b"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\Windows\\System32"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518255317590087645_da637123660281149084_-953649836:s8JiygMV1ntGagdMudjSLVknmDJpM2Py5TywIR050Jc=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Suspected credential theft activity",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-19T15:24:00.9912354Z",
            "last_observed": "2019-12-19T15:24:00.9912354Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--df61837d-0fa1-49b2-a1c3-c902c424d83d",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.506Z",
            "modified": "2020-01-03T10:37:11.506Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "mimikatz.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\tools\\x64"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518255317590087645_da637123660275108740_1307429309:aLzgnH1c+c34Pr34M9XKv3kw3+eFR_4KTtOfRwzPEsc=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Malicious credential theft tool execution detected",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-19T15:24:00.9912354Z",
            "last_observed": "2019-12-19T15:24:00.9912354Z",
            "number_observed": 1
        },
        {
            "id": "observed-data--29cb4361-05c0-45fd-b929-37feb0ed378a",
            "type": "observed-data",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-03T10:37:11.508Z",
            "modified": "2020-01-03T10:37:11.508Z",
            "objects": {
                "0": {
                    "type": "file",
                    "name": "mimikatz.exe",
                    "parent_directory_ref": "1",
                    "hashes": {
                        "SHA-256": "bf1a1daac21d3807924d0d3d13282bc020a6e1d9c634963667ec5e746c409bde"
                    }
                },
                "1": {
                    "type": "directory",
                    "path": "C:\\tools\\x64"
                },
                "2": {
                    "type": "domain-name",
                    "value": "winsrv-target"
                },
                "3": {
                    "type": "user-account",
                    "user_id": "testadmin"
                }
            },
            "x_com_msazure_sentinel_alert": {
                "id": "2518255317590087645_da637123660281149084_-953649836:QZwuEMZFw_9KajuFRp9Dkq9ypMgKuspzliv+0DPbS64=:WS44c473f9-e9bf-4c71-b40f-3cfd549c34df",
                "title": "Suspected credential theft activity",
                "provider": "ASC",
                "vendor": "Microsoft"
            },
            "x_com_msazure_sentinel": {
                "tenant_id": "b73e5ba8-34d5-495a-9901-06bdb84cf13e",
                "subscription_id": "083de1fb-cd2d-4b7c-895a-2b5af1d091e8"
            },
            "first_observed": "2019-12-19T15:24:00.9912354Z",
            "last_observed": "2019-12-19T15:24:00.9912354Z",
            "number_observed": 1
        }
    ]
}
```

Translated STIX attributes are inserted into the OData query in the order they are defined in the mapping file. <br/>

### Operator Support (Data Source)
| STIX Operator | Sample STIX expr | Sentinel Operator | Sample Native Expr |
| :---: | :---: | :---: | :---: |
| AND | [process:name = 'services.exe’] AND [network-traffic:dst_ref.value = '52.94.233.129']  | and | Both the observation expressions are handled as a single query joined with and operator. |
| OR | [process:name = 'services.exe’] OR [network-traffic:dst_ref.value = '52.94.233.129']  | or | Both the observation expressions are handled as a single query joined with or operator. |
| = | [network-traffic:dst_port=22]  | eq | networkConnections/any(q1:q1/destinationPort eq ‘22')  |
| != | [network-traffic:dst_port!=22]  | ne | networkConnections/any(q1:q1/destinationPort ne ‘22')  |
| '<' | [network-traffic:dst_port<22]  | lt | networkConnections/any(q1:q1/destinationPort lt ‘22')  |
| '>' | [network-traffic:dst_port>22]  | gt | networkConnections/any(q1:q1/destinationPort gt ‘22')  |
| '<=' | [network-traffic:dst_port<=22]  | le | networkConnections/any(q1:q1/destinationPort le ‘22') |
| '>=' | [network-traffic:dst_port>=22]  | ge | networkConnections/any(q1:q1/destinationPort ge ‘22') |
| IN | [network-traffic:dst_port IN (22, 3389)]  | eq(equals) with multiple (or) operator | networkConnections/any(a1:a1/destinationPort eq '22') or networkConnections/any(a1:a1/destinationPort eq '3389') |
| NOT IN | [network-traffic:dst_port NOT IN (22, 3389)]  | ne(not equals) with multiple (and) operator | networkConnections/any(a1:a1/destinationPort ne '22’) and networkConnections/any(a1:a1/destinationPort ne '3389' |
| LIKE, _: any one character, % - zero or more characters | process:name LIKE ‘%exe' | contains | processes/any(n:contains(n/name, 'exe')) |
| Matches | File:name MATCHES ‘.exe’ | contains | processes/any(n:contains(n/name, 'exe')) |
| NOT | network-traffic:dst_port NOT > 22 | Reversal of trailing operator behavior. | networkConnections/any(a1:a1/destinationPort le ‘22')  |
| ISSUBSET, ISSUPERSET | - | Not Supported | - |


### Odata query construction: IN clause

STIX attributes that map to multiple sentinel fields will have those fields joined by ORs in the returned query with comparator operator as 'equals' (custom logic) . <br/>

### Odata query construction: NOT IN clause

STIX attributes that map to multiple sentinel fields will have those fields joined by ANDs in the returned query with comparator operator as 'not equals' (custom logic). <br/>

### Odata query construction: NOT (negation) operator

STIX attributes that map to multiple sentinel fields will have those fields with comparator operator reversed. This reversal is effected for all the combinations (custom logic) <br/>

### Exclusions 
Sentinel does not support operator support for the following attributes,

`IN/NOT-IN Operator`
* x_com_msazure_sentinel_alert:provider
* x_com_msazure_sentinel_alert:vendor


`LIKE Operator` 
* process:pid
* process:parent_ref.pid
* user-account:account_last_login

