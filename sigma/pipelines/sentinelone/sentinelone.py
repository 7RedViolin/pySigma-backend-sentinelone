from sigma.processing.conditions import LogsourceCondition
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaDetectionItem
from sigma.exceptions import SigmaTransformationError

class InvalidFieldTransformation(DetectionItemFailureTransformation):
    """
    Overrides the apply_detection_item() method from DetectionItemFailureTransformation to also include the field name
    in the error message
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field_name = detection_item.field
        self.message = f"Invalid SigmaDetectionItem field name encountered: {field_name}. " + self.message
        raise SigmaTransformationError(self.message)


def _flatten(items, seqtypes=(list, tuple)):
    """Private function to flatten lists for Field mapping errors"""
    try:
        for i, x in enumerate(items):
            while isinstance(items[i], seqtypes):
                items[i:i+1] = items[i]
    except IndexError:
        pass
    return items

def sentinelone_pipeline() -> ProcessingPipeline:

    general_supported_fields = [
        'ObjectType',
        'EventType'
    ]

    translation_dict = {
        'process_creation':{                
            "ProcessId":"TgtProcPID",
            "Image":"TgtProcImagePath",
            "Description":"TgtProcDisplayName", #Not sure whether this should be Description or Product???
            "Product":"TgtProcDisplayName",
            "Company":"TgtProcPublisher",
            "CommandLine":"TgtProcCmdLine",
            "CurrentDirectory":"TgtProcImagePath",
            "User":"TgtProcUser",
            "TerminalSessionId":"TgtProcSessionId",
            "IntegrityLevel":"TgtProcIntegrityLevel",
            "md5":"TgtProcMd5",
            "sha1":"TgtProcSha1",
            "sha256":"TgtProcSha256",
            "ParentProcessId":"SrcProcPID",
            "ParentImage":"SrcProcImagePath",
            "ParentCommandLine":"SrcProcCmdLine",
        },
        'file':{
            "Image": "SrcProcImagePath",
            "CommandLine":"SrcProcCmdLine",
            "ParentImage":"SrcProcParentImagePath",
            "ParentCommandLine":"SrcProcParentCmdline",
            "TargetFilename":"TgtFilePath", 
            "SourceFilename":"TgtFileOldPath",
            "User":"SrcProcUser"
        },
        'image_load':{
            "ImageLoaded":"ModulePath",
            "Image": "SrcProcImagePath",
            "CommandLine":"SrcProcCmdLine",
            "ParentImage":"SrcProcParentImagePath",
            "ParentCommandLine":"SrcProcParentCmdline",
            "sha1":"ModuleSha1",
            "md5": "ModuleMd5"
        },
        'pipe_creation':{
            "PipeName":"NamedPipeName",
            "Image": "SrcProcImagePath",
            "CommandLine":"SrcProcCmdLine",
            "ParentImage":"SrcProcParentImagePath",
            "ParentCommandLine":"SrcProcParentCmdline",
        },
        'registry':{
            "Image": "SrcProcImagePath",
            "CommandLine":"SrcProcCmdLine",
            "ParentImage":"SrcProcParentImagePath",
            "ParentCommandLine":"SrcProcParentCmdline",
            "TargetObject": "RegistryKeyPath",
            "Details": "RegistryValue"
        },
        'dns':{
            "Image": "SrcProcImagePath",
            "CommandLine":"SrcProcCmdLine",
            "ParentImage":"SrcProcParentImagePath",
            "ParentCommandLine":"SrcProcParentCmdline",
            "query": "DnsRequest",
            "answer":"DnsResponse",
            "QueryName": "DnsRequest",
            "record_type":"DnsResponse"
        },
        'network':{
            "Image": "SrcProcImagePath",
            "CommandLine":"SrcProcCmdLine",
            "ParentImage":"SrcProcParentImagePath",
            "ParentCommandLine":"SrcProcParentCmdline",
            "DestinationHostname":["Url", "DnsRequest"],
            "DestinationPort":"DstPort",
            "DestinationIp":"DstIP",
            "User":"SrcProcUser",
            "SourceIp":"SrcIP",
            "SourcePort":"SrcPort",
            "Protocol":"NetProtocolName",
            "dst_ip":"DstIP",
            "src_ip":"SrcIP",
            "dst_port":"DstPort",
            "src_port":"SrcPort"
        }
    }

    os_filter = [
        # Add EndpointOS = Linux
        ProcessingItem(
            identifier="s1_linux_product",
            transformation=AddConditionTransformation({
                "EndpointOS": "linux"
            }),
            rule_conditions=[
                LogsourceCondition(product="linux")
            ]
        ),
        # Add EndpointOS = Windows
        ProcessingItem(
            identifier="s1_windows_product",
            transformation=AddConditionTransformation({
                "EndpointOS": "windows"
            }),
            rule_conditions=[
                LogsourceCondition(product="windows")
            ]
        ),
        # Add EndpointOS = OSX
        ProcessingItem(
            identifier="s1_osx_product",
            transformation=AddConditionTransformation({
                "EndpointOS":"osx"
            }),
            rule_conditions=[
                LogsourceCondition(product="macos")
            ]
        )
    ]

    object_event_type_filter = [
        # Add EventType = Process Creation
        ProcessingItem(
            identifier="s1_process_creation_eventtype",
            transformation=AddConditionTransformation({
                "EventType": "Process Creation"
            }),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        # Add ObjectType = "File"
        ProcessingItem(
            identifier="s1_file_event_objecttype",
            transformation=AddConditionTransformation({
                "ObjectType": "File"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_event")
            ]
        ),
        # Add EventType = "File Modification"
        ProcessingItem(
            identifier="s1_file_change_eventtype",
            transformation=AddConditionTransformation({
                "EventType": "File Modification"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_change")
            ]
        ),
        # Add EventType = "File Rename"
        ProcessingItem(
            identifier="s1_file_rename_eventtype",
            transformation=AddConditionTransformation({
                "EventType": "File Rename"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_rename")
            ]
        ),
        # Add EventType = "File Delete"
        ProcessingItem(
            identifier="s1_file_delete_eventtype",
            transformation=AddConditionTransformation({
                "EventType": "File Delete"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_delete")
            ]
        ),
        # Add EventType = "Module Load"
        ProcessingItem(
            identifier="s1_image_load_eventtype",
            transformation=AddConditionTransformation({
                "EventType": "ModuleLoad"
            }),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Add EventType for Pipe Creation
        ProcessingItem(
            identifier="s1_pipe_creation_eventtype",
            transformation=AddConditionTransformation({
                "EventType": "Named Pipe Creation"
            }),
            rule_conditions=[
                LogsourceCondition(category="pipe_creation")
            ]
        ),
        # Add ObjectType for Registry Stuff
        ProcessingItem(
            identifier="s1_registry_eventtype",
            transformation=AddConditionTransformation({
                "ObjectType": "Registry"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set")
            ]
        ),
        # Add ObjectType for DNS Stuff
        ProcessingItem(
            identifier="s1_dns_objecttype",
            transformation=AddConditionTransformation({
                "ObjectType":"DNS"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns")
            ]
        ),
        # Add ObjectType for Network Stuff
        ProcessingItem(
            identifier="s1_network_objecttype",
            transformation=AddConditionTransformation({
                "ObjectType": ["DNS","Url","IP"]
            }),
            rule_conditions=[
                LogsourceCondition(category="network_connection")
            ]
        )
    ]

    field_mappings = [
        # Process Creation
        ProcessingItem(
            identifier="s1_process_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['process_creation']),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        # File Stuff
        ProcessingItem(
            identifier="s1_file_change_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['file']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event")
            ]
        ),
        # Module Load Stuff
        ProcessingItem(
            identifier="s1_image_load_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['image_load']),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Pipe Creation Stuff
        ProcessingItem(
            identifier="s1_pipe_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['pipe_creation']),
            rule_conditions=[
                LogsourceCondition(category="pipe_creation")
            ]
        ),
        # Registry Stuff
        ProcessingItem(
            identifier="s1_registry_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['registry']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set")
            ]
        ),
        # DNS Stuff
        ProcessingItem(
            identifier="s1_dns_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['dns']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns")
            ]
        ),
        # Network Stuff
        ProcessingItem(
            identifier="s1_network_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['network']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        )
    ]

    change_logsource_info = [
        # Add service to be SentinelOne for pretty much everything
        ProcessingItem(
            identifier="s1_logsource",
            transformation=ChangeLogsourceTransformation(
                service="sentinelone"
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="image_load"),
                LogsourceCondition(category="pipe_creation"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="dns"),
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),
    ]

    unsupported_rule_types = [
        # Show error if unsupported option
        ProcessingItem(
            identifier="s1_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation("Rule type not yet supported by the SentinelOne Sigma backend"),
            rule_condition_negation=True,
            rule_conditions=[
                RuleProcessingItemAppliedCondition("s1_logsource")
            ]
        )
    ]

    unsupported_field_name = [
        ProcessingItem(
            identifier='s1_fail_field_not_supported',
            transformation=InvalidFieldTransformation("This pipeline only supports the following fields:\n{" + 
            '}, {'.join(sorted(set(
                list(_flatten([[k,v] for t in translation_dict.keys() for k, v in
                               translation_dict[t].items()])) + general_supported_fields
            )))),
            field_name_conditions=[
                ExcludeFieldCondition(fields=list(set(
                    list(_flatten([[k, v] for t in translation_dict.keys() for k, v in
                                   translation_dict[t].items()])) + general_supported_fields
                )))
            ]
        )
    ]

    return ProcessingPipeline(
        name="SentinelOne pipeline",
        priority=50,
        items = [
            *unsupported_field_name,
            *os_filter,
            *object_event_type_filter,
            *field_mappings,
            *change_logsource_info,
            *unsupported_rule_types,
        ]
    )