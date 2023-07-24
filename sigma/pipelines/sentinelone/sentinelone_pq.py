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

def sentinelonepq_pipeline() -> ProcessingPipeline:

    general_supported_fields = [
        'event.category',
        'event.type'
    ]

    translation_dict = {
        'process_creation':{
            "ProcessId":"tgt.process.pid",
            "Image":"tgt.process.image.path",
            "Description":"tgt.process.displayName", #Not sure whether this should be Description or Product???
            "Publisher": "tgt.process.publisher",
            "Product":"tgt.process.displayName",
            "Company":"tgt.process.publisher",
            "CommandLine":"tgt.process.cmdline",
            "CurrentDirectory":"tgt.process.image.path",
            "User":"tgt.process.user",
            "TerminalSessionId":"tgt.process.sessionid",
            "IntegrityLevel":"tgt.process.integrityLevel",
            "md5":"tgt.process.image.md5",
            "sha1":"tgt.process.image.sha1",
            "sha256":"tgt.process.image.sha256",
            "ParentProcessId":"src.process.pid",
            "ParentImage":"src.process.image.path",
            "ParentCommandLine":"src.process.cmdline",
        },
        'file':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "TargetFilename":"tgt.file.path", 
            "SourceFilename":"tgt.file.oldPath",
            "User":"src.process.user"
        },
        'image_load':{
            "ImageLoaded":"module.path",
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "sha1":"module.sha1",
            "md5": "module.md5"
        },
        'pipe_creation':{
            "PipeName":"namedPipe.name",
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
        },
        'registry':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "TargetObject": "registry.keyPath",
            "Details": "registry.value"
        },
        'dns':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "query": "event.dns.request",
            "answer":"event.dns.response",
            "QueryName": "event.dns.request",
            "record_type":"event.dns.response"
        },
        'network':{
            "Image": "src.process.image.path",
            "CommandLine":"src.process.cmdline",
            "ParentImage":"src.process.parent.image.path",
            "ParentCommandLine":"src.process.parent.cmdline",
            "DestinationHostname":["url.address", "event.dns.request"],
            "DestinationPort":"dst.port.number",
            "DestinationIp":"dst.ip.address",
            "User":"src.process.user",
            "SourceIp":"src.ip.address",
            "SourcePort":"src.port.number",
            "Protocol":"NetProtocolName",
            "dst_ip":"dst.ip.address",
            "src_ip":"src.ip.address",
            "dst_port":"dst.port.number",
            "src_port":"src.port.number"
        }
    }

    os_filter = [
        # Add EndpointOS = Linux
        ProcessingItem(
            identifier="s1_pq_linux_product",
            transformation=AddConditionTransformation({
                "endpoint.os": "linux"
            }),
            rule_conditions=[
                LogsourceCondition(product="linux")
            ]
        ),
        # Add EndpointOS = Windows
        ProcessingItem(
            identifier="s1_pq_windows_product",
            transformation=AddConditionTransformation({
                "endpoint.os": "windows"
            }),
            rule_conditions=[
                LogsourceCondition(product="windows")
            ]
        ),
        # Add EndpointOS = OSX
        ProcessingItem(
            identifier="s1_pq_osx_product",
            transformation=AddConditionTransformation({
                "endpoint.os":"osx"
            }),
            rule_conditions=[
                LogsourceCondition(product="macos")
            ]
        )
    ]

    object_event_type_filter = [
        # Add EventType = Process Creation
        ProcessingItem(
            identifier="s1_pq_process_creation_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "Process Creation"
            }),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        # Add ObjectType = "File"
        ProcessingItem(
            identifier="s1_pq_file_event_objecttype",
            transformation=AddConditionTransformation({
                "event.category": "file"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_event")
            ]
        ),
        # Add EventType = "File Modification"
        ProcessingItem(
            identifier="s1_pq_file_change_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "File Modification"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_change")
            ]
        ),
        # Add EventType = "File Rename"
        ProcessingItem(
            identifier="s1_pq_file_rename_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "File Rename"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_rename")
            ]
        ),
        # Add EventType = "File Delete"
        ProcessingItem(
            identifier="s1_pq_file_delete_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "File Delete"
            }),
            rule_conditions=[
                LogsourceCondition(category="file_delete")
            ]
        ),
        # Add EventType = "Module Load"
        ProcessingItem(
            identifier="s1_pq_image_load_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "ModuleLoad"
            }),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Add EventType for Pipe Creation
        ProcessingItem(
            identifier="s1_pq_pipe_creation_eventtype",
            transformation=AddConditionTransformation({
                "event.type": "Named Pipe Creation"
            }),
            rule_conditions=[
                LogsourceCondition(category="pipe_creation")
            ]
        ),
        # Add ObjectType for Registry Stuff
        ProcessingItem(
            identifier="s1_pq_registry_eventtype",
            transformation=AddConditionTransformation({
                "event.category": "Registry"
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
            identifier="s1_pq_dns_objecttype",
            transformation=AddConditionTransformation({
                "event.category":"DNS"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns")
            ]
        ),
        # Add ObjectType for Network Stuff
        ProcessingItem(
            identifier="s1_pq_network_objecttype",
            transformation=AddConditionTransformation({
                "event.category": ["DNS","Url","IP"]
            }),
            rule_conditions=[
                LogsourceCondition(category="network_connection")
            ]
        )
    ]

    field_mappings = [
        # Process Creation
        ProcessingItem(
            identifier="s1_pq_process_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['process_creation']),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        # File Stuff
        ProcessingItem(
            identifier="s1_pq_file_change_fieldmapping",
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
            identifier="s1_pq_image_load_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['image_load']),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Pipe Creation Stuff
        ProcessingItem(
            identifier="s1_pq_pipe_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['pipe_creation']),
            rule_conditions=[
                LogsourceCondition(category="pipe_creation")
            ]
        ),
        # Registry Stuff
        ProcessingItem(
            identifier="s1_pq_registry_fieldmapping",
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
            identifier="s1_pq_dns_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['dns']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns")
            ]
        ),
        # Network Stuff
        ProcessingItem(
            identifier="s1_pq_network_fieldmapping",
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
            identifier="s1_pq_logsource",
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
            identifier="s1_pq_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation("Rule type not yet supported by the SentinelOne PQ Sigma backend"),
            rule_condition_negation=True,
            rule_conditions=[
                RuleProcessingItemAppliedCondition("s1_pq_logsource")
            ]
        )
    ]

    unsupported_field_name = [
        ProcessingItem(
            identifier='s1_pq_fail_field_not_supported',
            transformation=InvalidFieldTransformation("This pipeline only supports the following fields:\n{" + 
            '}, {'.join(sorted(set(sum([list(translation_dict[x].keys()) for x in translation_dict.keys()],[])))) + '}'),
            field_name_conditions=[
                ExcludeFieldCondition(fields=list(set(sum([list(translation_dict[x].keys()) for x in translation_dict.keys()],[]))) + general_supported_fields)
            ]
        )
    ]

    return ProcessingPipeline(
        name="SentinelOne PQ pipeline",
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