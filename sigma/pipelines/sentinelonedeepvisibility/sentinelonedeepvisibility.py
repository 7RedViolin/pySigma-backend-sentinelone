from sigma.processing.conditions import LogsourceCondition
from sigma.pipelines.common import logsource_windows_dns_query
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def sentinelonedeepvisibility_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="SentinelOne Deep Visibility pipeline",
        allowed_backends=frozenset(),                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items = [
            # Add service to be SentinelOne for pretty much everything
            ProcessingItem(
                identifier="s1_dv_logsource",
                transformation=ChangeLogsourceTransformation(
                    service="sentinelone_deepvisibility"
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
                    LogsourceCondition(category="registry_set")
                ]
            ),
            # Add EndpointOS = Linux
            ProcessingItem(
                identifier="s1_dv_linux_product",
                transformation=AddConditionTransformation({
                    "EndpointOS": "linux"
                }),
                rule_conditions=[
                    LogsourceCondition(product="linux")
                ]
            ),
            # Add EndpointOS = Windows
            ProcessingItem(
                identifier="s1_dv_windows_product",
                transformation=AddConditionTransformation({
                    "EndpointOS": "windows"
                }),
                rule_conditions=[
                    LogsourceCondition(product="windows")
                ]
            ),
            # Add EventType = Process Creation
            ProcessingItem(
                identifier="s1_dv_process_creation_eventtype",
                transformation=AddConditionTransformation({
                    "EventType": "Process Creation"
                }),
                rule_conditions=[
                    LogsourceCondition(category="process_creation")
                ]
            ),
            # Map Fields for Process Creation
            ProcessingItem(
                identifier="s1_dv_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ProcessId":"TgtProcPID",
                    "Image":"TgtProcName",
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
                    "ParentImage":"SrcProcName",
                    "ParentCommandLine":"SrcProcCmdLine",
                }),
                rule_conditions=[
                    LogsourceCondition(category="process_creation")
                ]
            ),
            # Map Fields for File Stuff
            ProcessingItem(
                identifier="s1_dv_file_change_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Image": "SrcProcName",
                    "CommandLine":"SrcProcCmdLine",
                    "ParentImage":"SrcProcParentName",
                    "ParentCommandLine":"SrcProcParentCmdline",
                    "TargetFilename":"TgtFilePath", 
                    "SourceFilename":"TgtFileOldPath",
                    "user":"SrcProcUser"
                }),
                rule_condition_linking=any,
                rule_conditions=[
                    LogsourceCondition(category="file_change"),
                    LogsourceCondition(category="file_rename"),
                    LogsourceCondition(category="file_delete"),
                    LogsourceCondition(category="file_event")
                ]
            ),
            # Add ObjectType = "File"
            ProcessingItem(
                identifier="s1_dv_file_event_objecttype",
                transformation=AddConditionTransformation({
                    "ObjectType": "File"
                }),
                rule_conditions=[
                    LogsourceCondition(category="file_event")
                ]
            ),
            # Add EventType = "File Modification"
            ProcessingItem(
                identifier="s1_dv_file_change_eventtype",
                transformation=AddConditionTransformation({
                    "EventType": "File Modification"
                }),
                rule_conditions=[
                    LogsourceCondition(category="file_change")
                ]
            ),
            # Add EventType = "File Rename"
            ProcessingItem(
                identifier="s1_dv_file_rename_eventtype",
                transformation=AddConditionTransformation({
                    "EventType": "File Rename"
                }),
                rule_conditions=[
                    LogsourceCondition(category="file_rename")
                ]
            ),
            # Add EventType = "File Delete"
            ProcessingItem(
                identifier="s1_dv_file_delete_eventtype",
                transformation=AddConditionTransformation({
                    "EventType": "File Delete"
                }),
                rule_conditions=[
                    LogsourceCondition(category="file_delete")
                ]
            ),
            # Add EventType = "Module Load"
            ProcessingItem(
                identifier="s1_dv_image_load_eventtype",
                transformation=AddConditionTransformation({
                    "EventType": "ModuleLoad"
                }),
                rule_conditions=[
                    LogsourceCondition(category="image_load")
                ]
            ),
            # Map Fields for Module Load Stuff
            ProcessingItem(
                identifier="s1_dv_image_load_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ImageLoaded":"ModulePath",
                    "Image": "SrcProcName",
                    "CommandLine":"SrcProcCmdLine",
                    "ParentImage":"SrcProcParentName",
                    "ParentCommandLine":"SrcProcParentCmdline",
                    "sha1":"ModuleSha1",
                    "md5": "ModuleMd5"
                }),
                rule_conditions=[
                    LogsourceCondition(category="image_load")
                ]
            ),
            # Add EventType for Pipe Creation
            ProcessingItem(
                identifier="s1_dv_pipe_creation_eventtype",
                transformation=AddConditionTransformation({
                    "EventType": "Named Pipe Creation"
                }),
                rule_conditions=[
                    LogsourceCondition(category="pipe_creation")
                ]
            ),
            # Map Fields for Pipe Creation Stuff
            ProcessingItem(
                identifier="s1_dv_pipe_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "PipeName":"NamedPipeName",
                    "Image": "SrcProcName",
                    "CommandLine":"SrcProcCmdLine",
                    "ParentImage":"SrcProcParentName",
                    "ParentCommandLine":"SrcProcParentCmdline",
                }),
                rule_conditions=[
                    LogsourceCondition(category="pipe_creation")
                ]
            ),
            # Add ObjectType for Registry Stuff
            ProcessingItem(
                identifier="s1_dv_registry_eventtype",
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
            # Map Fields for Registry Stuff
            ProcessingItem(
                identifier="s1_dv_registry_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Image": "SrcProcName",
                    "CommandLine":"SrcProcCmdLine",
                    "ParentImage":"SrcProcParentName",
                    "ParentCommandLine":"SrcProcParentCmdline",
                    "TargetObject": "RegistryKeyPath",
                    "Details": "RegistryValue"
                }),
                rule_condition_linking=any,
                rule_conditions=[
                    LogsourceCondition(category="registry_add"),
                    LogsourceCondition(category="registry_delete"),
                    LogsourceCondition(category="registry_event"),
                    LogsourceCondition(category="registry_set")
                ]
            ),
            # DNS Connection
            # Add ObjectType = DNS
            ProcessingItem(
                identifier="s1_dv_dns_query_eventtype",
                transformation=AddConditionTransformation({
                    "ObjectType":"DNS"
                }),
                rule_conditions=[
                    logsource_windows_dns_query()
                ]
            ),
            # Map DNS Fields
            ProcessingItem(
                identifier="s1_dv_dns_query_filedmapping",
                transformation=FieldMappingTransformation({
                    "query":"DnsRequest",
                    "answer":"DnsResponse"
                }),
                rule_conditions=[
                    logsource_windows_dns_query()
                ]
            ),
            # Set service to be SentinelOne and category to be DNS Query
            ProcessingItem(
                identifier="s1_dv_dns_query_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="dns_query",
                    service="sentinelone_deepvisibility"
                ),
                rule_conditions=[
                    logsource_windows_dns_query()
                ]
            ),

            # Show error if unsupported option
            ProcessingItem(
                identifier="s1_dv_fail_rule_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation("Rule type not yet supported by the SentinelOne Deep Visibility Sigma backend"),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("s1_dv_logsource")
                ]
            )
        ]
    )