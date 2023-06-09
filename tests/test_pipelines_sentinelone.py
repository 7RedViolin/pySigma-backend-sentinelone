import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone import SentinelOneBackend

@pytest.fixture
def sentinelone_backend():
    return SentinelOneBackend()

def test_sentinelone_windows_os_filter(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath = "valueA")']

def test_sentinelone_linux_os_filter(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['EventType = "Process Creation" AND (EndpointOS = "linux" AND TgtProcImagePath = "valueA")']

def test_sentinelone_osx_os_filter(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['EventType = "Process Creation" AND (EndpointOS = "osx" AND TgtProcImagePath = "valueA")']

def test_sentinelone_process_creation_mapping(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    Description: foo bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: /etc
                    User: administrator
                    TerminalSessionId: 4
                    IntegrityLevel: bar bar
                    md5: asdfasdfasdfasdfasdf
                    sha1: asdfasdfasdfasdfasdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    ) == ['EventType = "Process Creation" AND (TgtProcPID = "12" AND TgtProcImagePath = "valueA" AND TgtProcDisplayName = "foo bar" AND ' +
          'TgtProcDisplayName = "bar foo" AND TgtProcPublisher = "foo foo" AND TgtProcCmdLine = "invoke-mimikatz" AND ' +
          'TgtProcImagePath = "/etc" AND TgtProcUser = "administrator" AND TgtProcSessionId = "4" AND ' +
          'TgtProcIntegrityLevel = "bar bar" AND TgtProcMd5 = "asdfasdfasdfasdfasdf" AND ' + 
          'TgtProcSha1 = "asdfasdfasdfasdfasdfasdf" AND TgtProcSha256 = "asdfasdfasdfasdfasdfasdfasdfasdf" AND SrcProcPID = "13" AND ' +
          'SrcProcImagePath = "valueB" AND SrcProcCmdLine = "Get-Path")']

def test_sentinelone_file_mapping(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: file_event
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    TargetFilename: foo bar
                    SourceFilename: bar foo
                    User: administrator
                condition: sel
        """)
    ) == ['ObjectType = "File" AND (SrcProcImagePath = "valueA" AND SrcProcCmdLine = "invoke-mimikatz" AND ' +
          'SrcProcParentImagePath = "valueB" AND SrcProcParentCmdline = "Get-Path" AND TgtFilePath = "foo bar" AND ' + 
          'TgtFileOldPath = "bar foo" AND SrcProcUser = "administrator")']

def test_sentinelone_image_load_mapping(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: image_load
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    sha1: asdfasdf
                    md5: asdfasdfasdf
                    ImageLoaded: foo bar
                condition: sel
        """)
    ) == ['EventType = "ModuleLoad" AND (SrcProcImagePath = "valueA" AND SrcProcCmdLine = "invoke-mimikatz" AND ' +
          'SrcProcParentImagePath = "valueB" AND SrcProcParentCmdline = "Get-Path" AND ModuleSha1 = "asdfasdf" AND ' + 
          'ModuleMd5 = "asdfasdfasdf" AND ModulePath = "foo bar")']

def test_sentinelone_pipe_creation_mapping(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: pipe_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    PipeName: foo bar
                condition: sel
        """)
    ) == ['EventType = "Named Pipe Creation" AND (SrcProcImagePath = "valueA" AND SrcProcCmdLine = "invoke-mimikatz" AND ' +
          'SrcProcParentImagePath = "valueB" AND SrcProcParentCmdline = "Get-Path" AND NamedPipeName = "foo bar")']

def test_sentinelone_registry_mapping(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: registry_event
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    TargetObject: foo bar
                    Details: bar foo
                condition: sel
        """)
    ) == ['ObjectType = "Registry" AND (SrcProcImagePath = "valueA" AND SrcProcCmdLine = "invoke-mimikatz" AND ' +
          'SrcProcParentImagePath = "valueB" AND SrcProcParentCmdline = "Get-Path" AND RegistryKeyPath = "foo bar" AND ' + 
          'RegistryValue = "bar foo")']

def test_sentinelone_dns_mapping(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: dns
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    query: foo bar
                    answer: bar foo
                    QueryName: foo foo
                    record_type: bar bar
                condition: sel
        """)
    ) == ['ObjectType = "DNS" AND (SrcProcImagePath = "valueA" AND SrcProcCmdLine = "invoke-mimikatz" AND ' +
          'SrcProcParentImagePath = "valueB" AND SrcProcParentCmdline = "Get-Path" AND DnsRequest = "foo bar" AND ' + 
          'DnsResponse = "bar foo" AND DnsRequest = "foo foo" AND DnsResponse = "bar bar")']

def test_sentinelone_network_mapping(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    DestinationHostname: foo bar
                    DestinationPort: 445
                    DestinationIp: 0.0.0.0
                    User: administrator
                    SourceIp: 1.1.1.1
                    SourcePort: 135
                    Protocol: udp
                    dst_ip: 2.2.2.2
                    src_ip: 3.3.3.3
                    dst_port: 80
                    src_port: 8080
                condition: sel
        """)
    ) == ['(ObjectType In ("DNS","Url","IP")) AND (SrcProcImagePath = "valueA" AND SrcProcCmdLine = "invoke-mimikatz" AND ' + 
          'SrcProcParentImagePath = "valueB" AND SrcProcParentCmdline = "Get-Path" AND (Url = "foo bar" OR DnsRequest = "foo bar") AND ' + 
          'DstPort = "445" AND DstIP = "0.0.0.0" AND SrcProcUser = "administrator" AND SrcIP = "1.1.1.1" AND SrcPort = "135" AND ' + 
          'NetProtocolName = "udp" AND DstIP = "2.2.2.2" AND SrcIP = "3.3.3.3" AND DstPort = "80" AND SrcPort = "8080")']

def test_sentinelone_unsupported_rule_type(sentinelone_backend : SentinelOneBackend):
  with pytest.raises(ValueError):
    sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_sentinelone_unsupported_field_name(sentinelone_backend : SentinelOneBackend):
  with pytest.raises(ValueError):
    sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )