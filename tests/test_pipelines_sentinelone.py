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
    ) == ['EventType="Process Creation" AND (EndpointOS="windows" AND TgtProcName="valueA")']

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
    ) == ['EventType="Process Creation" AND (EndpointOS="linux" AND TgtProcName="valueA")']

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
    ) == ['EventType="Process Creation" AND (TgtProcPID=12 AND TgtProcName="valueA" AND TgtProcDisplayName="foo bar" AND ' +
          'TgtProcDisplayName="bar foo" AND TgtProcPublisher="foo foo" AND TgtProcCmdLine="invoke-mimikatz" AND ' +
          'TgtProcImagePath="/etc" AND TgtProcUser="administrator" AND TgtProcSessionId=4 AND ' +
          'TgtProcIntegrityLevel="bar bar" AND TgtProcMd5="asdfasdfasdfasdfasdf" AND ' + 
          'TgtProcSha1="asdfasdfasdfasdfasdfasdf" AND TgtProcSha256="asdfasdfasdfasdfasdfasdfasdfasdf" AND SrcProcPID=13 AND ' +
          'SrcProcName="valueB" AND SrcProcCmdLine="Get-Path")']

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
    ) == ['ObjectType="File" AND (SrcProcName="valueA" AND SrcProcCmdLine="invoke-mimikatz" AND ' +
          'SrcProcParentName="valueB" AND SrcProcParentCmdline="Get-Path" AND TgtFilePath="foo bar" AND ' + 
          'TgtFileOldPath="bar foo" AND SrcProcUser="administrator")']

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
    ) == ['EventType="ModuleLoad" AND (SrcProcName="valueA" AND SrcProcCmdLine="invoke-mimikatz" AND ' +
          'SrcProcParentName="valueB" AND SrcProcParentCmdline="Get-Path" AND ModuleSha1="asdfasdf" AND ' + 
          'ModuleMd5="asdfasdfasdf" AND ModulePath="foo bar")']

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
    ) == ['EventType="Named Pipe Creation" AND (SrcProcName="valueA" AND SrcProcCmdLine="invoke-mimikatz" AND ' +
          'SrcProcParentName="valueB" AND SrcProcParentCmdline="Get-Path" AND NamedPipeName="foo bar")']

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
    ) == ['ObjectType="Registry" AND (SrcProcName="valueA" AND SrcProcCmdLine="invoke-mimikatz" AND ' +
          'SrcProcParentName="valueB" AND SrcProcParentCmdline="Get-Path" AND RegistryKeyPath="foo bar" AND ' + 
          'RegistryValue="bar foo")']

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
                    TargetObject: foo bar
                    Details: bar foo
                condition: sel
        """)
    )