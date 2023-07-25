import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone import SentinelOnePQBackend

@pytest.fixture
def sentinelone_pq_backend():
    return SentinelOnePQBackend()

def test_sentinelone_pq_windows_os_filter(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path="valueA")']

def test_sentinelone_pq_linux_os_filter(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.type="Process Creation" and (endpoint.os="linux" and tgt.process.image.path="valueA")']

def test_sentinelone_pq_osx_os_filter(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.type="Process Creation" and (endpoint.os="osx" and tgt.process.image.path="valueA")']

def test_sentinelone_pq_process_creation_mapping(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.type="Process Creation" and (tgt.process.pid=12 and tgt.process.image.path="valueA" and tgt.process.displayName="foo bar" and tgt.process.displayName="bar foo" and tgt.process.publisher="foo foo" and tgt.process.cmdline="invoke-mimikatz" and tgt.process.image.path="/etc" and tgt.process.user="administrator" and tgt.process.sessionid=4 and tgt.process.integrityLevel="bar bar" and tgt.process.image.md5="asdfasdfasdfasdfasdf" and tgt.process.image.sha1="asdfasdfasdfasdfasdfasdf" and tgt.process.image.sha256="asdfasdfasdfasdfasdfasdfasdfasdf" and src.process.pid=13 and src.process.image.path="valueB" and src.process.cmdline="Get-Path")']

def test_sentinelone_pq_file_mapping(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.category="file" and (src.process.image.path="valueA" and src.process.cmdline="invoke-mimikatz" and src.process.parent.image.path="valueB" and src.process.parent.cmdline="Get-Path" and tgt.file.path="foo bar" and tgt.file.oldPath="bar foo" and src.process.user="administrator")']

def test_sentinelone_pq_image_load_mapping(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.type="ModuleLoad" and (src.process.image.path="valueA" and src.process.cmdline="invoke-mimikatz" and src.process.parent.image.path="valueB" and src.process.parent.cmdline="Get-Path" and module.sha1="asdfasdf" and module.md5="asdfasdfasdf" and module.path="foo bar")']

def test_sentinelone_pq_pipe_creation_mapping(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.type="Named Pipe Creation" and (src.process.image.path="valueA" and src.process.cmdline="invoke-mimikatz" and src.process.parent.image.path="valueB" and src.process.parent.cmdline="Get-Path" and namedPipe.name="foo bar")']

def test_sentinelone_pq_registry_mapping(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.category="Registry" and (src.process.image.path="valueA" and src.process.cmdline="invoke-mimikatz" and src.process.parent.image.path="valueB" and src.process.parent.cmdline="Get-Path" and registry.keyPath="foo bar" and registry.value="bar foo")']

def test_sentinelone_pq_dns_mapping(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['event.category="DNS" and (src.process.image.path="valueA" and src.process.cmdline="invoke-mimikatz" and src.process.parent.image.path="valueB" and src.process.parent.cmdline="Get-Path" and event.dns.request="foo bar" and event.dns.response="bar foo" and event.dns.request="foo foo" and event.dns.response="bar bar")']

def test_sentinelone_pq_network_mapping(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
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
    ) == ['(event.category in ("DNS","Url","IP")) and (src.process.image.path="valueA" and src.process.cmdline="invoke-mimikatz" and src.process.parent.image.path="valueB" and src.process.parent.cmdline="Get-Path" and (url.address="foo bar" or event.dns.request="foo bar") and dst.port.number=445 and dst.ip.address="0.0.0.0" and src.process.user="administrator" and src.ip.address="1.1.1.1" and src.port.number=135 and NetProtocolName="udp" and dst.ip.address="2.2.2.2" and src.ip.address="3.3.3.3" and dst.port.number=80 and src.port.number=8080)']

def test_sentinelone_pq_unsupported_rule_type(sentinelone_pq_backend : SentinelOnePQBackend):
  with pytest.raises(ValueError):
    sentinelone_pq_backend.convert(
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

def test_sentinelone_pq_unsupported_field_name(sentinelone_pq_backend : SentinelOnePQBackend):
  with pytest.raises(ValueError):
    sentinelone_pq_backend.convert(
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