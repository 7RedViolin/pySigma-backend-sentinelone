import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone import SentinelOnePQBackend

@pytest.fixture
def sentinelone_pq_backend():
    return SentinelOnePQBackend()

def test_sentinelone_pq_and_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                    ParentImage: valueB
                condition: sel
        """)
    ) == ['event.type="Process Creation" and (tgt.process.image.path="valueA" and src.process.image.path="valueB")']

def test_sentinelone_pq_or_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA
                sel2:
                    ParentImage: valueB
                condition: 1 of sel*
        """)
    ) == ['event.type="Process Creation" and (tgt.process.image.path="valueA" or src.process.image.path="valueB")']

def test_sentinelone_pq_and_or_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA1
                        - valueA2
                    ParentImage:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['event.type="Process Creation" and ((tgt.process.image.path in ("valueA1","valueA2")) and (src.process.image.path in ("valueB1","valueB2")))']

def test_sentinelone_pq_or_and_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA1
                    ParentImage: valueB1
                sel2:
                    Image: valueA2
                    ParentImage: valueB2
                condition: 1 of sel*
        """)
    ) == ['event.type="Process Creation" and ((tgt.process.image.path="valueA1" and src.process.image.path="valueB1") or (tgt.process.image.path="valueA2" and src.process.image.path="valueB2"))']

def test_sentinelone_pq_in_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['event.type="Process Creation" and (tgt.process.image.path="valueA" or tgt.process.image.path="valueB" or tgt.process.image.path contains "valueC")']

def test_sentinelone_pq_regex_query(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image|re: foo.*bar
                    ParentImage: foo
                condition: sel
        """)
    ) == ['event.type="Process Creation" and (tgt.process.image.path matches "foo.*bar" and src.process.image.path="foo")']

def test_sentinelone_pq_cidr_query(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    DestinationIp|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['(event.category in ("DNS","Url","IP")) and dst.ip.address contains "192.168."']

def test_sentinelone_pq_default_output(sentinelone_pq_backend : SentinelOnePQBackend):
    """Test for output format default."""
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['event.type="Process Creation" and tgt.process.image.path="valueA"']

def test_sentinelone_pq_json_output(sentinelone_pq_backend : SentinelOnePQBackend):
    """Test for output format default."""
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """), "json"
    ) == {"queries":[{"query":'event.type="Process Creation" and tgt.process.image.path="valueA"', "title":"Test", "id":None, "description":None}]}



