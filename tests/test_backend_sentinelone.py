import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone import SentinelOneBackend

@pytest.fixture
def sentinelone_backend():
    return SentinelOneBackend()

def test_sentinelone_and_expression(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
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
    ) == ['EventType="Process Creation" AND (TgtProcName="valueA" AND SrcProcName="valueB")']

def test_sentinelone_or_expression(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
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
    ) == ['EventType="Process Creation" AND (TgtProcName="valueA" OR SrcProcName="valueB")']

def test_sentinelone_and_or_expression(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
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
    ) == ['EventType="Process Creation" AND ((TgtProcName In Contains AnyCase ("valueA1","valueA2")) AND (SrcProcName In Contains AnyCase ("valueB1","valueB2")))']


def test_sentinelone_or_and_expression(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
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
    ) == ['EventType="Process Creation" AND ((TgtProcName="valueA1" AND SrcProcName="valueB1") OR (TgtProcName="valueA2" AND SrcProcName="valueB2"))']

def test_sentinelone_in_expression(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
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
    ) == ['EventType="Process Creation" AND (TgtProcName="valueA" OR TgtProcName="valueB" OR TgtProcName startswithCIS "valueC")']

def test_sentinelone_regex_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
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
    ) == ['EventType="Process Creation" AND (TgtProcName RegExp foo.*bar AND SrcProcName="foo")']

def test_sentinelone_cidr_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['EventType="Process Creation" AND field startswithCIS "192.168."']


def test_sentinelone_default_output(sentinelone_backend : SentinelOneBackend):
    """Test for output format default."""
    assert sentinelone_backend.convert(
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
    ) == ['EventType="Process Creation" AND TgtProcName="valueA"']

def test_sentinelone_json_output(sentinelone_backend : SentinelOneBackend):
    """Test for output format default."""
    assert sentinelone_backend.convert(
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
    ) == {"queries":[{"query":'EventType="Process Creation" AND TgtProcName="valueA"', "title":"Test", "id":None, "description":None}]}



