import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.backends.sentinelone import SentinelOneBackend
from sigma.pipelines.sentinelone import sentinelone_pipeline


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
    ) == ['EventType = "Process Creation" AND (TgtProcImagePath = "valueA" AND SrcProcImagePath = "valueB")']

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
    ) == ['EventType = "Process Creation" AND (TgtProcImagePath = "valueA" OR SrcProcImagePath = "valueB")']

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
    ) == ['EventType = "Process Creation" AND ((TgtProcImagePath In Contains AnyCase ("valueA1","valueA2")) AND (SrcProcImagePath In Contains AnyCase ("valueB1","valueB2")))']

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
    ) == ['EventType = "Process Creation" AND ((TgtProcImagePath = "valueA1" AND SrcProcImagePath = "valueB1") OR (TgtProcImagePath = "valueA2" AND SrcProcImagePath = "valueB2"))']

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
    ) == ['EventType = "Process Creation" AND (TgtProcImagePath = "valueA" OR TgtProcImagePath = "valueB" OR TgtProcImagePath startswithCIS "valueC")']

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
    ) == ['EventType = "Process Creation" AND (TgtProcImagePath RegExp "foo.*bar" AND SrcProcImagePath = "foo")']

def test_sentinelone_cidr_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
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
    ) == ['(ObjectType In ("DNS","Url","IP")) AND DstIP startswithCIS "192.168."']

def test_sentinelone_enum_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: registry_event
                product: test_product
            detection:
                sel:
                    EventType: 
                    - valueA
                    - valueB
                condition: sel
        """)
    ) == ['ObjectType = "Registry" AND (EventType In ("valueA","valueB"))']

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
    ) == ['EventType = "Process Creation" AND TgtProcImagePath = "valueA"']

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
    ) == {"queries":[{"query":'EventType = "Process Creation" AND TgtProcImagePath = "valueA"', "title":"Test", "id":None, "description":None}]}

def test_sentinelone_preapply_pipeline(sentinelone_backend: SentinelOneBackend):
    """Tests for pre-applying the SentinelOne pipeline prior to converting a rule in the backend"""
    sigma_rule = SigmaRule.from_yaml("""
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
    sentinelone_pipeline().apply(sigma_rule)
    assert sentinelone_backend.convert_rule(
        sigma_rule
    ) == ['EventType = "Process Creation" AND (TgtProcImagePath = "valueA" AND SrcProcImagePath = "valueB")']
