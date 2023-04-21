import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelonedeepvisibility import SentinelOneDeepVisibilityBackend

@pytest.fixture
def sentinelonedeepvisibility_backend():
    return SentinelOneDeepVisibilityBackend()

def test_sentinelonedeepvisibility_and_expression(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    assert sentinelonedeepvisibility_backend.convert(
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
    ) == ['EventType="Process Creation" AND TgtProcName="valueA" AND SrcProcName="valueB"']

def test_sentinelonedeepvisibility_or_expression(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    assert sentinelonedeepvisibility_backend.convert(
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
    ) == ['EventType="Process Creation" AND TgtProcName="valueA" OR SrcProcName="valueB"']

def test_sentinelonedeepvisibility_and_or_expression(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    assert sentinelonedeepvisibility_backend.convert(
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
    ) == ['EventType="Process Creation" AND TgtProcName In Contains AnyCase ("valueA1", "valueA2") AND SrcProcName In Contains Anycase ("valueB1", "valueB2")']

def test_sentinelonedeepvisibility_or_and_expression(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    assert sentinelonedeepvisibility_backend.convert(
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
                    ParentName: valueB2
                condition: 1 of sel*
        """)
    ) == ['EventType="Process Creation" AND (TgtProcName="valueA1" OR SrcProcName="valueB1") AND (TgtProcName="valueA2" OR SrcProcName="valueB2")']

def test_sentinelonedeepvisibility_in_expression(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    assert sentinelonedeepvisibility_backend.convert(
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
    ) == ['EventType="Process Creation" AND TgtProcName In Contains AnyCase ("valueA", "valueB", "valueC*")']

def test_sentinelonedeepvisibility_regex_query(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    assert sentinelonedeepvisibility_backend.convert(
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
    ) == ['EventType="Process Creation" AND TgtProcName RegExp foo.*bar AND SrcProcName="foo"']

def test_sentinelonedeepvisibility_cidr_query(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    assert sentinelonedeepvisibility_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['field In Contains AnyCase ("192.168.*")']


def test_sentinelonedeepvisibility_default_output(sentinelonedeepvisibility_backend : SentinelOneDeepVisibilityBackend):
    """Test for output format default."""
    # TODO: implement a test for the output format
    pass


