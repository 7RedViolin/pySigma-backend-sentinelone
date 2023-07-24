from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaString
from sigma.pipelines.sentinelone import sentinelonepq_pipeline
from sigma.conversion.deferred import DeferredQueryExpression
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Union

class SentinelOnePQBackend(TextQueryBackend):
    """SentinelOne PowerQuery backend."""

    backend_processing_pipeline: ClassVar[ProcessingPipeline] = sentinelonepq_pipeline()

    name : ClassVar[str] = "SentinelOne PowerQuery backend"
    formats : Dict[str, str] = {
        "default": "Plaintext",
        "json": "JSON format"
    }

    requires_pipeline : bool = False

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    parenthesize : bool = True
    group_expression : ClassVar[str] = "({expr})"

    token_separator : str = " "
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = "="

    field_quote : ClassVar[str] = "'"
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w\.+$")
    field_quote_pattern_negation : ClassVar[bool] = False

    field_escape : ClassVar[str] = "\\"
    field_escape_quote : ClassVar[bool] = True
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")

    str_quote       : ClassVar[str] = '"'
    escape_char     : ClassVar[str] = "\\"
    wildcard_multi  : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "*"
    add_escaped     : ClassVar[str] = ""
    filter_chars    : ClassVar[str] = ""
    bool_values     : ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    startswith_expression : ClassVar[str] = "{field} contains {value}"
    endswith_expression   : ClassVar[str] = "{field} contains {value}"
    contains_expression   : ClassVar[str] = "{field} contains {value}"

    re_expression : ClassVar[str] = "{field} matches \"{regex}\""
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ()
    re_escape_escape_char : bool = True
    re_flag_prefix : bool = False

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression : ClassVar[str] = "{field} == {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression : ClassVar[str] = "{field} contains:matchcase {value}"
    case_sensitive_endswith_expression   : ClassVar[str] = "{field} contains:matchcase {value}"
    case_sensitive_contains_expression   : ClassVar[str] = "{field} contains:matchcase {value}"

    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = 'not ({field} matches "\\.*")'

    field_exists_expression : ClassVar[str] = '{field} matches "\\.*"'             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = 'not ({field} matches "\\.*")'      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = False       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    list_separator : ClassVar[str] = ","               # List element separator

    unbound_value_str_expression : ClassVar[str] = '"{value}"'
    unbound_value_num_expression : ClassVar[str] = '"{value}"'

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        query += ' | columns ' + ",".join(rule.fields) if rule.fields else ''
        return query

    def finalize_output_default(self, queries: List[str]) -> str:
        return queries

    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state:ConversionState) -> dict:
        query += ' | columns ' + ",".join(rule.fields) if rule.fields else ''
        return {"query":query, "title":rule.title, "id":rule.id, "description": rule.description}
    
    def finalize_output_json(self, queries: List[str]) -> dict:
        return {"queries":queries}
    
    