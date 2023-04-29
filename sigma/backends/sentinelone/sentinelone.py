from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaString
from sigma.pipelines.sentinelone import sentinelone_pipeline
from sigma.conversion.deferred import DeferredQueryExpression
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Union

class SentinelOneBackend(TextQueryBackend):
    """SentinelOne backend."""

    backend_processing_pipeline: ClassVar[ProcessingPipeline] = sentinelone_pipeline()

    name : ClassVar[str] = "SentinelOne backend"
    formats : Dict[str, str] = {
        "default": "Plaintext",
        "json": "JSON format"
    }

    requires_pipeline : bool = False

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    parenthesize : bool = True
    group_expression : ClassVar[str] = "({expr})"

    token_separator : str = " "
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = " = "

    field_quote : ClassVar[str] = "'"
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")
    field_quote_pattern_negation : ClassVar[bool] = True

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

    startswith_expression : ClassVar[str] = "{field} startswithCIS {value}"
    endswith_expression   : ClassVar[str] = "{field} endswithCIS {value}"
    contains_expression   : ClassVar[str] = "{field} containsCIS {value}"

    re_expression : ClassVar[str] = "{field} RegExp \"{regex}\""
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ()
    re_escape_escape_char : bool = True
    re_flag_prefix : bool = False

    compare_op_expression : ClassVar[str] = "{field} {operator} \"{value}\""
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field} IS NOT EMPTY"

    field_exists_expression : ClassVar[str] = "{field} EXISTS"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "NOT {field} EXISTS"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = False       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "In Contains AnyCase"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    list_separator : ClassVar[str] = ","               # List element separator

    unbound_value_str_expression : ClassVar[str] = '"{value}"'
    unbound_value_num_expression : ClassVar[str] = '"{value}"'

    def convert_condition_field_eq_val_num(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions
        In SentinelOne, number fields must be treated as strings and quoted
        """
        try:
            return self.escape_and_quote_field(cond.field) + self.eq_token + '"' + str(cond.value) + '"'
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """
        Conversion of field in value list conditions.
        In SentinelOne, certain fields are considered 'ENUM' and can only use the 'in' operator
        """
        enum_fields = ['ObjectType', 'EventType', 'EndpointOS', 'DriverLoadVerdict','EndpointMachineType',
                       'IndicatorCategory','LoginType','NamedPipeAccessMode','NamedPipeConnectionType','NamedPipeReadMode',
                       'NamedPipeRemoteClients','NamedPipeTypeMode','NamedPipeWaitMode','NetConnStatus','NetEventDirection',
                       'OsSrcProcActiveContentType','OsSrcProcIntegrityLevel','OsSrcProcParentActiveContentSignedStatus',
                       'OsSrcProcActiveContentType','OsSrcProcParentIntegrityLevel','OsSrcProcParentSignedStatus','OsSrcProcSignedStatus',
                       'OsSrcProcVerifiedStatus','RegistryOldValueType','RegistryValueType','SrcProcActiveContentSignedStatus','SrcProcActiveContentType',
                       'SrcProcIntegrityLevel','SrcProcParentActiveContentSignedStatus','SrcProcParentActiveContentType','SrcProcParentIntegrityLevel',
                       'SrcProcParentSignedStatus','SrcProcSignedStatus','SrcProcVerifiedStatus','TIIndicatorComparisonMethod','TIIndicatorType','TgtFileConvictedBy',
                       'TgtFileIsSigned','TgtFileLocation','TgtProcActiveContentSignedStatus','TgtProcActiveContentType','TgtProcIntegrityLevel','TgtProcRelation',
                       'TgtProcSignedStatus','TgtProcVerifiedStatus','UrlAction']

        if cond.args[0].field in enum_fields:
            op = "In"
        else:
            op = self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator

        return self.field_in_list_expression.format(
            field=self.escape_and_quote_field(cond.args[0].field),       # The assumption that the field is the same for all argument is valid because this is checked before
            op=op,
            list=self.list_separator.join([
                self.convert_value_str(arg.value, state)
                if isinstance(arg.value, SigmaString)   # string escaping and qouting
                else str(arg.value)       # value is number
                for arg in cond.args
            ]),
        )

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        return query

    def finalize_output_default(self, queries: List[str]) -> str:
        return queries

    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state:ConversionState) -> dict:
        return {"query":query, "title":rule.title, "id":rule.id, "description": rule.description}
    
    def finalize_output_json(self, queries: List[str]) -> dict:
        return {"queries":queries}
    
    