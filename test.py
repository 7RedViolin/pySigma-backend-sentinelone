from sigma.backends.sentinelonedeepvisibility.sentinelonedeepvisibility import SentinelOneDeepVisibilityBackend
from sigma.pipelines.sentinelonedeepvisibility.sentinelonedeepvisibility import sentinelonedeepvisibility_pipeline
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.collection import SigmaCollection
import yaml

list_of_rules = []

list_of_files = ['./test_rule.yml']#, './test_rule.yml']

for x in list_of_files:
  with open(x) as rule_file:
    sigma_rule_raw = yaml.load(rule_file, Loader=yaml.SafeLoader)
    list_of_rules.append(sigma_rule_raw)


rules = SigmaCollection.from_dicts(list_of_rules)

backend = SentinelOneDeepVisibilityBackend()
print("Result: ")

print(backend.convert(rules))