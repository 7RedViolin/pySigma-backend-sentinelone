# pySigma-backend-sentinelone
![Tests](https://github.com/7RedViolin/pySigma-pipeline-sentinelonedeepvisibility/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/4babc10180a1e9c846086e155ba1dbc6/raw/b755463e2db3283a191e4778dc4f6e7509210ca9/7RedViolin-pySigma-backend-sentinelone.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SentinelOne Backend

This is the SentinelOne backend for pySigma. It provides the package `sigma.backends.sentinelone` with the `SentinelOneBackend` class.
Further, it contains the processing pipelines in `sigma.pipelines.sentinelone` for field renames and error handling. This pipeline is automatically applied to `SigmaRule` and `SigmaCollection` objects passed to the `SentinelOneBackend` class.

It supports the following output formats:

* default: plain SentinelOne Deep Visibility queries
* json: JSON formatted SentinelOne Deep Visibility queries that includes the query, rule name, rule ID, and rule description

This backend is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)

## Installation
This can be install via pip from PyPI or using pySigma's plugin functionality

### PyPI
```bash
pip install pysigma-backend-sentinelone
```

### pySigma
```python
from sigma.plugins import SigmaPluginDirectory
plugins = SigmaPluginDirectory.default_plugin_directory()
plugins.get_plugin_by_id("sentinelone).install()
```

## Usage

### sigma-cli
```bash
sigma convert -t sentinelone proc_creation_win_office_onenote_susp_child_processes.yml
```

### pySigma
```python
from sigma.backends.sentinelone import SentinelOneBackend
from sigma.rule import SigmaRule

rule = SigmaRule.from_yaml("""
title: Invoke-Mimikatz CommandLine
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: Invoke-Mimikatz
    condition: sel""")


backend = SentinelOneBackend()
print(backend.convert_rule(rule)[0])
```