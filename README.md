# pySigma-backend-sentinelone
![Tests](https://github.com/7RedViolin/pysigma-backend-sentinelone/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/430d03b407f337c2b20029c356355f8a/raw/7RedViolin-pySigma-backend-carbonblack.json)
![Status](https://img.shields.io/badge/Status-stable-green)

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
plugins.get_plugin_by_id("sentinelone").install()
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

## Side Notes & Limitations
- Backend uses Deep Visibility syntax
- Pipeline uses Deep Visibility field names
- Pipeline supports `linux`, `windows`, and `macos` product types
- Pipeline supports the following category types for field mappings
  - `process_creation`
  - `file_event`
  - `file_change`
  - `file_rename`
  - `file_delete`
  - `image_load`
  - `pipe_creation`
  - `registry_add`
  - `registry_delete`
  - `registry_event`
  - `registry_set`
  - `dns_query`
  - `dns`
  - `network_connection`
  - `firewall`
- Any unsupported fields or categories will throw errors
