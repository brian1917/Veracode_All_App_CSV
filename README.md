# Veracode All App CSV

## Description
Script provides a single CSV for all flaws in a Veracode account. Default settings only export policy-violating, non-mitigated, and non-fixed flaws for most recent static and dynamic scans. Parameters can override defaults.

## Required Libraries 
csv, sys, requests, argparse, os, multiprocessing, functools, lxml, shutil, logging

## Parameters
1. **-u, --username**: Veracode user name with reviewer permissions. Required.
2. **-p, --password**: Veracode password. Required.
3. **-n, --non_policy_violating**: Will include non-policy violating flaws. Optional.
4. **-f, --fix**: Will include fixed flaws. Optional
5. **-m, --mitigated**: Will include mitigated flaws. Optional.
6. **-s, --static_only**: Will only export static flaws. Optional.
7. **-d, --dynamic_only**: Will include dynamic only flaws. Optional.
8. **-v, --verbose**: Verbose debug logging. Optional.

## Output
Creates a CSV file with all output: **flaws.csv**.
Creates a log file: **veracode_all_apps_csv.log**. (No output to terminal - all to log)

## Other Notes
The script will create two temporary directories: **build_xml_files** and **detailed_results**. These will be deleted at the end of the script. If the script exits in error, the temporary directories will be deleted at the start of the next run.
