# Veracode All App CSV

## Description
Script provides a single CSV for all flaws in a Veracode account. Default settings only export policy-violating, non-mitigated, and non-fixed flaws. Parameters can override defaults.

## Required Libraries 
<<<<<<< HEAD
sys, requests, argparse, os, multiprocessing, functools, lxml, import time, import shutil
=======
csv, sys, requests, argparse, os, lxml
>>>>>>> 5457cc67c8aa50dd70be803de72a07c3eee7dbf0

## Parameters
1. **-u, --username**: Veracode user name with reviewer permissions. Required.
2. **-p, --password**: Veracode password. Required.
3. **-n, --non_policy_violating**: Will include non-policy violating flaws. Optional.
4. **-f, --fix**: Will include fixed flaws. Optional
5. **-m, --mitigated**: Will include mitigated flaws. Optional.
6. **-t, --exclude_tracking_id**: Will exclude the tracking ID column (can be customer specific). Optional.
7. **-s, --static_only**: Will only export static flaws. Optional.
8. **-d, --dynamic_only**: Will include dynamic only flaws. Optional.
9. **-a, --app_list**: Text file to limit app list (app ID on separate lines). Optional.
