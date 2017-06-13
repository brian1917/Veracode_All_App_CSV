import csv
import sys
import requests
import argparse
import os
from lxml import etree


def results_api(api_user, api_password, build_id):
    payload = {'build_id': build_id}
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/detailedreport.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error downloading results for Build ID ' + build_id)
    return r.content


def get_app_list_api(api_user, api_password):
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/getapplist.do', auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error getting app_list')
    return r.content


def get_build_list_api(api_user, api_password, app_id):
    payload = {'app_id': app_id}
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/getbuildlist.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error getting build list')
    return r.content


def get_app_info_api(api_user, api_password, app_id):
    payload = {'app_id': app_id}
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/getappinfo.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error getting app info')
    return r.content


def get_tracking_id(api_user, api_password, app_id):
    app_info_xml = get_app_info_api(api_user, api_password, app_id)
    app_info_xml = etree.fromstring(app_info_xml)
    archer_tracking_id = app_info_xml.findall('{*}application/{*}customfield')[0].get('value')
    return archer_tracking_id


def get_mitigation_info(build_id, flaw_id_list, api_user, api_password):
    payload = {'build_id': build_id, 'flaw_id_list': flaw_id_list}
    r = requests.get('https://analysiscenter.veracode.com/api/getmitigationinfo.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error getting mitigation_info')
    return r.content


def main():
    # SET UP ARGUMENTS
    parser = argparse.ArgumentParser(
        description='This script creates a CSV for flaws in the most recent build of all applications in an account. '
                    'Use optional parameters to determine to filter what flaws to include.')
    parser.add_argument('-u', '--username', required=True, help='API Username')
    parser.add_argument('-p', '--password', required=True, help='API Password')
    parser.add_argument('-v', '--policy_violating', required=False, dest='policy_violating', action='store_true',
                        help='Will only include policy-violating flaws')
    parser.add_argument('-o', '--open', required=False, dest='open', action='store_true',
                        help='Will not include fixed flaws')
    parser.add_argument('-n', '--not_mitigated', required=False, dest='not_mitigated', action='store_true',
                        help='Will not include flaws with accepted mitigations')
    parser.add_argument('-t', '--exclude_tracking_id', required=False, dest='exclude_tracking_id', action='store_true',
                        help='Will not include Archer Tracking ID custom field (customer-specific')
    args = parser.parse_args()

    # DEFINE SOME VARIABLES
    total_flaw_count = 0

    # DELETE PREVIOUS CSV
    try:
        os.remove('flaws.csv')
    except OSError:
        pass

    # OPEN CSV FILE AND WRITE HEADERS
    with open('flaws.csv', 'wb') as f:
        wr = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        headers = ['unique_id', 'tracking_id', 'app_id', 'app_name', 'build_id', 'issueid', 'cweid', 'categoryname',
                   'categoryid', 'severity', 'exploitLevel', 'module', 'type', 'description', 'date_first_occurrence',
                   'remediation_status', 'affects_policy_compliance', 'mitigation_status', 'mitigation_proposer',
                   'mitigation_proposal_date', 'mitigation_proposal_comment', 'sourcefile', 'line', 'sourcefilepath',
                   'functionrelativelocation']
        wr.writerow(headers)

        # GET THE APP LIST
        app_list_xml = get_app_list_api(args.username, args.password)
        app_list_xml = etree.fromstring(app_list_xml)
        app_list = app_list_xml.findall('{*}app')

        # FOR EACH APP, GET THE BUILD LIST
        for app in app_list:
            app_skip_check = 0

            build_list_xml = get_build_list_api(args.username, args.password, app.attrib['app_id'])
            build_list_xml = etree.fromstring(build_list_xml)

            if len(build_list_xml) > 0:

                app_flaw_count = 0

                # GET RESULTS FOR LATEST BUILD
                latest_build = build_list_xml.findall('{*}build')[-1].get('build_id')
                results_xml = results_api(args.username, args.password, latest_build)
                if 'No report available' in results_xml and len(build_list_xml) > 1:
                    latest_build = build_list_xml.findall('{*}build')[-2].get('build_id')
                    results_xml = results_api(args.username, args.password, latest_build)
                if 'No report available' in results_xml and len(build_list_xml) > 2:
                    latest_build = build_list_xml.findall('{*}build')[-3].get('build_id')
                    results_xml = results_api(args.username, args.password, latest_build)
                if 'No report available' in results_xml:
                    app_skip_check = 1

                # SET THE TRACKING ID
                if args.exclude_tracking_id is True:
                    tracking_id = 'NA'
                else:
                    tracking_id = get_tracking_id(args.username, args.password, app.attrib['app_id'])

                # SKIP TRACKING IDS SET TO PHASE-2
                if tracking_id == 'PHASE-2':
                    app_skip_check = 1

                # CONTINUE IF NOT SKIPPING APP
                if app_skip_check == 0:

                    results_xml = etree.fromstring(results_xml)
                    static_flaws = results_xml.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')

                    # FOR EACH FLAW, CHECK PARAMETERS TO SEE IF WE SHOULD SKIP
                    for flaw in static_flaws:
                        flaw_skip_check = 0
                        if args.policy_violating is True:
                            if flaw.attrib['affects_policy_compliance'] == 'false':
                                flaw_skip_check = 1
                        if args.not_mitigated is True:
                            if flaw.attrib['mitigation_status'] == 'accepted':
                                flaw_skip_check = 1
                        if args.open is True:
                            if flaw.attrib['remediation_status'] == 'Fixed':
                                flaw_skip_check = 1

                                # CHECK THE MITIGATION STATUS AND GRAB COMMENT FOR PROPOSED
                        if flaw.attrib['mitigation_status'] == 'proposed':
                            mitigation_xml = get_mitigation_info(latest_build, flaw.attrib['issueid'], args.username,
                                                                 args.password)
                            mitigation_xml = etree.fromstring(mitigation_xml)
                            recent_proposal_comment = mitigation_xml.findall('{*}issue/{*}mitigation_action')[-1].get(
                                'comment')
                            recent_proposal_date = mitigation_xml.findall('{*}issue/{*}mitigation_action')[-1].get(
                                'date')
                            recent_proposal_reviewer = mitigation_xml.findall('{*}issue/{*}mitigation_action')[-1].get(
                                'reviewer')
                        else:
                            recent_proposal_comment = 'N/A'
                            recent_proposal_date = 'N/A'
                            recent_proposal_reviewer = 'N/A'

                        # WRITE DATA TO THE CSV IF WE DON'T SKIP
                        if flaw_skip_check == 0:
                            # ENCODE FLAW DESCRIPTION TO AVOID ERRORS
                            flaw_attrib_text = flaw.attrib['description']
                            flaw_attrib_text = flaw_attrib_text.encode('utf-8')

                            row = (app.attrib['app_id'] + '-' + flaw.attrib['issueid'],
                                   tracking_id, app.attrib['app_id'], app.attrib['app_name'], latest_build,
                                   flaw.attrib['issueid'],
                                   flaw.attrib['cweid'], flaw.attrib['categoryname'], flaw.attrib['categoryid'],
                                   flaw.attrib['severity'], flaw.attrib['exploitLevel'], flaw.attrib['module'],
                                   flaw.attrib['type'], flaw_attrib_text, flaw.attrib['date_first_occurrence'],
                                   flaw.attrib['remediation_status'], flaw.attrib['affects_policy_compliance'],
                                   flaw.attrib['mitigation_status'], recent_proposal_reviewer, recent_proposal_date,
                                   recent_proposal_comment, flaw.attrib['sourcefile'], flaw.attrib['line'],
                                   flaw.attrib['sourcefilepath'], flaw.attrib['functionrelativelocation'])
                            wr.writerow(row)

                            app_flaw_count += 1
                            total_flaw_count += 1

                    print '[*] Exported ' + str(app_flaw_count) + ' static flaws from ' + str(
                        app.attrib['app_name']) + ' (' + str(app.attrib['app_id']) + '), Build ID ' + str(latest_build)

    print '[*] Exported ' + str(total_flaw_count) + ' total flaws'


if __name__ == '__main__':
    main()
