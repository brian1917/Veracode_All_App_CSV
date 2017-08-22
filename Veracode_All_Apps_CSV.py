import csv
import sys
import requests
import argparse
import os
import multiprocessing as mp
from functools import partial
from lxml import etree
import shutil
import logging


def cleanup(clean_type):
    try:
        shutil.rmtree('detailed_results')
    except OSError:
        pass
    try:
        shutil.rmtree('build_xml_files')
    except OSError:
        pass
    try:
        os.remove('api_app_list.txt')
    except OSError:
        pass

    if clean_type == 'start':
        try:
            os.remove('flaws.csv')
        except OSError:
            pass
        if not os.path.exists('detailed_results'):
            os.makedirs('detailed_results')
        if not os.path.exists('build_xml_files'):
            os.makedirs('build_xml_files')

    return ()


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
    file_name = 'build_xml_files' + os.path.sep + app_id + "_buildlist.xml"
    payload = {'app_id': app_id}
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/getbuildlist.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error getting build list')
    f = open(file_name, 'w')
    f.write(r.content)
    f.close()
    logging.info('Created ' + file_name)
    return ()


def get_app_info_api(api_user, api_password, app_id):
    payload = {'app_id': app_id}
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/getappinfo.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error getting app info')
    return r.content


def get_custom_field_1(api_user, api_password, app_id):
    app_info_xml = get_app_info_api(api_user, api_password, app_id)
    app_info_xml = etree.fromstring(app_info_xml)
    custom_field_1 = app_info_xml.findall('{*}application/{*}customfield')[0].get('value')
    return custom_field_1


def flaw_skip_check_func(flaw, non_policy_violating_flag, mitigated_flag, fixed_flag):
    check = 0
    if flaw.attrib['affects_policy_compliance'] == 'false':
        if non_policy_violating_flag is False:
            check = 1
    if flaw.attrib['mitigation_status'] == 'accepted':
        if mitigated_flag is False:
            check = 1
    if flaw.attrib['remediation_status'] == 'Fixed':
        if fixed_flag is False:
            check = 1
    return check


def check_mitigations(flaw, results_xml, scan_type):
    if flaw.attrib['remediation_status'] != 'Fixed':
        if flaw.attrib['mitigation_status'] in ['proposed', 'accepted', 'rejected']:
            recent_comment = results_xml.findall(
                '{*}severity/{*}category/{*}cwe/{*}' + scan_type + 'flaws/{*}flaw[@issueid="' + flaw.attrib[
                    'issueid'] + '"]/{*}mitigations/{*}mitigation')[-1].get('description')
            recent_reviewer = results_xml.findall(
                '{*}severity/{*}category/{*}cwe/{*}' + scan_type + 'flaws/{*}flaw[@issueid="' + flaw.attrib[
                    'issueid'] + '"]/{*}mitigations/{*}mitigation')[-1].get('user')
            recent_date = results_xml.findall(
                '{*}severity/{*}category/{*}cwe/{*}' + scan_type + 'flaws/{*}flaw[@issueid="' + flaw.attrib[
                    'issueid'] + '"]/{*}mitigations/{*}mitigation')[-1].get('date')
        else:
            recent_comment = 'NA'
            recent_reviewer = 'NA'
            recent_date = 'NA'
    else:
        recent_comment = 'NA'
        recent_reviewer = 'NA'
        recent_date = 'NA'
    return recent_comment, recent_reviewer, recent_date


def build_csv_fields(scan_type, flaw, app_id, custom_field_1, app_name, latest_build, recent_proposal_comment,
                     recent_proposal_reviewer, recent_proposal_date):
    field = {'unique_id': app_id + flaw.attrib['issueid'],
             'custom_field_1': custom_field_1,
             'app_id': app_id,
             'app_name': app_name,
             'latest_build': latest_build,
             'issueid': flaw.attrib['issueid'],
             'cweid': flaw.attrib['cweid'],
             'categoryname': flaw.attrib['categoryname'],
             'categoryid': flaw.attrib['categoryid'],
             'severity': flaw.attrib['severity'],
             'description': flaw.attrib['description'],
             'date_first_occurrence': flaw.attrib['date_first_occurrence'],
             'remediation_status': flaw.attrib['remediation_status'],
             'affects_policy_compliance': flaw.attrib['affects_policy_compliance'],
             'mitigation_status': flaw.attrib['mitigation_status'],
             'recent_proposal_comment': recent_proposal_comment,
             'recent_proposal_reviewer': recent_proposal_reviewer,
             'recent_proposal_date': recent_proposal_date,
             'flaw_attrib_text': flaw.attrib['description']}

    if scan_type == 'static':
        field['exploitLevel'] = flaw.attrib['exploitLevel']
        field['sourcefile'] = flaw.attrib['sourcefile']
        field['sourcefilepath'] = flaw.attrib['sourcefilepath']
        field['line'] = flaw.attrib['line']
        field['url'] = 'NA-SAST'

    else:
        field['exploitLevel'] = 'NA-DAST'
        field['sourcefile'] = 'NA-DAST'
        field['sourcefilepath'] = 'NA-DAST'
        field['line'] = 'NA-DAST'
        field['url'] = flaw.attrib['url']

    row = (field['unique_id'],
           field['custom_field_1'],
           field['app_id'],
           field['app_name'].encode('utf-8'),
           field['latest_build'],
           field['issueid'],
           field['cweid'],
           field['categoryname'],
           field['categoryid'],
           field['severity'],
           field['exploitLevel'],
           field['date_first_occurrence'],
           field['description'].encode('utf-8'),
           field['remediation_status'],
           field['affects_policy_compliance'],
           field['mitigation_status'],
           field['recent_proposal_comment'].encode('utf-8'),
           field['recent_proposal_reviewer'].encode('utf-8'),
           field['recent_proposal_date'],
           field['sourcefilepath'].encode('utf-8'),
           field['sourcefile'].encode('utf-8'),
           field['line'],
           field['url'].encode('utf-8'))

    return row


def create_results_xml(api_user, api_password, app_id):
    # CHECK FOR PROVIDED LIST IN PARAMETERS
    build_list_xml_file = 'build_xml_files' + os.path.sep + app_id + '_buildlist.xml'
    build_list_xml = etree.parse(build_list_xml_file)

    number_of_builds = len(build_list_xml.findall('{*}build'))

    if number_of_builds > 0:
        latest_build = build_list_xml.findall('{*}build')[-1].get('build_id')
        results_xml = results_api(api_user, api_password, latest_build)
        if 'No report available' in results_xml and number_of_builds > 1:
            latest_build = build_list_xml.findall('{*}build')[-2].get('build_id')
            results_xml = results_api(api_user, api_password, latest_build)
        if 'No report available' in results_xml and number_of_builds > 2:
            latest_build = build_list_xml.findall('{*}build')[-3].get('build_id')
            results_xml = results_api(api_user, api_password, latest_build)
    else:
        results_xml = ''  # NEED TO SET IT TO SOMETHING FOR LOGIC CHECK

    if 'No report available' in results_xml or number_of_builds == 0:
        logging.info('App ID ' + app_id + ' has no valid builds; building dummy XML')
        results_xml = '<?xml version="1.0" encoding="UTF-8"?><error>No builds valid. Dummy XML for script</error>'

    file_name = 'detailed_results' + os.path.sep + app_id + '.xml'
    f = open(file_name, 'w')
    f.write(results_xml)
    f.close()
    logging.info('Created ' + file_name)


def main():
    print '[*] Starting script; see veracode_all_apps_csv.log for details.'

    # SET UP ARGUMENTS
    parser = argparse.ArgumentParser(
        description='This script creates a CSV for flaws in the most recent build of all applications in an account. '
                    'Use optional parameters to determine to filter what flaws to include.')

    parser.add_argument('-u', '--username', required=True, help='API Username')
    parser.add_argument('-p', '--password', required=True, help='API Password')
    parser.add_argument('-n', '--non_policy_violating', required=False, dest='non_policy_violating',
                        action='store_true',
                        help='Will include non-policy-violating flaws')
    parser.add_argument('-f', '--fix', required=False, dest='fixed', action='store_true',
                        help='Will include fixed flaws')
    parser.add_argument('-m', '--mitigated', required=False, dest='mitigated', action='store_true',
                        help='Will include flaws with accepted mitigations')
    parser.add_argument('-s', '--static_only', required=False, dest='static_only', action='store_true',
                        help='Will export static flaws only')
    parser.add_argument('-d', '--dynamic_only', required=False, dest='dynamic_only', action='store_true',
                        help='Will export dynamic flaws only')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='Verbose (Debug) logging')

    args = parser.parse_args()

    # SET LOGGING
    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(filename='veracode_all_apps_csv.log',
                        format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=log_level)

    # ERROR CHECK PARAMETERS
    if args.static_only is True and args.dynamic_only is True:
        sys.exit('[*] You cannot have the static-only and dynamic-only flags set together. Exiting script.')

    # DEFINE SOME VARIABLES
    total_flaw_count = 0
    non_policy_violating_flag = args.non_policy_violating
    mitigated_flag = args.mitigated
    fixed_flag = args.fixed

    # DELETE PREVIOUS CSV
    cleanup('start')

    # OPEN CSV FILE AND WRITE HEADERS
    with open('flaws.csv', 'wb') as f:
        wr = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        headers = ['unique_id', 'custom_field_1', 'app_id', 'app_name', 'latest_build', 'issueid', 'cweid',
                   'categoryname', 'categoryid', 'severity', 'exploitLevel', 'date_first_occurrence', 'description',
                   'remediation_status', 'affects_policy_compliance', 'mitigation_status', 'recent_proposal_comment',
                   'recent_proposal_reviewer', 'recent_proposal_date', 'sourcefilepath', 'sourcefile', 'line', 'url']
        wr.writerow(headers)

        # GET THE APP LIST
        app_list_xml = get_app_list_api(args.username, args.password)
        app_list_xml = etree.fromstring(app_list_xml)
        app_list = app_list_xml.findall('{*}app')

        # CREATE APP LIST TEXT FILE
        f = open('api_app_list.txt', 'w')
        for app in app_list[:-1]:
            f.write('%s\n' % app.attrib['app_id'])
        f.write('%s' % app_list[-1].get('app_id'))
        f.close()

        # FOR EACH APP IN THE TEXT FILE, GET THE BUILD LIST XML
        f = open('api_app_list.txt', "r")
        app_list = f.read().split('\n')
        f.close()

        pool = mp.Pool(4)
        func_build_list = partial(get_build_list_api, args.username, args.password)
        pool.map(func_build_list, app_list)
        pool.close()
        pool.join()

        # GET DETAILED XML FOR EACH APP
        pool = mp.Pool(4)
        func_detailed_report = partial(create_results_xml, args.username, args.password)
        pool.map(func_detailed_report, app_list)
        pool.close()
        pool.join()

        # FOR EACH APP, START BY GETTING THE BUILD LIST
        for app in app_list:
            app_skip_check = 0

            file_name = 'detailed_results' + os.path.sep + app + '.xml'
            results_xml = etree.parse(file_name)

            with open(file_name, 'r') as xml_file:
                xml_string = xml_file.read()

            if '<error>' in xml_string:
                app_skip_check = 1
                logging.info('Skipping App ID ' + app + ' because it has no results')

            # GET CUSTOM FIELD 1 TO BRING INTO REPORTS FOR CUSTOMER-SPECIFIC NEEDS
            custom_field_1 = get_custom_field_1(args.username, args.password, app)

            if app_skip_check == 0:
                app_name = results_xml.getroot().attrib['app_name']
                latest_build = results_xml.getroot().attrib['build_id']
                static_app_flaw_count = 0
                dynamic_app_flaw_count = 0

                static_flaws = results_xml.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
                dynamic_flaws = results_xml.findall('{*}severity/{*}category/{*}cwe/{*}dynamicflaws/{*}flaw')

                if args.dynamic_only is not True:
                    for flaw in static_flaws:
                        # FOR EACH STATIC FLAW, CHECK PARAMETERS TO SEE IF WE SHOULD SKIP
                        flaw_skip_check = flaw_skip_check_func(flaw, non_policy_violating_flag,
                                                               mitigated_flag, fixed_flag)

                        # GET MITIGATION INFO
                        recent_proposed_mitigation = check_mitigations(flaw, results_xml, 'static')

                        # WRITE DATA TO THE CSV IF WE DON'T SKIP
                        if flaw_skip_check == 0:

                            row = build_csv_fields('static', flaw, app, custom_field_1, app_name, latest_build,
                                                   recent_proposed_mitigation[0], recent_proposed_mitigation[1],
                                                   recent_proposed_mitigation[2])

                            wr.writerow(row)

                            static_app_flaw_count += 1
                            total_flaw_count += 1

                    logging.info('Exported ' + str(static_app_flaw_count) + ' static flaws from ' +
                                 app_name + ' (' + str(app) + '), Build ID ' + str(latest_build))

                    if args.static_only is not True:
                        # FOR EACH DYNAMIC FLAW, CHECK PARAMETERS TO SEE IF WE SHOULD SKIP
                        for flaw in dynamic_flaws:
                            flaw_skip_check = flaw_skip_check_func(flaw, non_policy_violating_flag, mitigated_flag,
                                                                   fixed_flag)

                            # GET MITIGATION INFO
                            recent_proposed_mitigation = check_mitigations(flaw, results_xml, 'dynamic')

                            # WRITE DATA TO THE CSV IF WE DON'T SKIP
                            if flaw_skip_check == 0:

                                row = build_csv_fields('dynamic', flaw, app, custom_field_1, app_name, latest_build,
                                                       recent_proposed_mitigation[0], recent_proposed_mitigation[1],
                                                       recent_proposed_mitigation[2])
                                wr.writerow(row)

                                dynamic_app_flaw_count += 1
                                total_flaw_count += 1

                        logging.info('Exported ' + str(dynamic_app_flaw_count) + ' dynamic flaws from ' +
                                     app_name + ' (' + app + '), Build ID ' + str(latest_build))

    logging.info('COMPLETE: Exported ' + str(total_flaw_count) + ' total flaws')

    cleanup('end')


if __name__ == '__main__':
    main()
