import math
import time
import pandas as pd
import logging
import psycopg2
import requests

from db_utils import upsert_row, get_conn


def extract_cve_data(list_to_append: list, cve_json: dict):
    """
    Extracts the CVE data from the JSON and appends it to the list
    :param list_to_append: List to append the data to
    :param cve_json: JSON data for the CVE
    :return: None
    """
    list_to_append.append({
        'id': cve_json.get('id'),
        'published_at': cve_json.get('published'),
        'last_modified_at': cve_json.get('lastModified'),
        'source_identifier': cve_json.get('sourceIdentifier'),
        'vuln_status': cve_json.get('vulnStatus')
    })


def extract_description_data(list_to_append: list, cve_json: dict):
    """
    Extracts the description data from the JSON and appends it to the list
    :param list_to_append: List to append the data to
    :param cve_json: JSON data for the CVE
    :return: None
    """
    descriptions = cve_json.get('descriptions', [])
    for description in descriptions:
        list_to_append.append({
            'cve_id': cve_json.get('id'),
            'lang': description.get('lang'),
            'value': description.get('value')
        })


def extract_cvss_metric_data(list_to_append: list, cve_json: dict):
    """
    Extracts the CVSS metric data from the JSON and appends it to the list
    :param list_to_append: List to append the data to
    :param cve_json: JSON data for the CVE
    :return: None
    """
    for metric_version in ['cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31']:
        if metric_version not in cve_json.get('metrics', {}):
            continue

        cvss_metrics = cve_json.get('metrics', {}).get(metric_version, [])
        for metric in cvss_metrics:
            version = metric.get('cvssData', {}).get('version')
            if version == '2.0':
                list_to_append.append({
                    'cve_id': cve_json.get('id'),
                    'version': metric.get('cvssData', {}).get('version'),
                    'base_score': metric.get('cvssData', {}).get('baseScore'),
                    'exploitability_score': metric.get('exploitabilityScore'),
                    'impact_score': metric.get('impactScore'),
                    'base_severity': metric.get('baseSeverity'),
                    'vector_string': metric.get('cvssData', {}).get('vectorString'),
                    'access_vector': metric.get('cvssData', {}).get('accessVector'),
                    'access_complexity': metric.get('cvssData', {}).get('accessComplexity'),
                    'authentication': metric.get('cvssData', {}).get('authentication'),
                    'confidentiality_impact': metric.get('cvssData', {}).get('confidentialityImpact'),
                    'integrity_impact': metric.get('cvssData', {}).get('integrityImpact'),
                    'availability_impact': metric.get('cvssData', {}).get('availabilityImpact'),
                    'ac_insuf_info': metric.get('acInsufInfo'),
                    'obtain_all_privilege': metric.get('obtainAllPrivilege'),
                    'obtain_user_privilege': metric.get('obtainUserPrivilege'),
                    'obtain_other_privilege': metric.get('obtainOtherPrivilege'),
                    'user_interaction_required': metric.get('userInteractionRequired')
                })
            else:
                list_to_append.append({
                    'cve_id': cve_json.get('id'),
                    'version': metric.get('cvssData', {}).get('version'),
                    'base_score': metric.get('cvssData', {}).get('baseScore'),
                    'exploitability_score': metric.get('exploitabilityScore'),
                    'impact_score': metric.get('impactScore'),
                    'base_severity': metric.get('cvssData', {}).get('baseSeverity'),
                    'vector_string': metric.get('cvssData', {}).get('vectorString'),
                    'access_vector': metric.get('cvssData', {}).get('attackVector'),
                    'access_complexity': metric.get('cvssData', {}).get('attackComplexity'),
                    'authentication': metric.get('cvssData', {}).get('privilegesRequired'),
                    'confidentiality_impact': metric.get('cvssData', {}).get('confidentialityImpact'),
                    'integrity_impact': metric.get('cvssData', {}).get('integrityImpact'),
                    'availability_impact': metric.get('cvssData', {}).get('availabilityImpact'),
                    'ac_insuf_info': None,
                    'obtain_all_privilege': metric.get('obtainAllPrivilege'),
                    'obtain_user_privilege': metric.get('obtainUserPrivilege'),
                    'obtain_other_privilege': metric.get('obtainOtherPrivilege'),
                    'user_interaction_required': metric.get('userInteractionRequired')
                })


def extract_configurations_data(list_to_append: list, cve_json: dict):
    """
    Extracts the configuration data from the JSON and appends it to the list
    :param list_to_append: List to append the data to
    :param cve_json: JSON data for the CVE
    :return: None
    """
    configurations = cve_json.get('configurations', [])
    for config in configurations:
        nodes = config.get('nodes', [])
        for node in nodes:
            cpe_matches = node.get('cpeMatch', [])
            for cpe in cpe_matches:
                list_to_append.append({
                    'cve_id': cve_json.get('id'),
                    'match_criteria_id': cpe.get('matchCriteriaId'),
                    'cpe23_uri': cpe.get('criteria'),
                    'flag_vulnerable': cpe.get('vulnerable'),
                })


def extract_references_data(list_to_append: list, cve_json: dict):
    """
    Extracts the references data from the JSON and appends it to the list
    :param list_to_append: List to append the data to
    :param cve_json: JSON data for the CVE
    :return: None
    """
    references = cve_json.get('references', [])
    for reference in references:
        list_to_append.append({
            'cve_id': cve_json.get('id'),
            'url': reference.get('url'),
            'source': reference.get('source')
        })


def save_patch_to_db(data_patch: dict, conn: psycopg2.extensions.connection):
    """
    Saves the patch data to the database
    :param data_patch: JSON data for the patch
    :param conn: Database connection
    :return: None
    """
    cve_data = []
    descriptions_data = []
    cvss_data = []
    configurations_data = []
    references_data = []

    # Extract data from the patch
    for vuln in data_patch['vulnerabilities']:
        cve = vuln.get('cve', {})
        extract_cve_data(cve_data, cve)
        extract_description_data(descriptions_data, cve)
        extract_cvss_metric_data(cvss_data, cve)
        extract_configurations_data(configurations_data, cve)
        extract_references_data(references_data, cve)

    # Convert lists to DataFrames
    df_cve = pd.DataFrame(cve_data)
    df_descriptions = pd.DataFrame(descriptions_data)
    df_cvss = pd.DataFrame(cvss_data)
    df_configurations = pd.DataFrame(configurations_data)
    df_references = pd.DataFrame(references_data)

    # Save the data to the database
    upsert_row(df_cve, 'cves', conn, primary_key=['id'])
    upsert_row(df_descriptions, 'cve_description', conn, primary_key=['cve_id', 'lang'])
    upsert_row(df_cvss, 'cve_impact', conn, primary_key=['cve_id', 'version'])
    upsert_row(df_configurations, 'cve_cpe', conn, primary_key=['cve_id', 'match_criteria_id'])
    upsert_row(df_references, 'cve_references', conn, primary_key=['cve_id', 'url'])


if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Select the page you want to start syncing from and the page size
    page = 0
    results_per_page = 2000
    total_results = None

    # Connect to the database
    conn = get_conn()
    try:
        while total_results is None or page < math.ceil(total_results / results_per_page):
            t0 = time.time()
            response = requests.get(
                f'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={results_per_page}&startIndex={page * results_per_page}')
            if response.status_code != 200:
                logging.error(f"Response status code: {response.status_code}")
                logging.error(f"Error fetching data from NVD: {response.text}")
                raise Exception(f"Error fetching data from NVD: {response.text}")

            data = response.json()

            # metadata
            if total_results is None:
                results_per_page = data['resultsPerPage']
                total_results = data['totalResults']

            logging.info(f"Processing page {page} of {math.ceil(total_results / results_per_page)}")

            save_patch_to_db(data, conn)

            # increment the page number for the next request
            page += 1

            # to not go over the time limit of 5 requests per 30 seconds
            time.sleep(max(0, 7 - (time.time() - t0)))
    except Exception as e:
        logging.error(f"Error processing page {page}: {e}")
        raise e
    finally:
        conn.close()



