import os
import sys
import time
import csv
import json
import logging
import requests
from colorama import Fore
import zipfile
import shodan
from shodan.exception import APIError


class Hunter:
    def __init__(self, config, output_dir):
        self.logger = logging.getLogger(__name__)

        self.config = config
        self.api_keys = self.config.get('api_keys')
        self.shodan_api_key = self.api_keys.get('shodan')
        self.api = shodan.Shodan(self.shodan_api_key)

        self.country_code = config.get('country_code')

        self.reports_path = output_dir
        self.config_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/config"
        self.reports_ips_path = f"{self.reports_path}/ips"
        self.reports_json_path = f"{self.reports_path}/json"
        self.reports_csv_path = f"{self.reports_path}/csv"
        self.reports_raw_path = f"{self.reports_path}/raw"
        self.reports_iocs_path = f"{self.reports_path}/iocs"

        self.feodotracker_c2_url = self.config.get('feeds').get('feodotracker')
        self.urlhaus_feed_url = self.config.get('feeds').get('urlhaus')
        self.urlhaus_cc_feed_url = f"{self.config.get('feeds').get('urlhaus_cc_feed')}{self.country_code}"
        self.threatfox_feed_url = self.config.get('feeds').get('threatfox')

        self.products = self.get_search_operators("c2")  # "malware", "tools"

    def get_search_operators(self, type):
        file_name = f"{self.config_path}/{type}_search_operators.json"
        with open(file_name, "r") as file_input:
            data = json.loads(file_input.read())
        return data['search_operators']

    def query_shodan(self):
        # print("SHODAN")
        # logging.info("SHODAN")
        terminal_size = os.get_terminal_size()
        # selected_machines = {}  # JSON report of selected machines based on the configured country code  
        selected_entries = []  # list of selected machines

        shodan_c2_data = []
        for product, queries in self.products.items():
            # raw_responses = {}  # unfiltered JSON responses
            raw_responses_entries = []
            # products = {}   # JSON report
            product_entries = []  # list of products from one page result
            product_table = []  # CSV report
            entries_count = 0
            ip_list = []  # TXT report

            for query in queries:
                # single quote used because of JSON formating
                query = query.replace("'", "\"")

                print(
                    f"[{time.strftime('%H:%M:%S')}] [INFO] Initializing search for {product} with '{query}' search query ...")
                self.logger.info(
                    f"Initializing search for {product} with '{query}' search query")

                # NOTE: Please purchase a Shodan membership to access more than 2 pages of results ...
                for i in range(1, 100):

                    attempts = 10
                    while attempts > 0:
                        try:
                            self.logger.info(f"Searching Shodan")
                            results = self.api.search(query, page=i)
                        except APIError as e:
                            print(
                                f"[{time.strftime('%H:%M:%S')}] [WARNING] {e}")
                            self.logger.warning(f"{e}")
                            print(
                                f"[{time.strftime('%H:%M:%S')}] [INFO] Remaining number of connection retries {attempts}")
                            self.logger.info(
                                f"Remaining number of connection retries {attempts}")
                            attempts -= 1
                            time.sleep(3)
                            continue
                        except Exception as e:  # catch different error than 'APIError'
                            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] {e}")
                            self.logger.error(f"{e}")
                            print("\nExiting program ...\n")
                            sys.exit(1)
                        break

                    if attempts == 0:
                        print(
                            f"[{time.strftime('%H:%M:%S')}] [ERROR] Number of connection retries exceeded")
                        self.logger.error(
                            f"Number of connection retries exceeded")
                        print("\nExiting program ...\n")
                        sys.exit(1)

                    # alternative: results['total']
                    number_of_results = len(results["matches"])
                    entries_count += number_of_results

                    if number_of_results == 0:  # no results when the page after the last one is accessed
                        print(
                            f"[{time.strftime('%H:%M:%S')}] [INFO] Last page reached")
                        self.logger.info(f"Last page reached")
                        break
                    elif number_of_results > 0:
                        print(
                            f"[{time.strftime('%H:%M:%S')}] [INFO] Search query returned {number_of_results} result(s)")
                        self.logger.info(
                            f"Search query returned {number_of_results} result(s)")
                        print(
                            f"[{time.strftime('%H:%M:%S')}] [INFO] Parsing page number {i}")
                        self.logger.info(f"Parsing page number {i}")

                        for service in results["matches"]:

                            raw_responses_entries.append(service)

                            product_name = service.get("product")
                            ip = service.get("ip_str")
                            asn = service.get("asn")
                            org = service.get('org')
                            isp = service.get('isp')
                            hostnames = service.get('hostnames')
                            location = service.get('location')
                            if location:
                                country_name = location.get('country_name')
                                country_code = location.get('country_code')
                                city = location.get('city')
                                region_code = location.get('region_code')
                            else:
                                country_name, country_code, city, region_code = "", "", "", ""
                            last_seen = service.get('timestamp')

                            if not ip in ip_list:

                                entry = [product_name, ip, asn, org, isp, hostnames, country_name,
                                         country_code, city, region_code, last_seen]  # used for writing to CSV file
                                product_table.append(entry)

                                service_entry = dict(
                                    product=product_name,
                                    ip=ip,
                                    asn=asn,
                                    org=org,
                                    isp=isp,
                                    hostnames=hostnames,
                                    country_name=country_name,
                                    country_code=country_code,
                                    city=city,
                                    region_code=region_code,
                                    last_seen=last_seen,
                                    product_query=product,
                                    search_operator=query
                                )
                                product_entries.append(service_entry)

                                if country_code == self.country_code:
                                    selected_entries.append(service_entry)

                            ip_list.append(ip)

                print(
                    f"[{time.strftime('%H:%M:%S')}] [INFO] Processed {len(ip_list)} IP addresses so far")
                self.logger.info(f"Processed {len(ip_list)} IP addresses")

            # build one list which contains all the products  
            shodan_c2_data.append(product_entries)

            ip_list = list(set(ip_list))
            print(
                f"\n[{time.strftime('%H:%M:%S')}] [INFO] Found {len(ip_list)} unique IP addresses")
            self.logger.info(f"Found {len(ip_list)} unique IP addresses")

            product_name = product.replace(" ", "_")

            self.write_ips_report(product_name, ip_list)
            self.write_json_report(product_name, product_entries)
            self.write_csv_report(product_name, product_table)
            self.write_raw_report(product_name, raw_responses_entries)

            print('.' * terminal_size.columns)

        # print(':' * terminal_size.columns)

        if selected_entries:
            self.write_matched_machines(selected_entries)
            print('-' * terminal_size.columns)

        return shodan_c2_data

    def write_matched_machines(self, selected_entries):
        selected_machines = {}
        selected_machines['country_code'] = self.country_code
        selected_machines['matches'] = selected_entries
        json_object = json.dumps(selected_machines, indent=4)
        file_name = f"{self.reports_json_path}/{self.country_code}_matches.json"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing JSON report to {file_name} ...")
        self.logger.info(f"Writing JSON report to {file_name}")
        with open(file_name, "w") as file:
            file.write(json_object)

    def write_ips_report(self, product_name, ip_list):
        file_name = f"{self.reports_ips_path}/{product_name}.txt"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing IP address list to {file_name} ...")
        self.logger.info(f"Writing IP address list to {file_name}")
        with open(file_name, "w") as output_file:
            for ip in ip_list:
                output_file.write(f"{ip}\n")

    def write_raw_report(self, product_name, raw_responses_entries):
        json_object = json.dumps(raw_responses_entries, indent=4)
        file_name = f"{self.reports_raw_path}/{product_name}_RAW.json"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing RAW unfiltered report to {file_name} ...")
        self.logger.info(f"Writing RAW unfiltered report to {file_name}")
        with open(file_name, "w") as file:
            file.write(json_object)

    def write_json_report(self, product_name, product_entries):
        json_object = json.dumps(product_entries, indent=4)
        file_name = f"{self.reports_json_path}/{product_name}.json"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing JSON report to {file_name} ...")
        self.logger.info(f"Writing JSON report to {file_name}")
        with open(file_name, "w") as file:
            file.write(json_object)

    def write_csv_report(self, product_name, product_table):
        fields = ["Product", "IP Address", "ASN", "Organization", "ISP",
                  "Hostnames", "Country", "Country Code", "City", "Region Code", "Last Seen"]
        file_name = f"{self.reports_csv_path}/{product_name}.csv"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing CSV report to {file_name} ...")
        self.logger.info(f"Writing CSV report to {file_name}")
        with open(file_name, 'w') as file:
            write = csv.writer(file, delimiter=';')
            write.writerow(fields)
            write.writerows(product_table)

    def query_feodotracker(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching latest Feodo Tracker's Botnet C2 IoCs ...")
        logging.info(
            f"Fetching latest Feodo Tracker's Botnet C2 IoCs")
        response = requests.get(self.feodotracker_c2_url)
        feodotracker_c2 = json.loads(response.content.decode("utf-8"))
        json_object = json.dumps(feodotracker_c2, indent=4)
        self.write_iocs_report(f"feodotracker_C2", json_object)

        return feodotracker_c2

    def search_feodotracker(self, feodotracker_c2):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Searching for country code '{self.country_code}' in Feodo Tracker IoCs ...")
        logging.info(f"Searching for country code '{self.country_code}' in IoCs ...")

        found = False
        found_active = False
        matched_machines = []
        matched_machines_online = []

        # IP addresses that were acting as a botnet C2 within the past 30 days
        for entry in feodotracker_c2:
            if entry['country'] == self.country_code:
                matched_machines.append(entry)
                found = True
            if entry['country'] == self.country_code and entry['status'] == "online":
                matched_machines_online.append(entry)
                found_active = True

        if not found:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}No matches for country code '{self.country_code}' were found in Feodo Tracker IoCs{Fore.RESET}")
            logging.info(
                f"No matches for country code '{self.country_code}' were found")
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Found matches for country code '{self.country_code}' in Feodo Tracker IoCs{Fore.RESET}")
            logging.info(
                f"Found matches for country code '{self.country_code}'")
            json_object = json.dumps(matched_machines, indent=4)
            self.write_iocs_report(f"feodotracker_C2_{self.country_code}", json_object)

            if found_active:
                print(
                    f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Found active machines for country code '{self.country_code}' in Feodo Tracker IoCs{Fore.RESET}")
                logging.info(f"Found active machines for country code '{self.country_code}' in Feodo Tracker IoCs")
                json_object = json.dumps(matched_machines_online, indent=4)
                self.write_iocs_report(f"feodotracker_C2_{self.country_code}_active", json_object)

        return matched_machines, matched_machines_online

    def query_urlhaus(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching URLhaus full data dump ...")
        logging.info(f"Fetching URLhaus full data dump ...'")

        response = requests.get(self.urlhaus_feed_url)

        if response.status_code == 200:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Successfully downloaded zip compressed data dump ...")
            logging.info(f"Successfully downloaded zip compressed data dump ...'")
            # save the content of the response as a binary file
            with open("urlhaus.zip", "wb") as f:
                f.write(response.content)

            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting URLhaus IoCs feed from the retrieved zip file ...")
            logging.info(f"Extracting URLhaus IoCs feed from the retrieved zip file ...'")
            with zipfile.ZipFile("urlhaus.zip", "r") as zip_ref:
                zip_ref.extractall(f"{self.reports_iocs_path}/")

            # remove the zip file
            logging.info(f"Removing retrieved zip file ...'")
            os.remove("urlhaus.zip")

            # rename extracted csv
            logging.info(f"Renaming extracted URLhaus CSV feed ...'")
            os.rename(f"{self.reports_iocs_path}/csv.txt", f"{self.reports_iocs_path}/urlhaus.csv")

            # load extracted csv
            logging.info(f"Loading extracted URLhaus CSV feed ...'")
            with open(f"{self.reports_iocs_path}/urlhaus.csv", "r") as urlhaus_feed:
                response_data = urlhaus_feed.read().splitlines()

            # remove extracted csv
            logging.info(f"Removing extracted URLhaus CSV feed ...'")
            os.remove(f"{self.reports_iocs_path}/urlhaus.csv")

            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Parsing extracted URLhaus IoCs ...")
            logging.info("Parsing extracted URLhaus IoCs")
            data = []
            for line in response_data:
                # retrieved content has a header created from '#' symbols
                if not line.startswith("#") and len(line) > 0:
                    # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                    prepared_data = list(csv.reader([line]))[0]
                    entry = dict(
                        date_added=prepared_data[1],
                        url=prepared_data[2],
                        url_status=prepared_data[3],
                        last_online=prepared_data[4],
                        threat=prepared_data[5],
                        tags=prepared_data[6],
                        urlhaus_link=prepared_data[7]
                    )
                    data.append(entry)

            if data:
                self.write_iocs_report(f"urlhaus_C2", json.dumps(data, indent=4))

        return data

    def query_urlhaus_cc(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching recent URLhaus Country feed for '{self.country_code}' ...")
        logging.info(f"Fetching recent URLhaus Country feed for '{self.country_code}'")

        response = requests.get(self.urlhaus_cc_feed_url)
        response_content = response.content.decode("utf-8")
        response_data = response_content.split("\n")

        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Parsing fetched URLhaus Country feed ...")
        logging.info("Parsing fetched URLhaus Country feed")
        data = []
        for line in response_data:
            # retrieved content has a header created from '#' symbols
            if not line.startswith("#") and len(line) > 0:
                prepared_data = list(csv.reader([line]))[0]
                entry = dict(
                    date_added=prepared_data[0],
                    url=prepared_data[1],
                    url_status=prepared_data[2],
                    threat=prepared_data[3],
                    host=prepared_data[4],
                    ip_address=prepared_data[5],
                    asn=prepared_data[6],
                    country_code=prepared_data[7],
                )
                data.append(entry)

        json_object = json.dumps(data, indent=4)
        if data:  # write only if data is not empty
            self.write_iocs_report(f"urlhaus_C2_{self.country_code}", json_object)

        return data

    def search_urlhaus(self, urlhaus_feed):

        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Searching in URLhaus feed for active URLs whose domain name resolve to '{self.country_code}' IP address ...")
        logging.info(
            f"Searching in URLhaus feed for active URLs whose domain name resolve to '{self.country_code}' IP address ...")

        found = False
        matched_machines_online = []

        for entry in urlhaus_feed:
            if entry['url_status'] == "online":
                matched_machines_online.append(entry)
                found = True

        if not found:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}No active URLs for country code '{self.country_code}' were found in URLhaus feed{Fore.RESET}")
            logging.info(
                f"No active URLs for country code '{self.country_code}' were found in URLhaus feed")
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Found active URLs for country code '{self.country_code}' in URLhaus feed{Fore.RESET}")
            logging.info(
                f"Found active URLs for country code '{self.country_code}' in URLhaus feed")
            json_object = json.dumps(matched_machines_online, indent=4)
            self.write_iocs_report(f"urlhaus_C2_{self.country_code}_active", json_object)

        return matched_machines_online

    def get_threatfox_iocs(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching ThreatFox full data dump ...")
        logging.info(f"Fetching ThreatFox full data dump ...'")

        response = requests.get(self.threatfox_feed_url)

        if response.status_code == 200:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Successfully downloaded zip compressed data dump ...")
            logging.info(f"Successfully downloaded zip compressed data dump ...'")
            # save the content of the response as a binary file
            with open("threatfox.zip", "wb") as f:
                f.write(response.content)

            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting ThreatFox IoCs feed from the retrieved zip file ...")
            logging.info(f"Extracting ThreatFox IoCs feed from the retrieved zip file ...'")
            with zipfile.ZipFile("threatfox.zip", "r") as zip_ref:
                zip_ref.extractall(f"{self.reports_iocs_path}/")

            # remove the zip file
            logging.info(f"Removing retrieved zip file ...'")
            os.remove("threatfox.zip")

            # rename extracted json
            logging.info(f"Renaming extracted ThreatFox JSON feed ...'")
            os.rename(f"{self.reports_iocs_path}/full.json", f"{self.reports_iocs_path}/threatfox_C2.json")

            # load the JSON file
            logging.info(f"Loading extracted ThreatFox JSON feed ...'")
            with open(f"{self.reports_iocs_path}/threatfox_C2.json", "r") as f:
                threatfox_urls = json.load(f)

            # parse threatfox iocs
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Parsing extracted ThreatFox IoCs ...")
            logging.info("Parsing extracted ThreatFox IoCs")
            data = []
            for key, value in threatfox_urls.items():
                ioc_data = value[0]
                entry = dict(
                    ioc=ioc_data.get('ioc_value'),
                    ioc_type=ioc_data.get('ioc_type'),
                    threat_type=ioc_data.get('threat_type'),
                    malware=ioc_data.get('malware_printable'),
                    first_seen_utc=ioc_data.get('first_seen_utc'),
                    last_seen_utc=ioc_data.get('last_seen_utc'),
                    confidence_level=ioc_data.get('confidence_level'),
                    tags=ioc_data.get('tags')
                )
                data.append(entry)

            return data

        else:
            return

    def write_iocs_report(self, service_name, json_object):
        report_output_path = f"{self.reports_iocs_path}/{service_name}.json"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing IoCs to '{report_output_path} ...'")
        logging.info(f"Writing IoCs to '{report_output_path}'")
        with open(report_output_path, "w") as output:
            output.write(json_object)
