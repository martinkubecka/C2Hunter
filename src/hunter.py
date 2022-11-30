import os
import sys
import time
import csv
import json
import logging
import shodan
from shodan.exception import APIError


class Hunter:
    def __init__(self, config, output_dir):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.shodan_api_key = self.get_shodan_api_key()
        self.api = shodan.Shodan(self.shodan_api_key)
        self.country_code = config.get('country_code')

        self.reports_path = output_dir
        self.config_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/config"
        self.reports_json_path = f"{self.reports_path}/json"
        self.reports_csv_path = f"{self.reports_path}/csv"
        self.reports_raw_path = f"{self.reports_path}/raw"

        self.products = self.get_search_operators("c2")  # "malware", "tools"

    def get_shodan_api_key(self):
        self.api_keys = self.config.get('api_keys')
        if self.api_keys:
            shodan_api_key = self.api_keys.get('shodan')
            # print(f"API KEY: {shodan_api_key}")
            return shodan_api_key
        return

    def shodan_query(self):
        terminal_size = os.get_terminal_size()
        # output dictionary of entries based on the configured country code
        selected_machines = {}
        selected_entries = []   # list of selected machines based on the configured country code

        for product, queries in self.products.items():
            print('-' * terminal_size.columns)
            raw_responses = {}  # unfiltered JSON responses
            raw_responses_entries = []
            products = {}   # JSON report
            product_entries = []    # list of products from one page result
            product_table = []  # CSV report
            entries_count = 0
            ip_list = []    # TXT report

            for query in queries:
                # single quote used because of JSON formating
                query = query.replace("'", "\"")

                print(
                    f"[{time.strftime('%H:%M:%S')}] [INFO] Initializing search for {product} with '{query}' search query ...")
                self.logger.info(
                    f"Initializing search for {product} with '{query}' search quer")

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
                        except:  # catch different error than 'APIError'
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

                            if not ip in ip_list:

                                entry = [product_name, ip, asn, org, isp, hostnames, country_name,
                                         country_code, city, region_code]  # used for writing to CSV file
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
                                    metadata=dict(
                                        product_query=product,
                                        search_operator=query
                                    )
                                )
                                product_entries.append(service_entry)

                                if country_code == self.country_code:
                                    selected_entries.append(service_entry)

                            ip_list.append(ip)
                            # print(ip)

                print(
                    f"[{time.strftime('%H:%M:%S')}] [INFO] Processed {len(ip_list)} IP addresses so far")
                self.logger.info(f"Processed {len(ip_list)} IP addresses")

            ip_list = list(set(ip_list))
            print(
                f"\n[{time.strftime('%H:%M:%S')}] [INFO] Found {len(ip_list)} unique IP addresses")
            self.logger.info(f"Found {len(ip_list)} unique IP addresses")

            product_name = product.replace(" ", "_")

            file_name = f"{self.reports_path}/{product_name}.txt"
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Writing IP address list to {file_name} ...")
            self.logger.info(f"Writing IP address list to {file_name}")
            with open(file_name, "w") as output_file:
                for ip in ip_list:
                    output_file.write(f"{ip}\n")

            raw_responses['matches'] = raw_responses_entries
            json_object = json.dumps(raw_responses, indent=4)
            file_name = f"{self.reports_raw_path}/{product_name}_RAW.json"
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Writing RAW unfiltered report to {file_name} ...")
            self.logger.info(f"Writing RAW unfiltered report to {file_name}")
            with open(file_name, "w") as file:
                file.write(json_object)

            fields = ["Product", "IP Address", "ASN", "Organization", "ISP",
                      "Hostnames", "Country", "Country Code", "City", "Region Code"]
            file_name = f"{self.reports_csv_path}/{product_name}.csv"
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Writing CSV report to {file_name} ...")
            self.logger.info(f"Writing CSV report to {file_name}")
            with open(file_name, 'w') as file:
                write = csv.writer(file, delimiter=';')
                write.writerow(fields)
                write.writerows(product_table)

            products['matches'] = product_entries
            json_object = json.dumps(products, indent=4)
            file_name = f"{self.reports_json_path}/{product_name}.json"
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Writing JSON report to {file_name} ...")
            self.logger.info(f"Writing JSON report to {file_name}")
            with open(file_name, "w") as file:
                file.write(json_object)

        print('-' * terminal_size.columns)

        if selected_entries:
            selected_machines['country_code'] = self.country_code
            selected_machines['matches'] = selected_entries
            json_object = json.dumps(selected_machines, indent=4)
            file_name = f"{self.reports_json_path}/{self.country_code}_matches.json"
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Writing JSON report to {file_name} ...")
            self.logger.info(f"Writing JSON report to {file_name}")
            with open(file_name, "w") as file:
                file.write(json_object)
            print('-' * terminal_size.columns)

    def get_search_operators(self, type):
        file_name = f"{self.config_path}/{type}_search_operators.json"
        with open(file_name, "r") as file_input:
            data = json.loads(file_input.read())
        return data['search_operators']
