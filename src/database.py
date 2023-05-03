import logging
import time
import json
import sqlite3
import hashlib


class DatabaseHandler:
    def __init__(self, config, db_dir):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.connection = sqlite3.connect("db/c2_servers.db")

    def urlhaus_table(self, urlhaus_c2_data):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Cashing retrieved data into 'urlhaus' table ...")
        logging.info(f"Cashing retrieved data into 'urlhaus' table")
        cursor = self.connection.cursor()
        create_table_query = '''CREATE TABLE IF NOT EXISTS urlhaus (
                                date_added TEXT,
                                url TEXT PRIMARY KEY,
                                url_status TEXT,
                                last_online TEXT,
                                threat TEXT,
                                tags TEXT,
                                urlhaus_link TEXT)'''
        cursor.execute(create_table_query)

        insert_query = '''INSERT OR IGNORE INTO urlhaus (
                          date_added,
                          url,
                          url_status,
                          last_online,
                          threat,
                          tags,
                          urlhaus_link)
                          VALUES (?, ?, ?, ?, ?, ?, ?)'''

        updated_urls = []
        for entry in urlhaus_c2_data:
            data = tuple(entry.values())
            cursor.execute(insert_query, data)
            # update the URL status to the retrieved value
            url_status = entry.get('url_status')
            if url_status:
                cursor.execute('''UPDATE urlhaus
                            SET url_status = ?
                            WHERE url = ? AND url_status != ?''',
                               (url_status, entry.get('url'), url_status))

                # add updateded URL to the list if its status was updated
                if cursor.rowcount > 0:
                    updated_urls.append(entry.get('url'))

        self.connection.commit()

        # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Total number of {self.connection.total_changes} rows inserted, deleted or updated since the database connection")
        logging.info(
            f"Total number of {self.connection.total_changes} rows inserted, deleted, updated since the database connection")

        if len(updated_urls) > 0:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Updated the status value in {len(updated_urls)} URLs")
            logging.info(f"Updated the status value in {len(updated_urls)} URLs")
            # for url in updated_urls:
            #     print(url)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] No cached entries were updated in 'urlhaus' table")
            logging.info(f"No cached entries were updated in 'urlhaus' table")

        cursor.close()

    def feodotracker_table(self, feodotracker_c2_data):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Cashing retrieved data into 'feodotracker' table ...")
        logging.info(f"Cashing retrieved data into 'feodotracker' table")
        cursor = self.connection.cursor()
        create_table_query = '''CREATE TABLE IF NOT EXISTS feodotracker (
                                id TEXT PRIMARY KEY,
                                ip_address TEXT,
                                port TEXT,
                                status TEXT,
                                hostname TEXT,
                                as_number TEXT,
                                as_name TEXT,
                                country TEXT,
                                first_seen TEXT,
                                last_online TEXT,
                                malware TEXT)'''
        cursor.execute(create_table_query)

        insert_query = '''INSERT OR IGNORE INTO feodotracker (
                          id,
                          ip_address,
                          port,
                          status,
                          hostname,
                          as_number,
                          as_name,
                          country,
                          first_seen,
                          last_online,
                          malware)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

        updated_ip_address = []
        for entry in reversed(feodotracker_c2_data):
            ip_address = entry.get('ip_address')
            port = entry.get('port')
            entry_id = hashlib.sha256(f"{ip_address}:{port}".encode('utf-8')).hexdigest()
            data = (entry_id,) + tuple(entry.values())
            cursor.execute(insert_query, data)
            # update the URL status to the retrieved value
            status = entry.get('status')
            if status:
                cursor.execute('''UPDATE feodotracker
                    SET status = ?
                    WHERE id = ? AND status != ?''',
                               (status, entry_id, status))

                # add updated IP:PORT to the list if its status was updated
                if cursor.rowcount > 0:
                    updated_ip_address.append(f"{ip_address}:{port}")

        self.connection.commit()

        # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Total number of {self.connection.total_changes} rows inserted, deleted or updated since the database connection")
        logging.info(
            f"Total number of {self.connection.total_changes} rows inserted, deleted, updated since the database connection")

        if len(updated_ip_address) > 0:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Updated the status value in {len(updated_ip_address)} IP addresses")
            logging.info(f"Updated the status value in {len(updated_ip_address)} IP addresses")
        #     for ip in updated_ip_address:
        #         print(ip)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] No cached entries were updated in 'feodotracker' table")
            logging.info(f"No cached entries were updated in 'feodotracker' table")

        cursor.close()

    def threatfox_table(self, threatfox_data):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Cashing retrieved data into 'threatfox' table ...")
        logging.info(f"Cashing retrieved data into 'threatfox' table")
        cursor = self.connection.cursor()

        create_table_query = '''CREATE TABLE IF NOT EXISTS threatfox (
                                id TEXT PRIMARY KEY,
                                ioc TEXT,
                                ioc_type TEXT,
                                threat_type TEXT,
                                malware TEXT,
                                first_seen_utc TEXT,
                                last_seen_utc TEXT,
                                confidence_level TEXT,
                                tags TEXT)'''
        cursor.execute(create_table_query)

        insert_query = '''INSERT OR IGNORE INTO threatfox (
                            id,
                            ioc,
                            ioc_type,
                            threat_type,
                            malware,
                            first_seen_utc,
                            last_seen_utc,
                            confidence_level,
                            tags)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'''

        updated_iocs = []
        for entry in threatfox_data:
            ioc = entry.get('ioc')
            first_seen_utc = entry.get('first_seen_utc')
            entry_id = hashlib.sha256(f"{ioc}:{first_seen_utc}".encode('utf-8')).hexdigest()
            data = (entry_id,) + tuple(entry.values())
            cursor.execute(insert_query, data)
            # update 'last_seen_utc' if changed
            last_seen_utc = entry.get('last_seen_utc')
            if last_seen_utc:
                cursor.execute('''UPDATE threatfox
                            SET last_seen_utc = ?
                            WHERE id = ? AND last_seen_utc != ?''',
                               (last_seen_utc, entry_id, last_seen_utc))

                # if entry was updated, add IOC to a list of updated IoCs
                if cursor.rowcount > 0:
                    updated_iocs.append(f"{entry.get('ioc')} : {entry.get('first_seen_utc')}")

        self.connection.commit()

        # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Total number of {self.connection.total_changes} rows inserted, deleted or updated since the database connection")
        logging.info(
            f"Total number of {self.connection.total_changes} rows inserted, deleted, updated since the database connection")

        if len(updated_iocs) > 0:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Updated 'last seen' value in {len(updated_iocs)} IoCs")
            logging.info(f"Updated 'last seen' value in {len(updated_iocs)} IoCs")
            # for ioc in updated_iocs:
            #     print(ioc)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] No cached entries were updated in 'threatfox' table")
            logging.info(f"No cached entries were updated in 'threatfox' table")

        cursor.close()

    def shodan_table(self, shodan_data):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Cashing retrieved data into 'shodan' table ...")
        logging.info(f"Cashing retrieved data into 'shodan' table")
        cursor = self.connection.cursor()

        create_table_query = '''CREATE TABLE IF NOT EXISTS shodan (
                                product TEXT,
                                ip_address TEXT PRIMARY KEY,
                                asn TEXT,
                                org TEXT,
                                isp TEXT,
                                hostname TEXT,
                                country_name TEXT,
                                country_code TEXT,
                                city TEXT,
                                region_code TEXT,
                                last_seen,
                                product_query TEXT,
                                search_operator TEXT)'''
        cursor.execute(create_table_query)

        insert_query = '''INSERT OR IGNORE INTO shodan (
                          product,
                          ip_address,
                          asn,
                          org,
                          isp,
                          hostname,
                          country_name,
                          country_code,
                          city,
                          region_code,
                          last_seen,
                          product_query,
                          search_operator)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

        updated_ip_address = []
        for product in shodan_data:
            for entry in product:
                hostnames = entry.get("hostnames")
                entry["hostnames"] = json.dumps(hostnames)  # serialize list to a string
                data = tuple(entry.values())
                cursor.execute(insert_query, data)
                # update all data for the entry if 'last_seen' changed
                last_seen = entry.get('last_seen')
                if last_seen:
                    cursor.execute('''UPDATE shodan
                                    SET product = ?, asn = ?, org = ?, isp = ?, hostname = ?, country_name = ?, country_code = ?, city = ?, region_code = ?, last_seen = ?, product_query = ?, search_operator = ?
                                    WHERE ip_address = ? AND last_seen != ?''',
                                   (entry.get('product'), entry.get('asn'), entry.get('org'), entry.get('isp'),
                                    entry.get('hostnames'), entry.get('country_name'), entry.get('country_code'),
                                    entry.get('city'), entry.get('region_code'), entry.get('last_seen'),
                                    entry.get('product_query'), entry.get('search_operator'),
                                    entry.get('ip'), last_seen))

                # if entry was updated, add IOC to a list of updated IoCs
                if cursor.rowcount > 0:
                    updated_ip_address.append(f"{entry.get('product')} : {entry.get('ip')}")

        self.connection.commit()

        # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Total number of {self.connection.total_changes} rows inserted, deleted or updated since the database connection")
        logging.info(
            f"Total number of {self.connection.total_changes} rows inserted, deleted, updated since the database connection")

        if len(updated_ip_address) > 0:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Updated entry data for {len(updated_ip_address)} IP addresses")
            logging.info(f"Updated entry data for {len(updated_ip_address)} IP addresses")
            # for ip in updated_ip_address:
            #     print(ip)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] No cached entries were updated in 'shodan' table")
            logging.info(f"No cached entries were updated in 'shodan' table")

        cursor.close()
