import logging
import time
import json
from  colorama import Fore
import sqlite3
import hashlib


class DatabaseHandler:
    def __init__(self, config, db_dir):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.connection = sqlite3.connect("db/c2_servers.db")

    def urlhaus_table(self, urlhaus_c2_data):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Cashing retrieved data into 'urlhaus' table")
        logging.info(f"Cashing retrieved data into 'urlhaus' table")
        cursor = self.connection.cursor()
        create_table_query = '''CREATE TABLE IF NOT EXISTS urlhaus (
                                date_added TEXT,
                                url TEXT PRIMARY KEY,
                                url_status TEXT,
                                threat TEXT,
                                host TEXT,
                                ip_address TEXT,
                                asn TEXT,
                                country_code TEXT)'''
        cursor.execute(create_table_query)

        insert_query = '''INSERT OR IGNORE INTO urlhaus (
                          date_added,
                          url,
                          url_status,
                          threat,
                          host,
                          ip_address,
                          asn,
                          country_code)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)'''

        updated_urls = []
        for entry in reversed(urlhaus_c2_data):
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

        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Total number of {self.connection.total_changes} rows inserted, deleted or updated since the database connection")
        logging.info(f"Total number of {self.connection.total_changes} rows inserted, deleted, updated since the database connection")

        if len(updated_urls) > 0:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Updated the status value in {len(updated_urls)} URLs")
            logging.info(f"Updated the status value in {len(updated_urls)} URLs")
            # for url in updated_urls:
            #     print(url)
        # else:
        #     print(f"[{time.strftime('%H:%M:%S')}] [INFO] No cached entries were updated in 'urlhaus' table")
        #     logging.info(f"No cached entries were updated in 'urlhaus' table")

        cursor.close()

    def feodotracker_table(self, feodotracker_c2_data):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Cashing retrieved data into 'feodotracker' table")
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

                # add updateded IP:PORT to the list if its status was updated
                if cursor.rowcount > 0:
                    updated_ip_address.append(f"{ip_address}:{port}")

        self.connection.commit()

        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Total number of {self.connection.total_changes} rows inserted, deleted or updated since the database connection")
        logging.info(f"Total number of {self.connection.total_changes} rows inserted, deleted, updated since the database connection")

        if len(updated_ip_address) > 0:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Updated the status value in {len(updated_ip_address)} IP addresses")
            logging.info(f"Updated the status value in {len(updated_ip_address)} IP addresses")
        #     for url in updated_ip_address:
        #         print(url)
        # else:
        #     print(f"[{time.strftime('%H:%M:%S')}] [INFO] No cached entries were updated in 'feodotracker' table")
        #     logging.info(f"No cached entries were updated in 'feodotracker' table")

        cursor.close()

    def shodan_table(self, shodan_data):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Cashing retrieved data into 'shodan' table")
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

        for product in shodan_data:
            for entry in product:
                hostnames = entry.get("hostnames")
                entry["hostnames"] = json.dumps(hostnames) # serialize list to a string
                data = tuple(entry.values())
                cursor.execute(insert_query, data)

        self.connection.commit()

        cursor.close()


