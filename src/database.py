import logging
import sqlite3


class DatabaseHandler:
    def __init__(self, config, db_dir):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.connection = sqlite3.connect("db/c2_servers.db")

    def urlhaus_db(self, urlhaus_c2_data):
        cursor = self.connection.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS urlhaus (date_added TEXT, url TEXT, url_status TEXT, threat TEXT, host TEXT, ip_address TEXT, asn TEXT, country_code TEXT)")

        insert_query = """INSERT INTO urlhaus 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?);"""

        for entry in urlhaus_c2_data:
            data = tuple(entry.values())
            cursor.execute(insert_query, data)

        print(f"total changes: {self.connection.total_changes}")
        self.connection.commit()
        cursor.close()

    def feodotracker_table(self, feodotracker_c2_data):
        cursor = self.connection.cursor()
        cursor.execute()
        insert_query = """INSERT INTO feodotracker 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?);"""
        
        for entry in feodotracker_c2_data:
            data = tuple(entry.values())
            cursor.execute(insert_query, data)

            print(f"total changes: {self.connection.total_changes}")
            self.connection.commit()
            cursor.close()