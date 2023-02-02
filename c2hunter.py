import os
import sys
import time
import shutil
from datetime import datetime
import logging
import argparse
import yaml

from src.hunter import Hunter
from src.database import DatabaseHandler

# Based on the 'C2 Tracker' project
# - https://github.com/montysecurity/C2-Tracker

# References
# - https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f
# - https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2
# - https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md
# - https://blog.bushidotoken.net/2022/11/detecting-and-fingerprinting.html


def banner():
    print("[   C2|Hunter   ]")


def arg_formatter():
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)
    return formatter


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(
    ), description='DESCRIPTION')

    parser.add_argument(
        '-q', '--quiet', help="do not print a banner", action='store_true')
    parser.add_argument('-c', '--config', metavar='FILE', default="config/config.yml",
                        help='config file (default: "config/config.yml")')
    parser.add_argument('--disable-shodan',
                        help="disable querying Shodan", action='store_true')
    parser.add_argument('--disable-feodotracker',
                        help="disable querying Feodo Tracker", action='store_true')
    parser.add_argument('--disable-urlhaus',
                        help="disable querying URLhaus", action='store_true')
    parser.add_argument('-o', '--output', metavar="DIRECTORY", default="reports",
                        help='output directory (default: "reports/")')

    # return parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    return parser.parse_args()


def is_valid_file(filename, filetype):
    if not os.path.exists(filename):
        return False
    else:
        if filetype == "yml":
            if not filename.endswith(".yml") or filename.endswith(".yaml"):
                return False
    return True


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{logging_path}' directory for storing log files")
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/{(os.path.splitext(__file__)[0]).split('/')[-1]}.log", level=logging.DEBUG)
    logger = logging.getLogger('__name__')


def load_config(filename):
    with open(filename, "r") as ymlfile:
        config = yaml.safe_load(ymlfile)
    return config


def directory_structure(output_dir):
    # custom report directory
    if not output_dir == "reports":
        report_dir = f"{output_dir}/reports"
        backups_dir = f"{output_dir}/backups"
    # default report directory
    else:
        report_dir = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/reports"
        backups_dir = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/backups"

    ips_dir = f"{report_dir}/ips"
    json_dir = f"{report_dir}/json"
    csv_dir = f"{report_dir}/csv"
    raw_dir = f"{report_dir}/raw"
    iocs_dir = f"{report_dir}/iocs"
    db_dir = f"db"

    # output directory does not exist
    if not os.path.isdir(report_dir):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{report_dir}' directory structure for storing reports")
        logging.info(
            f"Creating '{report_dir}' directory structure for storing reports")
        os.mkdir(report_dir)
        os.mkdir(ips_dir)
        os.mkdir(json_dir)
        os.mkdir(csv_dir)
        os.mkdir(raw_dir)
        os.mkdir(iocs_dir)
        os.mkidir(db_dir)
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{backups_dir}' directory for storing reports backups")
        logging.info(
            f"Creating '{backups_dir}' directory for storing reports backups")
        os.mkdir(backups_dir)

    # output directory exists but check for the subdirectory structure
    else:
        if not os.path.isdir(backups_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating missing '{backups_dir}' directory for storing reports backups")
            logging.info(
                f"Creating missing '{backups_dir}' directory for storing reports backups")
            os.mkdir(backups_dir)

        if not os.path.isdir(ips_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating missing '{ips_dir}' directory for storing IP lists")
            logging.info(
                f"Creating missing '{ips_dir}' directory for storing IP lists")
            os.mkdir(ips_dir)

        if not os.path.isdir(json_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating missing '{json_dir}' directory for storing JSON reports")
            logging.info(
                f"Creating missing '{json_dir}' directory for storing JSON reports")
            os.mkdir(json_dir)

        if not os.path.isdir(csv_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating missing '{csv_dir}' directory for storing CSV reports")
            logging.info(
                f"Creating missing '{csv_dir}' directory for storing CSV reports")
            os.mkdir(csv_dir)

        if not os.path.isdir(raw_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating missing '{json_dir}' directory for storing RAW reports")
            logging.info(
                f"Creating missing '{json_dir}' directory for storing RAW reports")
            os.mkdir(raw_dir)

        if not os.path.isdir(iocs_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating missing directory '{iocs_dir}' for storing IOCs")
            logging.info(f"Creating directory '{iocs_dir}' for storing IOCs'")
            os.mkdir(iocs_dir)

        if not os.path.isdir(db_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating missing directory '{db_dir}' for storing database files")
            logging.info(f"Creating directory '{db_dir}' for storing database file'")
            os.mkdir(db_dir)

    return report_dir, backups_dir, db_dir


def backup_recent_reports(report_dir, backups_dir):
    new_backup_dir = f"{backups_dir}/{datetime.today().strftime('%Y-%m-%d')}"
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{new_backup_dir}' directory to store the most recent reports ...")
    logging.info(
        f"Creating '{new_backup_dir}' directory to store the most recent reports")
    if os.path.exists(new_backup_dir):
        shutil.rmtree(new_backup_dir)
    os.mkdir(new_backup_dir)

    source_dir = report_dir
    target_dir = new_backup_dir
    dir_names = os.listdir(report_dir)  # TODO : REWORK

    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Moving files from '{report_dir}' directory to '{new_backup_dir}' directory ...")
    logging.info(
        f"Copying files from '{report_dir}' directory to '{new_backup_dir}' directory")
    for dir_name in dir_names:
        file_names = os.listdir(os.path.join(source_dir, dir_name))
        target_subdir = os.path.join(target_dir, dir_name)
        os.mkdir(target_subdir)

        for file_name in file_names:
            source_file = f"{os.path.join(source_dir, dir_name)}/{file_name}"
            shutil.copy(source_file, target_subdir)


def main():
    if not sys.platform.startswith('linux'):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Unsupported platform")
        print("\nExiting program ...\n")
        exit(1)

    os.system("clear")
    init_logger()

    args = parse_args()

    if not args.quiet:
        banner()

    print('-' * os.get_terminal_size().columns)

    config_path = args.config
    if is_valid_file(config_path, "yml"):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading config '{config_path}' ...")
        logging.info(f"Loading config '{config_path}'")
        config = load_config(config_path)
    else:
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided config file '{config_path}' does not exist or it is not a yaml file")
        logging.error(
            f"Provided config file '{config_path}' does not exist or it is not a yaml file")
        print("\nExiting program ...\n")
        sys.exit(1)

    output_dir = args.output
    report_dir, backups_dir, db_dir = directory_structure(output_dir)

    print('-' * os.get_terminal_size().columns)

    c2hunter = Hunter(config, report_dir)
    database_handler = DatabaseHandler(config, db_dir)

    if not args.disable_shodan:
        c2hunter.query_shodan()
        print('-' * os.get_terminal_size().columns)

    if not args.disable_feodotracker:
        feodotracker_c2_data = c2hunter.query_feodotracker()
        c2hunter.search_country_code_in_feodotracker(feodotracker_c2_data)
        print('-' * os.get_terminal_size().columns)

    if not args.disable_urlhaus:
        urlhaus_c2_data = c2hunter.query_urlhaus()
        c2hunter.search_active_C2_from_urlhaus(urlhaus_c2_data)
        database_handler.urlhaus_db(urlhaus_c2_data)
        print('-' * os.get_terminal_size().columns)

    # TODO : store backups in DB
    backup_recent_reports(report_dir, backups_dir)
    print('-' * os.get_terminal_size().columns)

    # timestamp_output_path = f"{output_dir}/timestamp"
    # with open(timestamp_output_path, "w") as timestamp_file:
    #     timestamp_file.write(f"{datetime.today().strftime('%Y-%m-%d')}")


if __name__ == '__main__':
    main()
