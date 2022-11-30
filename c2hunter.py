import os
import sys
import time
import logging
import argparse
import yaml

from src.hunter import Hunter 

# Based on the 'C2 Tracker' project
# - https://github.com/montysecurity/C2-Tracker

# References
# - https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f
# - https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2
# - https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md
# - https://blog.bushidotoken.net/2022/11/detecting-and-fingerprinting.html

def banner():
    print(r"""
    """)


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

    parser.add_argument('-o', '--output', metavar="DIRECTORY", default="reports",
                        help="output directory (default: 'reports/')")

    # return parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    return parser.parse_args()


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


def check_report_directory(output_dir):
    report_dir = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/reports"
    json_dir = f"{report_dir}/json"
    csv_dir = f"{report_dir}/csv"

    if output_dir == "reports":
        report_dir = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/reports"
    else:
        report_dir = output_dir

    if not os.path.isdir(report_dir):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{report_dir}' directory for storing reports")
        logging.info(f"Creating '{report_dir}' directory for storing reports")
        os.mkdir(report_dir)
        os.mkdir(json_dir)
        os.mkdir(csv_dir)


# save raw response

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

    config = load_config(args.config)

    output_dir = args.output
    check_report_directory(output_dir)

    c2hunter = Hunter(config, output_dir)
    c2hunter.shodan_query()


if __name__ == '__main__':
    main()
