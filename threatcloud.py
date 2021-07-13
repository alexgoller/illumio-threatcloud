import os
import time
import logging
import sys
import datetime
import csv
import argparse


from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

# example ipl-import
#  name | description | include | exclude | fqdns | external_data_set | external_data_ref |

# example wkld-import
# - hostname
# - name
# - role
# - app
# - env
# - loc
# - interfaces
# - public_ip
# - machine_authentication_id
# - description
# - os_id
# - os_detail
# - data_center
# - external_data_set
# - external_data_reference

header_domains = ['name', 'description', 'include', 'exclude', 'fqdns','external_data_set','external_data_ref']
header_workloads = ['hostname','name','role','app','env','loc','interfaces']


parser = argparse.ArgumentParser()
parser.add_argument('--otxkey', help='OTX API key', default=os.environ['OTX_API_KEY'])
parser.add_argument('--pulse', help='AlienVault OTX pulse id')
parser.add_argument('--workloads', help='Import file for workloads', default='wkld-import.csv')
parser.add_argument('--domains', help='Import file for domains/FQDNS', default='ipl-import.csv')
args = parser.parse_args()

if 'pulse' not in args:
    logging.warn("No config file given. Quitting")
    exit()


def main():
    # OTX_API_KEY = os.environ['OTX_API_KEY']
    otx = OTXv2(args.otxkey)

    # pulse_id = "60e2c5a2286d4d5303af0f81"
    pulse_id = args.pulse
    indicators = otx.get_pulse_indicators(pulse_id)
    ips = []
    domains = []

    for indicator in indicators:
        if indicator['type'] == "IPv4":
            ips.append(indicator["indicator"])
        if indicator['type'] == "domain":
            domains.append(indicator["indicator"])

    with open(args.workloads, 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header_workloads)
        for ip in ips:
            umwl_row = ['threatcloud-' + str(ip), '', 'C2', pulse_id, 'OTX', 'Threatcloud', 'eth0:' + str(ip)]
            writer.writerow(umwl_row)

    # usually only one IPL for each pulse_id
    domain = ";".join(domains)
    ipl_row = ['Threatcloud'+'-'+pulse_id, '', '', '', domain, pulse_id, 'illumio-threatcloud']

    with open(args.domains, 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header_domains)
        writer.writerow(ipl_row)


if __name__ == "__main__":
    main()
