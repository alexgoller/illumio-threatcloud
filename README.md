# illumio-threatcloud

Illumio Threatcloud aims to create Illumio Core objects for current
Ransomware events like REvil etc.

# How it works

* connects to OTX
* pull OTX pulses
* take IPs and FQDNs and create IPlists or unmanaged workloads
* label workloads accordingly

# Use cases

## Retrospectively check if a current threat was identified using IP and FQDN IOCs.

## Proactively block access to IOCs

## Block unauthorized access to IOCs using enforcement boundaries

# Running threatcloud

Be sure to put your OTX key into a environment variable called OTX_API_KEY or submit via command line
flag (insecure).
The script will refuse to work if you do not submit a pulse id, e.g.

    usage: threatcloud.py [-h] [--otxkey OTXKEY] [--pulse PULSE] [--workloads WORKLOADS] [--domains DOMAINS]

    optional arguments:
      -h, --help            show this help message and exit
      --otxkey OTXKEY       OTX API key
      --pulse PULSE         AlienVault OTX pulse id
      --workloads WORKLOADS Import file for workloads
      --domains DOMAINS     Import file for domains/FQDNS

Run the script searching for pulse 60e2c5a2286d4d5303af0f81 (Kaseya/REvil)

    threatcloud.py --pulse 60e2c5a2286d4d5303af0f81

This will create two files wkld-import.csv and ipl-import.csv.
Next import both via workloader:

    workloader wkld-import wkld-import --update-pce --umwl --no-prompt
    workloader ipl-import ipl-import --update-pce --no-prompt

You should be able to see the imported IOCs in your PCE as unmanaged workloads
with a default environment label of 'OTX' and a location label called 'Threatcloud'.
The application name will be the pulse id of the pulse pulled.

An iplist will be created called Threatcloud-pulse-id.

# Requirements

* a valid OTX account from otx.alienvault.com
* OTXv2
* workloader for importing the threatcloud workloads to the PCE (github.com/brian1917/workloader)
