# illumio-threatcloud

Illumio Threatcloud aims to create Illumio Core objects for current
Ransomware events like REvil etc.

# How it works

* connects to OTX
* pull OTX pulses
* take IPs and FQDNs and create IPlists or unmanaged workloads
* label workloads accordingly


# Requirements

* a valid OTX account from otx.alienvault.com
* OTXv2
* workloader for importing the threatcloud workloads to the PCE (github.com/brian1917/workloader)
