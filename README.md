# sophos-api-tamper-protection
Sophos Central Tamper Protection utility for mass changes

Use this python script to check the status of Tamper Protection across all of your devices known within your
Sophos Central envrionment.

NOTE:   You must enable Sophos Tamper Protection within the global settings of Central.
        If you do not do this, this script will not yield any effect.
        
Usage:

Discover and Enable Tamper Protection on all devices:

 #> python3 tamper_protect.py

Things to come:
- Differentiate between SERVERS and WORKSTATION class sytsems.
- Status indicator for large jobs
- Multi estate support; partner dashboard and enterprise dashboard

Open license, no restrictions and not officially supported by Sophos.

Thanks for reading.