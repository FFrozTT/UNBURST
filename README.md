# UNBURST

A SUNBURST Forensic tool that tells you if your own hosts match any of the supplied SUNBURST FQDN's.
In order to gather info from remote systems you will likely need to run as an administrator, with some domain privileges (like remote registry and wmic access).  You won't need full domain admin.
<br>If you only want to use the tool to manully calculate GUID then you don't need to run as admin. I included all the source code here so you can see it is safe to run.

### Automated checking
Step 1
Add all SUNBURST FQDN's to check against (e.g. [https://github.com/bambenek/research/blob/main/sunburst/uniq-hostnames.txt](https://github.com/bambenek/research/blob/main/sunburst/uniq-hostnames.txt))

Step 2
Fill in the remote host name and click "Get value from remote machine" button. 

### Manual checking
Step 1
Add all SUNBURST FQDN's to check against (e.g. [https://github.com/bambenek/research/blob/main/sunburst/uniq-hostnames.txt](https://github.com/bambenek/research/blob/main/sunburst/uniq-hostnames.txt))

Step 2
Fill in the ID Strings field with a single string containing the MAC, domain, and MachineGuid all together without any spaces

1. MAC address in all caps with no colons or hyphens
  - getmac /s \<remote ip\>
  <br>or
  - getmac /s
  <br>or
  - ipconfig /all
2. Domain name in all lower case e.g. domain.com
3. MachineGuid from registry
  - reg query \\\\\<remote ip\>\\HKLM\SOFTWARE\\Microsoft\\Cryptography\\
  or
  - reg query HKLM\\SOFTWARE\\Microsoft\\Cryptography\\

### Results
If a GUID match was discovered, it will be highlighted in the top section. If there was no match, you will see the GUID listed but that's it.

### Notes
1. There isn't any indicator that it's *working* at the moment so when you click the button, just wait. I haven't got around to doing the whole async button thing yet.
2. If you are doing manual GUID's, only do one ID at a time. If you are doing automatic, it will check all of the systems MAC addresses at once.
3. I haven't tested this against long domain names, I only have one domain name to validate this with.

### Credit
1. Erik Hjelmvik - https://securityboulevard.com/2020/12/reassembling-victim-domain-fragments-from-sunburst-dns/
2. Cado Security - https://github.com/cadosecurity/MalwareAnalysis/tree/3daecfaa9c8f3257a9da2ab13006b1ebb3a82329
