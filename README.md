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
Fill in the ID Strings field with a single string containing MAC domain, and MachineGuid all together without any spaces

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
