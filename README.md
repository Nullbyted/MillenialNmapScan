# MillenialNmapScan
<pre>
import nmap

# Create an instance of the nmap scanner
nm = nmap.PortScanner()

# Ask the user for the IP
ip = input("What's the IP, my guy? ")

#Stealth scan?
stealth = input("Are we going to be sneaky or nah? (yes/no) ")
if stealth == "yes":
    stealth_flag = "-sS"
else:
    stealth_flag = ""

#Common ports
scan_common = input("Soo.. just scan the common ports? (yes/no) ")
if scan_common == "yes":
    ports = "20,21,22,23,25,53,80,110,135,139,443,445,3389"
else:
    ports = input("Enter the ports or range of ports to scan: ")

#Scan
nm.scan(ip, ports, stealth_flag)

#Results
print("Alright bet! This is what I got:")
for host in nm.all_hosts():
    print("Host: {} ({})".format(host, nm[host].hostname()))
    for proto in nm[host].all_protocols():
        print("Protocol: {}".format(proto))
        lport = nm[host][proto].keys()
        lport = sorted(lport)
        for port in lport:
            print("port {}\tstate {}".format(port, nm[host][proto][port]["state"]))
            
</pre>
