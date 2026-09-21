HI. 
MY PROGREMME IS CREATED BY MY FOR ONLY EDUCATIONAL AND KINDA FUN PURPOSE. THANKS FOR READING<3
USE ONLY YOUR INTERNET PLZ


REQUIREMENTS:
python 3
scapy - 2.5.0 
pandas - 2.0.0 (f u want)
numpy - 1.24.0 
scikit-learn - 1.3.0

On Linux, `libpcap` is required (it is usually already present). On macOS, use `brew install libpcap`. On Windows, use Npcap (https://npcap.com/). 

SO, LETS START.


	1) DOWNLOAD PYTHON 3, NCAP. ALSO DOWNLOAD ALL MY PROJECT FILES AND PUT THEM TO THE ONE FOLDER.( 4 EXAMPLE -  C:\SCANNER\ ).

	2) OPEN POWERSHELL IN THIS FOLDER (SHIFT + RIGHT-CLICK IN FILE EXPLORER → 'OPEN POWERSHELL WINDOW HERE'), THEN RUN: python -m venv venv, FOLLOWED BY venv\Scripts\Activate.ps1 (IF THERE IS AN ERROR REGARDING SCRIPT EXECUTION 	POLICY, RUN THIS ONCE: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass , AND FINALLY pip install -r requirements.txt .

	3) CLOSE AND RUN POWERSHELL AS AN ADMINISTRATOR. Find PowerShell in the Start menu, right-click it → 'Run as administrator', navigate back to the project folder `cd C:\netsentry` , and reactivate the venv `venv\Scripts	\Activate.ps1` .

	4) Run `ls` and make sure you see `main.py` and the other files.

	5) Set dependencies. Run `pip install -r requirements.txt`- make sure you do this in the specific window showing `(venv)` in the prompt and that the window is running as an administrator.

	6) Find out your subnet and interface name. Run " ipconfig " and locate the 'IPv4 Address' line (e.g., 146.111.1.11) and the subnet mask.

	7) Start the scan. " python main.py scan --network 146.111.1.11 --output scan_results.json " - replace the subnet with the one 	from the previous step. If Scapy does not detect the interface automatically, a reboot may be 	required after installing Npcap.

	8) YOU WILL SEE COUNT OF THE DEVICES AND THEIR IPs.

	9) Get the list of interfaces. Run `python -c "from scapy.all import show_interfaces; show_interfaces()"` - this will display a table of all network interfaces that Scapy detects via Npcap.
 
	10) Find the row in the table where the IP column shows (E.G) 146.111.1.11 (this is your 'Ethernet 4' adapter from ipconfig). Copy the value from the Name or Description column for that row—this is the value you need to pass 		to --iface.

	11) RUN python -c "from scapy.arch.windows import get_windows_if_list; [print(repr(i['name'])) for i in get_windows_if_list() if i['ips'] and '192.168.1.12' in i['ips']]" AND SEE THE NAME OF YOUR ADAPTER. (E.G. Ethernet 4).

	12) Launch the capture. python main.py capture --iface "Ethernet 4" --duration 30 --pcap-out capture.pcap --csv-out capture.csv  instead of Ethernet 4, use the name from the previous step. Quotation marks around the name are 	required. WAIT FOR 30 SEC (YOU CAN CHANGE DURATION CHANGING THE PARAMETER  --duration 40\50\60... ).

	13) Now we run the anomaly analysis. python main.py analyze --csv capture.csv --output report.json  NOW YOU SEE ALL ANOMALIES. if you don't understand, you can paste this result to AI and he will help you to understand :)

	14) Check who these IPs are: python main.py analyze --csv capture2.csv --output report2.json

	15) Who has connected recently. python main.py scan --network  (E.G) 146.111.1.11 --db netsentry.db  View accumulated history:  python main.py history --db netsentry.db 

	16) Who appeared for the first time in the last 24 hours. python main.py history --db netsentry.db --new-since-hours 24

	17) Find out the DEVICE TYPE: install a new dependency.  pip install manuf

	18) Run the scan again: python main.py scan --network 192.168.1.0/24 --db netsentry.db






														THANKS FOR YOUR DOWNLOAD, PAL <3
