# VirusTotal Hash Analyzer
A Python script that gets score, name, extension and distributors of a file hashes list.<br>

## _Requirements_
You need to create your VirusTotal API_KEY (Dude, don't tremble, it's free).<br>
Go to [VirusTotal](https://developers.virustotal.com/) > Signin > Click on your account avatar > API key<br>
* Free API_KEY limit: 500 requests per day and a rate of 4 requests per minute.<br>
If you need to make a lot of requests you can think about buying a paid plan (Account > API key > Request premium API key)<br><br>

Install the following python libraries:
 - `pip install requests`

## _Usage steps_
 - You have to create a simple .txt file that contains the list of file hashes (1 item for each line)
 - Run `virustotal_hash_analyzer.py`
 - Enter the path of the .txt file containing the hashes list
 - Enter the minimum percentage of positive scans (DEFAULT = ALL)
 - Enter your VirusTotal API_KEY (or write it into first line of your_key.txt file)
 - Enter "yes" if is a Premium API key, else "false" (or write it into second line of your_key.txt file)
 - The script will create (or write) the result to VirusTotal_result.txt file within the path from which the script was launched

## _Tips_
- If you don't have a Premium API key, the script will delay the execution of the requests to VirusTotal, so as not to happen the foreseen limits<br>
- While generating the results, the script is able to append data into an existing file by adding a Timestamp so that you can distinguish the various searches.<br><br>
