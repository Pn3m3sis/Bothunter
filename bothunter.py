from scapy.all import PcapReader, TCP, UDP, IP, Raw
import json
import os
import sys
import re
from collections import defaultdict
from multiprocessing import Pool, cpu_count

def sanitize_output(content):
    """Removes malformed bytes and non-printable characters while preserving hex values."""
    try:
        cleaned = content.decode('utf-8', errors='ignore')
        cleaned = cleaned.replace('\x00', '')  # Remove null bytes
        cleaned = re.sub(r'[^\x20-\x7E\n\r]', ' ', cleaned)  # Replace non-printable characters
        return cleaned
    except:
        return ""

def search_stream(stream, regex_patterns):
    """Searches for regex patterns in a TCP/UDP stream using regex, collecting multiple findings."""
    try:
        stream_content_lower = stream.lower()
    except:
        return False, b"", []
    
    matched_metadata = []
    for pattern, metadata in regex_patterns:
        if re.search(pattern, stream_content_lower):  
            matched_metadata.append(metadata)
    
    return bool(matched_metadata), stream, matched_metadata

def parse_http_payload(payload):
    """Extracts basic HTTP details if the payload contains HTTP traffic."""
    try:
        lines = payload.decode('utf-8', errors='ignore').split("\n")
        first_line = lines[0].strip()
        if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\\s", first_line):
            headers = {}
            for line in lines[1:]:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    headers[parts[0].strip()] = parts[1].strip()
            return {
                "method": first_line.split()[0],
                "url": first_line.split()[1] if len(first_line.split()) > 1 else "",
                "host": headers.get("Host", ""),
                "user_agent": headers.get("User-Agent", ""),
                "full_headers": headers
            }
    except:
        return None
    return None

def process_session(args):
    """Worker function to process a single TCP/UDP session."""
    session_key, payloads, regex_patterns, port_specific_patterns, protocol = args
    reassembled_stream = b''.join(payloads)  

    if len(reassembled_stream) < 20:
        return None  

    sanitized_content = sanitize_output(reassembled_stream)
    src_ip, src_port, dest_port = session_key
    matched_metadata = []

    if dest_port in port_specific_patterns:
        active_patterns = port_specific_patterns[dest_port]
    else:
        active_patterns = regex_patterns

    found_raw, content_raw, metadata_raw = search_stream(reassembled_stream, active_patterns)
    found_clean, content_clean, metadata_clean = search_stream(sanitized_content.encode('utf-8'), active_patterns)
    
    matched_metadata.extend(metadata_raw + metadata_clean)

    if matched_metadata:
        attack_vectors = list(set(m.get("Tag") for m in matched_metadata if "Tag" in m))
        cve_list = list(set(m.get("CVE") for m in matched_metadata if "CVE" in m))
        botnets = list(set(m.get("Botnet") for m in matched_metadata if "Botnet" in m))

        result = {
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_port": dest_port,
            "Content": sanitized_content.splitlines() if found_clean else "RAW_MATCH_FOUND"
        }

        if attack_vectors:
            result["Tag"] = attack_vectors
        if cve_list:
            result["CVE"] = cve_list
        if botnets:
            result["Botnet"] = botnets

        if protocol == "TCP":
            http_info = parse_http_payload(reassembled_stream)
            if http_info:
                result["HTTP_Details"] = http_info

        return result

    return None

def analyze_pcap(pcap_file, regex_patterns):
    """Analyzes a pcap file using multi-core parallel processing for TCP and UDP."""
    tcp_sessions = defaultdict(list)  
    udp_sessions = defaultdict(list)  

    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                session_key = (pkt[IP].src, pkt[TCP].sport, pkt[TCP].dport)  # TCP
                tcp_sessions[session_key].append(pkt[Raw].load)

            elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
                session_key = (pkt[IP].src, pkt[UDP].sport, pkt[UDP].dport)  # UDP
                udp_sessions[session_key].append(pkt[Raw].load)

    cpu_cores = max(cpu_count() - 1, 1)
    print(f"Using {cpu_cores} CPU cores...")

    with Pool(cpu_cores) as pool:
        tcp_results = pool.map(process_session, [(k, v, regex_patterns, port_specific_patterns, "TCP") for k, v in tcp_sessions.items()])
        udp_results = pool.map(process_session, [(k, v, regex_patterns, port_specific_patterns, "UDP") for k, v in udp_sessions.items()])

    tcp_results = [r for r in tcp_results if r is not None]
    udp_results = [r for r in udp_results if r is not None]

    output_file = f"{os.path.splitext(os.path.basename(pcap_file))[0]}_bot_traffic.json"
    results = {
        "TCP": tcp_results,
        "UDP": udp_results
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 bothunter.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    regex_patterns = [
        # ELF dropper
        (rb"\\x45\\x4c\\x46", {"Tag": "ELF Dropper"}),

        # NIGGER
        (rb"/bin/busybox nigger|dvrlocker", {"Botnet": "Nigger"}),
	    # IZ1H9
	    (rb"/bin/busybox iz1h9", {"Botnet": "IZ1H9"}),
	    # APEP
	    (rb"/bin/busybox apep|guccix86", {"Botnet": "Apep"}),
        # KURC
        (rb"/bin/busybox kurc", {"Botnet": "Kurc"}),
        # UNSTABLE
        (rb"/bin/busybox unstable|/bin/busybox elbatsnu|\\x6d\\x61\\x67\\x69\\x63\\x69\\x61\\x6e", {"Botnet": "Unstable"}),
        # HOHO
        (rb"/bin/busybox hoho|hoho\.x86", {"Botnet": "Dark Nexus"}),
        # AISURU
        (rb"/bin/busybox aisuru", {"Botnet": "Aisuru"}),
        # ARES
        (rb"bin/busybox haxx|bin/busybox ares|flow\.x86|nigga\.x86|\\x41\\x72\\x65\\x73\\x2e\\x78\\x38\\x36", {"Botnet": "Ares"}),
        # TBOT
        (rb"/bin/busybox tbot|/bin/busybox tbotnet|\\x73\\x68\\x65\\x6c\\x6c\\x78\\x38\\x36|shellx86", {"Botnet": "Tbot"}),
        # IDDOSYOU
        (rb"iddosyou|andsm0kedoinks|josho\.x86", {"Botnet": "IDdosYou"}),
        # LOUD
        (rb"/bin/busybox loud|0xh0roxxnavebusyoo\.x86|/bin/busybox vga|\\x30\\x78\\x68\\x30\\x72\\x6f\\x78\\x78\\x6e\\x61\\x76\\x65\\x62\\x75\\x73\\x79\\x6f\\x6f\\x2e\\x78\\x38\\x36", {"Botnet": "Loud"}),
        # GAFGYT
        (rb"atlas\.(x86|arm|arm5|arm6|arm7|mips|mipsel|ppc|sh4|sparc)|/v1\.24/containers/create|ftpget\s+-v\s+-p\s+21\s+\d{1,3}(?:\.\d{1,3}){3}\s+telnetd|/bin/busybox botnet", {"Botnet": "Gafgyt"}),
        # HAJIME
        (rb"/bin/busybox ecchi|ihcce", {"Botnet": "Hajime"}),
        # MOZI
        (rb"(?:http://\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}/i|\\x59\\x59\\x46\\x4d\\x47\\x47|\\x41\\x54\\x55\\x31\\xed\\x53\\x48|\\x4d\\x6f\\x7a\\x69|mozi(?!lla|la)[\w.-]*|\\x53\\x4f\\x55\\x49\\x56\\x59)", {"Botnet": "Mozi"}),
        # MANGA
        (rb"http://\d{1,3}(?:\.\d{1,3}){3}/bins/dark\.(mpsl|arm5|arm6|arm7|x86|ppc|mips)|/bin/busybox dark", {"Botnet": "Manga"}),
        # SYLVEON
        (rb"/bin/busybox sylveon", {"Botnet": "Sylveon"}),
        # PEDO
        (rb"/bin/busybox pedo|\\x70\\x65\\x64\\x6f|/pedalcheta/cutie\.x86", {"Botnet": "PedoBot"}),
        # NIGGABOX
        (rb"(?:niggabox|\\x6e\\x69\\x67\\x67\\x61\\x62\\x6f\\x78)", {"Botnet": "Niggabox"}),
        # HAKKA
        (rb"(?:hakka|\\x68\\x61\\x6b\\x6b\\x61)", {"Botnet": "Hakka"}),
        # Switchblades Botnet
        (rb"(?:sbidiot|switchblades|\\x53\\x42\\x49\\x44\\x49\\x4f\\x54|skid\.x86)", {"Botnet": "Switchblades"}),
        # MIRAI
        (rb"(?:mirai|jklx86|\\x6a\\x6b\\x6c\\x78\\x38\\x36|\\x6d\\x69\\x72\\x61\\x69|/bin/busybox BOT)", {"Botnet": "Mirai"}),
        # SORA
        (rb"(?<!super)visoradmin|(?:[^a-zA-Z0-9]|^)sora(?:\.(?:x86|sh))?(?:[^a-zA-Z0-9]|$)|\\x73\\x6f\\x72\\x61|ak1k2|owari|fomni|wicked", {"Botnet": "Sora"}),
        # MIORI
        (rb"(?:miori|\\x6d\\x69\\x6f\\x72\\x69|\\x6d\\x69\\x6f\\x72\\x69\\x63\\x68)", {"Botnet": "Miori"}),
        # SATORI
        (rb"(?:satori|\\x61\\x74\\x6f\\x72\\x69)", {"Botnet": "Satori"}),
        # CONDI
        (rb"\bcondi\b|condixx|\\x38\\x31\\x38\\x32\\x54|\\x68\\x69\\x33\\x35\\x31\\x31|\\x63\\x6f\\x6e\\x64\\x69", {"Botnet": "Condi"}),
        # AndroxGh0st
        (rb"androxgh0st", {"Botnet": "AndroxGh0st"}),
        # TSUNAMI/KAITEN
        (rb"(?:tsunami|kaiten|\\x73\\x75\\x6e\\x61\\x6d\\x69|\\x61\\x69\\x74\\x65\\x6e)", {"Botnet": "Tsunami/Kaiten"}),

        # IoT Malware Download via wget, curl, tftp
        (rb"(wget|curl|ftpget|tftp)\s+(-O\s+)?http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?/[\w./-]+", {"Tag": "IoT Malware Download"}),

        # IoT botnet binary pattern
        (rb"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?/[\w./-]+\.(mips|mipsel|mpsl|arm|sh|x86)", {"Tag": "Binary Download"}),

        # CVE Exploits for IoT Devices
        (rb"/ctrlt/deviceupgrade_1", {"Tag": "Huawei Router Exploit", "CVE": "CVE-2017-17215"}),
        (rb"/solr/admin/info/system\?wt=json", {"Tag": "Log4Shell Exploit", "CVE": "CVE-2021-44228", "Botnet": "Kinsing"}),
        (rb"/actuator/gateway/routes", {"Tag": "Spring Cloud Gateway RCE", "CVE": "CVE-2022-22947"}),
        (rb"/gponform/diag_form\?style", {"Tag": "GPON Vulnerability", "CVE": "CVE-2018-10561"}),
        (rb"/gponform/diag_form\?images", {"Tag": "GPON Vulnerability", "CVE": "CVE-2018-10562"}),
        (rb"/hnap1/", {"Tag": "HNAP Exploit", "CVE": "CVE-2015-2051"}),
        (rb"/boaform/admin/formping", {"Tag": "Netlink Router Exploit", "CVE": "CVE-2020-8958"}),
        (rb"/boaform/admin/formlogin", {"Tag": "Totolink TOTOLINK A3002RU Router", "CVE": "CVE-2020-25499"}),
        (rb"/cgi-bin/viewLog\.asp", {"Tag": "Zyxel Exploit", "CVE": "CVE-2017-18368"}),
        (rb"/set_ftp\.cgi\?loginuse", {"Tag": "GOahead Exploit", "CVE": "CVE-2017-18377"}),
        (rb"/ping\.cgi\?pingipaddress", {"Tag": "Comtrend RCE", "CVE": "CVE-2020-10173"}),
        (rb"/sdk/weblanguage", {"Tag": "Hikvision Exploit", "CVE": "CVE-2021-36260"}),
        (rb"flash/rw/store/user.dat", {"Tag": "MikroTik Router Credential Theft", "CVE": "CVE-2018-14847"}),
        (rb"/shell\?cd\+/tmp;rm\+-rf\+\*", {"Tag": "Jaws Web Server RCE", "CVE": "CVE-2016-20016"}),
        (rb"/goform/formsyscmd", {"Tag": "Realtek SDK RCE", "CVE": "CVE-2018-20057"}),
        (rb"/goform/formwsc", {"Tag": "Realtek SDK RCE", "CVE": "CVE-2021-35395"}),
        (rb"/pages/createpage-entervariables\.action", {"Tag": "Confluence OGNL Injection RCE", "CVE": "CVE-2021-26084"}),
        (rb"/backupmgt/localjob\.php", {"Tag": "Seagate NAS RCE", "CVE": "CVE-2014-3206"}),
        (rb"/cgi-bin/\.\%", {"Tag": "Apache HTTP Server Path Traversal RCE", "CVE": "CVE-2021-41773"}),
        (rb"/linuxki/experimental", {"Tag": "HP LinuxKI Toolset RCE", "CVE": "CVE-2020-7209"}),
        (rb"/cgi-bin/admin\.cgi", {"Tag": "Korenix JetWave Router RCE", "CVE": "CVE-2021-46422"}),
        (rb"/cgi-bin/cstecgi\.cgi", {"Tag": "DrayTek Vigor Router RCE", "CVE": "CVE-2022-26186"}),
        (rb"/cgi-bin/admin\.cgi\?command=syscommand&cmd", {"Tag": "Korenix JetWave Router RCE", "CVE": "CVE-2021-46422"}),
        (rb"/ubus/", {"Tag": "OpenWRT UBUS Remote Code Execution", "CVE": "CVE-2022-29013"}),
        (rb"/login/login\.html", {"Tag": "ThinkPHP Authentication Bypass", "CVE": "CVE-2021-4039"}),
        (rb"/cgi-bin/system_log\.cgi", {"Tag": "Embedded System Log Injection", "CVE": "CVE-2020-17456"}),
        (rb"/chkisg\.htm", {"Tag": "D-Link Router Authentication Bypass", "CVE": "CVE-2018-10823"}),
        (rb"/cgi-bin/mainfunction\.cgi", {"Tag": "DrayTek Vigor Remote Code Execution", "CVE": "CVE-2020-8515"}),
        (rb"/vendor/phpunit/phpunit/src/util/php/eval-stdin\.php", {"Tag": "PHPUnit Remote Code Execution", "CVE": "CVE-2017-9841"}),
        (rb"(?i)/(\.env(\.\w+)?|config\.json|phpinfo\.php|_profiler/phpinfo|\?phpinfo=1|frontend_dev\.php|debug/default/view\?panel=config)", {"Tag": "Path Traversal RCE", "CVE": "CVE-2021-41773"}),
        (rb"d33pblu3", {"Tag": "Possible RCE User Enumeration"}),
        (rb"\.git/config", {"Tag": "Possible RCE", "CVE": "CVE-2024-32002"}),
        (rb"/securityrealm/user/admin/search/index", {"CVE": "CVE-2024-23897", "Tag": "Jenkins 2.441"}),
        (rb"/ud/act\?1", {"Tag": "ZyXEL D1000 Modem RCE", "CVE": "CVE-2016-10372"}),
        (rb"(?i)/picsdesc\.xml|/ud/\?9|/wanipcn\.xml", {"Tag": "Realtek SDK UPnP RCE", "CVE": "CVE-2014-8361"}),
        (rb"/cgi-bin/;\s*cd\${ifs}", {"Tag": "Netgear NMS RCE", "CVE": "CVE-2016-6277"}),
        (rb"ping.cgi", {"Tag": "D-Link DIR820LA1_FW105B03 RCE", "CVE": "CVE-2023-25280"}),
        
        # ZTE ZXV10 H108L Router Vulnerabilities
        (rb"/login\.gch", {"Tag": "ZTE ZXV10 H108L Router Vulnerability"}),
        (rb"frm_logintoken", {"Tag": "ZTE ZXV10 H108L Authentication Bypass"}),
        (rb"/manager_dev_ping_t\.gch", {"Tag": "ZTE ZXV10 H108L Remote Command Execution"}),
        (rb"/getpage\.gch\?pid=1001", {"Tag": "ZTE ZXV10 H108L Configuration Exposure"}),

        # Additional detections for SSH Botnets & IoT C2 Communication
        (rb"random1random2random3random4", {"Tag": "Encrypted C2 Traffic"}),
        (rb"nice%20ports%2c/tri%6eity\.txt%2ebak", {"Botnet": "Medusa"}),

        # Android IoT Exploits
        (rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:5555\s+shell", {"Tag": "Android Debug Bridge Exploit"}),

        (rb"<\?xml\s+version=.*?\?>|<soap:envelope\s+xmlns:soap=", {"Tag": "Suspicious XML/SOAP Activity"}),
        
        # IoT Protocols
        (rb"(mqttclient|mqtt)", {"Tag": "MQTT IoT Protocol"}),
        (rb"\(description=\(connect_data=\(cid=\(program", {"Tag": "Encrypted C2 Communication"}),
        (rb"lzrora", {"Tag": "LoRa IoT"}),
        (rb"(opc\.tcp://|\(connect_data=\(command=version\)\))", {"Tag": "Encrypted Binary Download"}),

        # UDP
        (rb"cd\s+/tmp;\s*rm\s+-rf\s+\S+;\s*/bin/busybox\s+wget\s+http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\S+;\s*chmod\s+\S+\s+\S+;\s*\./\S+(?:\s+\S+)?;", {"Tag": "IoT Exploit", "CVE": "CVE-2021-35394"}),
        (rb"cd\s+/tmp.*?cd\s+/var/run.*?cd\s+/mnt.*?cd\s+/root.*?"
         rb"wget\s+http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/[a-zA-Z0-9_-]+\.sh.*?"
         rb"chmod\s+777.*?curl.*?tftp", {"Tag": "IoT Exploit", "CVE": "CVE-2021-35394"}),
        (rb"http://schemas\.xmlsoap\.org/ws/2005/04/discovery/probe", {"Tag": "WS-Discovery possible reflection/amplification attack"})
]

    port_specific_patterns = {
        23: [  # Rules only for port 23 (Telnet)
            (rb"(root|admin|default|guest|support|superadmin|service|supervisor|telnet|administrator|telnetadmin|user|12345|8ehome|huawei|cisco|vizxv|hi3518|xmhdipc|aquario|tech)[\s\S]*?(root|admin|default|guest|support|superadmin|service|supervisor|telnet|administrator|telnetadmin|user|12345|8ehome|huawei|cisco|vizxv|hi3518|xmhdipc|aquario|tech)", {"Tag": "Telnet Brute-force"}),
            (rb"(enable|system|shell|linuxshell|start|config\s+terminal|/bin/busybox|chmod\s+777|selfrep)[\s\S]*?(enable|system|shell|linuxshell|start|config\s+terminal|/bin/busybox|chmod\s+777|selfrep)", {"Tag": "Telnet Post-Login Command Execution"}),
            (rb"(xc3511|vizxv|888888|xmhdipc|jauntech|smcadmin|klv123|666666|klv1234|Zte521|hi3518|jvbzd|anko|zlxx\.|7ujMko0vizxv|7ujMko0admin|ikwb|dreambox|realtek|000000|1111111|54321|meinsm|mother|fucker)[\s\S]*?(xc3511|vizxv|888888|xmhdipc|jauntech|smcadmin|klv123|666666|klv1234|Zte521|hi3518|jvbzd|anko|zlxx\.|7ujMko0vizxv|7ujMko0admin|ikwb|dreambox|realtek|000000|1111111|54321|meinsm|mother|fucker)", {"Botnet": "Mirai-variant"}),

            # ELF dropper
            (rb"\\x45\\x4c\\x46", {"Tag": "ELF Dropper"}),
            # SHELL dropper
            (rb"\\x23\\x21\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68", {"Tag": "Shell script Dropper"}),

            (rb"/bin/busybox nigger|dvrlocker", {"Botnet": "Nigger"}),
            # IZ1H9
            (rb"/bin/busybox iz1h9", {"Botnet": "IZ1H9"}),
            # APEP
            (rb"/bin/busybox apep|guccix86", {"Botnet": "Apep"}),
            # KURC
            (rb"/bin/busybox kurc", {"Botnet": "Kurc"}),
            # UNSTABLE
            (rb"/bin/busybox unstable|/bin/busybox elbatsnu|\\x6d\\x61\\x67\\x69\\x63\\x69\\x61\\x6e", {"Botnet": "Unstable"}),
            # Dark Nexus
            (rb"/bin/busybox hoho|hoho\.x86", {"Botnet": "Dark Nexus"}),
            # AISURU
            (rb"/bin/busybox aisuru", {"Botnet": "Aisuru"}),
            # ARES
            (rb"bin/busybox haxx|bin/busybox ares|flow\.x86|nigga\.x86|\\x41\\x72\\x65\\x73\\x2e\\x78\\x38\\x36", {"Botnet": "Ares"}),
            # TBOT
            (rb"/bin/busybox tbot|/bin/busybox tbotnet|\\x73\\x68\\x65\\x6c\\x6c\\x78\\x38\\x36|shell\.x86", {"Botnet": "Tbot"}),
            # IDDOSYOU
            (rb"iddosyou|andsm0kedoinks|josho\.x86", {"Botnet": "IDdosYou"}),
            # LOUD
            (rb"/bin/busybox loud|0xh0roxxnavebusyoo\.x86|/bin/busybox vga|\\x30\\x78\\x68\\x30\\x72\\x6f\\x78\\x78\\x6e\\x61\\x76\\x65\\x62\\x75\\x73\\x79\\x6f\\x6f\\x2e\\x78\\x38\\x36", {"Botnet": "Loud"}),
            # GAFGYT
            (rb"atlas\.(x86|arm|arm5|arm6|arm7|mips|mipsel|ppc|sh4|sparc)|/v1\.24/containers/create|ftpget\s+-v\s+-p\s+21\s+\d{1,3}(?:\.\d{1,3}){3}\s+telnetd|/bin/busybox botnet", {"Botnet": "Gafgyt"}),
            # HAJIME
            (rb"/bin/busybox ecchi|ihcce|\.verdf", {"Botnet": "Hajime"}),
            # MOZI
            (rb"(?:http://\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}/i|\\x59\\x59\\x46\\x4d\\x47\\x47|\\x41\\x54\\x55\\x31\\xed\\x53\\x48|\\x4d\\x6f\\x7a\\x69|mozi(?!lla|la)[\w.-]*|\\x53\\x4f\\x55\\x49\\x56\\x59)", {"Botnet": "Mozi"}),
            # MANGA
            (rb"http://\d{1,3}(?:\.\d{1,3}){3}/bins/dark\.(mpsl|arm5|arm6|arm7|x86|ppc|mips)|/bin/busybox dark", {"Botnet": "Manga"}),
            # SYLVEON
            (rb"/bin/busybox aa|sylveon", {"Botnet": "Sylveon"}),
            # Gafgyt
            (rb"atlas\.(x86|arm|arm5|arm6|arm7|mips|mipsel|ppc|sh4|sparc)|/v1\.24/containers/create|ftpget\s+-v\s+-p\s+21\s+\d{1,3}(?:\.\d{1,3}){3}\s+telnetd", {"Botnet": "Gafgyt"}),
            # PEDO
            (rb"/bin/busybox pedo|\\x70\\x65\\x64\\x6f|/pedalcheta/cutie\.x86", {"Botnet": "PedoBot"}),
            # NIGGABOX
            (rb"(?:niggabox|\\x6e\\x69\\x67\\x67\\x61\\x62\\x6f\\x78)", {"Botnet": "Niggabox"}),
            # HAKKA
            (rb"(?:hakka|\\x68\\x61\\x6b\\x6b\\x61)", {"Botnet": "Hakka"}),
            # Switchblades Botnet
            (rb"(?:sbidiot|switchblades|\\x53\\x42\\x49\\x44\\x49\\x4f\\x54)", {"Botnet": "Switchblades"}),
            # MIRAI
            (rb"(?:mirai|jklx86|\\x6a\\x6b\\x6c\\x78\\x38\\x36|\\x6d\\x69\\x72\\x61\\x69|/bin/busybox BOT)", {"Botnet": "Mirai"}),
            # SORA
            (rb"(?<!super)visoradmin|(?:[^a-zA-Z0-9]|^)sora(?:\.(?:x86|sh))?(?:[^a-zA-Z0-9]|$)|\\x73\\x6f\\x72\\x61|ak1k2|owari|fomni|wicked", {"Botnet": "Sora"}),
            # MIORI
            (rb"(?:miori|\\x6d\\x69\\x6f\\x72\\x69|\\x6d\\x69\\x6f\\x72\\x69\\x63\\x68)", {"Botnet": "Miori"}),
            # SATORI
            (rb"(?:satori|\\x61\\x74\\x6f\\x72\\x69|okosu)", {"Botnet": "Satori"}),
            # CONDI
            (rb"\bcondi\b|condixx|\\x38\\x31\\x38\\x32\\x54|\\x68\\x69\\x33\\x35\\x31\\x31|\\x63\\x6f\\x6e\\x64\\x69", {"Botnet": "Condi"}),
            # AndroxGh0st
            (rb"androxgh0st", {"Botnet": "AndroxGh0st"}),
            # TSUNAMI/KAITEN
            (rb"(?:tsunami|kaiten|\\x73\\x75\\x6e\\x61\\x6d\\x69|\\x61\\x69\\x74\\x65\\x6e)", {"Botnet": "Tsunami/Kaiten"}),

            # IoT Malware Download via wget, curl, tftp
            (rb"(wget|curl|ftpget|tftp)\s+(-O\s+)?http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?/[\w./-]+", {"Tag": "IoT Malware Download"}),

            # IoT botnet C2 URL pattern
            (rb"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?/[\w./-]+\.(mips|mipsel|mpsl|arm|sh|x86)", {"Tag": "C2 URL Download"})
        ]
    }

    analyze_pcap(pcap_file, regex_patterns)
