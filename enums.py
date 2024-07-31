import subprocess
import argparse
import nmap
import logging

logger = logging.getLogger(__file__)
logger.addHandler(logging.FileHandler("./log.txt"))
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


def exec_cmd(cmd) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def port_scan(ip):
    nm = nmap.PortScanner()
    res = nm.scan(hosts=ip, arguments='-p- -T4')
    logger.info(res)
    return res

def is_open_http(nmap_scan_result, ip):
    return nmap_scan_result['scan'][ip]['tcp'][80]['state'] == 'open'

def get_hostname(nmap_scan_result, ip):
    return nmap_scan_result['scan'][ip]['hostnames'][0]['name']

def whatweb(hostname) -> str:
    cmd = f'whatweb --aggression 3 -v http://{hostname}'
    ret = exec_cmd(cmd)
    logger.info(ret)
    return ret

def dirsearch(hostname) -> str:
    cmd = f'dirsearch -u http://{hostname} -i 200'
    ret = exec_cmd(cmd)
    logger.info(ret)
    return ret

def feroxbuster(hostname) -> str:
    cmd = f'feroxbuster -u http://{hostname} -n'
    ret = exec_cmd(cmd)
    logger.info(ret)
    return ret

def ffuf(hostname) -> str:
    fuzz_domain = f'FUZZ.{hostname}'
    cmd = f'ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://{hostname} -H "Host: {fuzz_domain} -mc 200'
    ret = exec_cmd(cmd)
    logger.info(ret)
    return ret

# args setting
parser = argparse.ArgumentParser()
parser.add_argument('--ip', help='target ip address', required=True)
args = parser.parse_args()
logger.info(f'target ip address: {args.ip}')


nmap_scan_result = port_scan(args.ip)
hostname = get_hostname(nmap_scan_result, args.ip)

logger.info(f"hostname : {hostname}")

if is_open_http(nmap_scan_result, args.ip):
    
    if hostname:
        with open('/etc/hosts', 'a') as f:
            print(f'{args.ip}   {hostname}', file=f)

        ret = ffuf(hostname)
        ret = whatweb(hostname)
        ret = dirsearch(hostname)
        ret = feroxbuster(hostname)
