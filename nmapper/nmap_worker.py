import pathlib
import socket
from multiprocessing.pool import ThreadPool

import nmap
from diamond_shovel.function.task import TaskContext
from kink import inject

from nmap_container import plugin_di


@inject(container=plugin_di)
def execute_scan(target_hosts: list[str], ports: str, extra_flags: str, data_folder: pathlib.Path):
    nm = nmap.PortScanner(nmap_search_path=(
            "nmap",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/sw/bin/nmap",
            "/opt/local/bin/nmap",
            data_folder / "nmap"
        ))
    ip_mapping = {}
    for domain_or_ip in target_hosts:
        try:
            ip = socket.gethostbyname(domain_or_ip)
            if ip not in ip_mapping:
                ip_mapping[ip] = [domain_or_ip]
                nm.scan(hosts=ip, arguments=f'-p {ports} {extra_flags}')
            else:
                ip_mapping[ip].append(domain_or_ip)
        except Exception as e:
            raise Exception(f'解析域名 {domain_or_ip} 出错: {e}')
    results = {}
    for ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            lport = nm[ip][proto].keys()
            for port in lport:
                if nm[ip][proto][port]['state'] == 'open':
                    if ip not in results:
                        results[ip] = []
                    results[ip].append((port, proto))
    return results, ip_mapping


@inject(container=plugin_di)
def handle_task(task: TaskContext, ports: str, thread_size: int, extra_flags: str):
    target_hosts_full = task.target_hosts + task.target_domains
    hosts_chunks = [target_hosts_full[i::thread_size] for i in range(thread_size)]
    pool = ThreadPool(thread_size)
    results = pool.map(lambda x: execute_scan(x, ports, extra_flags), hosts_chunks)
    pool.close()
    pool.join()
    task.nmap_result = results
