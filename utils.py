import requests
import logging
import os
import base64
import asyncio
from concurrent.futures import ThreadPoolExecutor
import vpn
import socket
from typing import List
from time import sleep
import concurrent.futures

CONFIG_PATH = os.getcwd() + "/configs"
MAX_THREADS = 50

def is_root():
    return os.getuid() == 0

def get_available_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0))
    _, port = sock.getsockname()
    sock.close()
    return port

def get_vpn_list():
    response = requests.get("http://www.vpngate.net/api/iphone/")
    
    if response.text:
        lines = response.text.splitlines()
        filtered_lines = [line for line in lines[2:] if line and line != "*"]
        return filtered_lines
    else:
        logging.error(f"[GET VPN LIST] No data received from VPN list API (status code: {response.status_code})")
        return []
    
def load_config():
    config_list = get_vpn_list()

    if not config_list:
        logging.error("[CONFIG PARSER] No VPN configurations found.")
        return []
    
    logging.info(f"[CONFIG PARSER] Loading {len(config_list)} configs...")

    if not os.path.exists(CONFIG_PATH):
        os.makedirs(CONFIG_PATH)

    vpn_configs = []

    def process_config(config):
        try:
            if not config.strip():
                return

            cols = config.split(',')
            config_name = f"{cols[1]}_{cols[6]}"

            cfg = base64.b64decode(cols[14]).decode('utf-8')
            cfg += '\n' + 'pull-filter ignore "redirect-gateway"' + '\n'

            if 'cipher AES-128-CBC' in cfg:
                cfg += 'data-ciphers AES-128-CBC' + '\n'

            file_path = os.path.join(CONFIG_PATH, f"{config_name}.ovpn")
            with open(file_path, 'wt', encoding='utf-8') as f:
                f.write(cfg)

            vpn_configs.append(file_path)
        except Exception as e:
            logging.error(f"[CONFIG PARSER] Error processing config: {str(e)}", exc_info=True)
            raise e

    with ThreadPoolExecutor(MAX_THREADS) as executor:
        executor.map(process_config, config_list)

    return vpn_configs

def benchmark_vpn_latency(vpn_connection: vpn.VPNConnection, attempts=3, inital_check=True):

    successful_latencies = []
    proxies = {
        'http': f"socks5h://localhost:{vpn_connection.proxy_port}",
        'https': f"socks5h://localhost:{vpn_connection.proxy_port}"
    }
    
    for i in range(attempts):
        try:
            response = requests.get("http://www.google.com", proxies=proxies, timeout=5)
            if response.status_code == 200:
                successful_latencies.append(response.elapsed.total_seconds())
                logging.debug(f"[BENCHMARK] - {vpn_connection.config_name} - Attempt {i+1}/{attempts}: {response.elapsed.total_seconds():.3f}s")
                # if break_on_success:
                #     break
            else:
                logging.error(f"[BENCHMARK] - {vpn_connection.config_name} - Attempt {i+1}/{attempts} failed: status code {response.status_code}")
        except Exception as e:
            logging.error(f"[BENCHMARK] - {vpn_connection.config_name} - Error in attempt {i+1}/{attempts}: {str(e)}")
        finally:
            sleep()
    
    if inital_check:
        try:
            response = requests.get("https://icanhazip.com", proxies=proxies, timeout=5)
            if response.status_code == 200:
                resolved_ip = response.text.strip()
                if resolved_ip:
                    vpn_connection.resolved_ip = resolved_ip
                    logging.info(f"[BENCHMARK] - {vpn_connection.config_name} - IP: {resolved_ip}")
                else:
                    logging.error(f"[BENCHMARK] - {vpn_connection.config_name} - Failed to resolve IP with response {response.text}")
            else:
                logging.error(f"[BENCHMARK] - {vpn_connection.config_name} - Failed to get IP: status code {response.status_code}")
        except Exception as e:
            logging.error(f"[BENCHMARK] - {vpn_connection.config_name} - Error getting IP: {str(e)}")

    if successful_latencies:
        avg_latency = sum(successful_latencies) / len(successful_latencies)
        logging.info(f"[BENCHMARK] - {vpn_connection.config_name} - Average latency ({len(successful_latencies)}/{attempts} successful): {avg_latency:.3f}s")
        return vpn_connection, avg_latency, 1 - len(successful_latencies) / attempts
    else:
        logging.error(f"[BENCHMARK] - {vpn_connection.config_name} - All {attempts} latency measurement attempts failed for {vpn_connection.config_name}")
        vpn_connection.stop_connect()
        return vpn_connection, None, 0.0


def load_configs(vpn_configs):
    instances: List[vpn.VPNConnection] = []

    for config_path in vpn_configs:
        vpn_instance = vpn.VPNConnection(config_path, get_available_tcp_port(), max_reconnect_attempts=1)
        vpn_instance.start_connect()
        instances.append(vpn_instance)


    total_instance = len(instances)
    connected_instance = 0
    failed_instance = 0

    while connected_instance < total_instance - failed_instance:
        sleep(1)
        failed_instance = len([x for x in instances if x.on_exit or x.self_exit])
        connected_instance = len([x for x in instances if x.is_connected])
        logging.debug(f"[LOADER] Connected: {connected_instance}, Failed: {failed_instance}, Total: {total_instance}")
        # logging.debug(f"Connected instances: {[x.config_name for x in instances if x.is_connected]}")
        # logging.debug(f"Failed instances: {[x.config_name for x in instances if x.on_exit or x.self_exit]}")
        # logging.debug(f"Pending instances: {[x.config_name for x in instances if not x.is_connected and not x.on_exit and not x.self_exit]}")

    instances = [x for x in instances if x.is_connected]
    if not instances:
        logging.error("[LOADER] No VPN connections were established.")
        return None

    with ThreadPoolExecutor(MAX_THREADS) as executor:
        futures = [executor.submit(benchmark_vpn_latency, instance) for instance in instances]
        concurrent.futures.wait(futures)

        results: List[tuple[vpn.VPNConnection, float]] = []
        for future in futures:
            instance, latency, fail_rate = future.result()
            if latency is not None:
                results.append((instance, latency, fail_rate))

        if not results:
            logging.error("[LOADER] No successful latency measurements.")
            return None
        
    return sorted(results, key=lambda x: (x[2], x[1] if x[1] is not None else float('inf')))
