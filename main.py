import os
from concurrent.futures import ThreadPoolExecutor
import logging
import utils
import concurrent.futures
from typing import List
import vpn
from time import sleep
import sys
import logging.config
import glob
import resource
import psutil

if not utils.is_root():
    print("Please run this script as root.")
    sys.exit(1)

logging_config = {
    'version': 1,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(levelname)s - %(message)s',
        },
    },
    'handlers': {
        'file': {
            'class': 'logging.FileHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'filename': 'vpn_manager.log',
            'mode': 'a',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'stream': sys.stdout,
        },
    },
    'root': {
        'level': 'INFO',
        'handlers': ['file', 'console'],
    },
}

logging.config.dictConfig(logging_config)

running_config = []
running_ip = []
running_ports = []
running_instances = []
NUM_PROXY = 10
PROXY_PORTS = [x for x in range(1080, 1080 + NUM_PROXY)]
MAX_THREADS = 50

def add_instance(instance: vpn.VPNConnection, proxy_port: int):
    instance.change_proxy_port(proxy_port)
    running_config.append(instance.config_path)
    running_ports.append(instance.proxy_port)
    running_instances.append(instance)
    logging.info(f"Selected {instance.config_name} for proxy on port {instance.proxy_port}")

def run_proxy(available_ports):
    if len(available_ports) == 0:
        return
    
    vpn_configs = utils.load_config()
    # filenames = os.listdir(os.getcwd() + "/configs")
    # vpn_configs = [os.path.join(os.getcwd() + "/configs", filename) for filename in filenames if filename.endswith('.ovpn')]
    # vpn_configs = vpn_configs[:10]  # Limit to 10 configs for testing
    vpn_configs = [config for config in vpn_configs if config not in running_config]

    bench: List[tuple[vpn.VPNConnection], float] = utils.load_configs(vpn_configs)
    
    with ThreadPoolExecutor(MAX_THREADS) as executor:
        counter = 0
        index = 0
        selected_id = []

        while counter < len(available_ports) and index < len(bench):
            instance, latency, fail_rate = bench[index]
            if instance.resolved_ip is not None and not instance.resolved_ip.startswith('219.100.37') and instance.resolved_ip not in running_ip:
                logging.info(f"[MAIN] Selected {instance.config_name} - Latency: {latency}, Fail rate: {fail_rate}")
                running_ip.append(instance.resolved_ip)
                executor.submit(add_instance, instance, available_ports[counter])
                selected_id.append(index)
                counter += 1

            index += 1

        for index, instance in enumerate(bench):
            if index not in selected_id:
                executor.submit(instance[0].stop_connect)

def get_fd_info():
    if sys.platform.startswith('linux'):
        # Linux: Đếm FD và lấy giới hạn
        open_fds = len(glob.glob('/proc/self/fd/*'))
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        return open_fds, soft_limit, hard_limit
    elif sys.platform.startswith('darwin'):
        # macOS: Đếm FD và lấy giới hạn
        open_fds = len(glob.glob('/dev/fd/*'))
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        return open_fds, soft_limit, hard_limit
    elif sys.platform.startswith('win'):
        # Windows: Đếm handle
        p = psutil.Process()
        open_handles = p.num_handles()
        return open_handles, None, None  # Không có giới hạn mềm và cứng
    else:
        raise NotImplementedError("Hệ điều hành không được hỗ trợ")



while True:
    try:
        info = get_fd_info()
        if len(info) == 3 and info[1] is not None:
            open_fds, soft_limit, hard_limit = info
            logging.info(f"Số FD đang mở: {open_fds}")
            logging.info(f"Giới hạn mềm: {soft_limit}")
            logging.info(f"Giới hạn cứng: {hard_limit}")
        else:
            open_handles, _, _ = info
            logging.info(f"Số handle đang mở: {open_handles}")

        logging.info(f"[MAIN] Running ips: {running_ip}")
        logging.info(f"[MAIN] Running configs: {running_config}")
        logging.info(f"[MAIN] Running ports: {running_ports}")
        with ThreadPoolExecutor(MAX_THREADS) as executor:
            futures = [executor.submit(utils.benchmark_vpn_latency, instance, inital_check=False) for instance in running_instances]

            for future in concurrent.futures.as_completed(futures):
                instance, latency, fail_rate = future.result()
                if latency is None or latency > 2.0 or fail_rate > 0.5:
                    logging.info(f"[MAIN] Remove {instance.config_name} - Latency: {latency}, Fail rate: {fail_rate}")
                    running_config.remove(instance.config_path)
                    running_ports.remove(instance.proxy_port)
                    running_instances.remove(instance)
                    running_ip.remove(instance.resolved_ip)

        available_ports = [x for x in PROXY_PORTS if x not in running_ports]
        if len(available_ports) > 0:
            logging.info(f"[MAIN] Available ports: {available_ports}")
            run_proxy(available_ports)
            logging.info(f"[MAIN] Run new proxy done")
            
        sleep(60)
    except ValueError as e:
        logging.error(f"ValueError in main loop: {e}", exc_info=True)
        sleep(5)
        continue
    except Exception as e:
        logging.error(f"Error in main loop: {e}", exc_info=True)
        sleep(5)
        continue