import requests
import hashlib
import os
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ecdsa import SigningKey, SECP256k1
import hashlib
import base58
import logging
from datetime import datetime
from colorama import init, Fore, Back, Style
from eth_account import Account

# Initialize colored output
init(autoreset=True)

# Configuration
ETHERSCAN_API = "VHKK3E9HXG6VP7HIPN3J1THQ3QCBDI6XV3"
PROGRESS_FILE = "scan_progress.txt"
REQUEST_TIMEOUT = 20  # Increased timeout for all requests
MAX_RETRIES = 3       # Maximum number of request attempts

# Proxy configuration (can be disabled in menu)
PROXY_ENABLED = True
my_proxies = {
    'http':  'http://Sn4hZU91:cUx21UGV@45.139.31.32:63322',
    'https': 'http://Sn4hZU91:cUx21UGV@45.139.31.32:63322',
}

def get_request_session():
    """Create a session with proxy settings and timeouts"""
    session = requests.Session()
    if PROXY_ENABLED:
        session.proxies = my_proxies
    session.mount('http://', requests.adapters.HTTPAdapter(
        max_retries=MAX_RETRIES,
        pool_connections=20,
        pool_maxsize=100))
    session.mount('https://', requests.adapters.HTTPAdapter(
        max_retries=MAX_RETRIES,
        pool_connections=20,
        pool_maxsize=100))
    return session

def save_progress(position, filename):
    """Save current position in file"""
    with open(PROGRESS_FILE, 'w') as f:
        f.write(f"{filename}|{position}")

def load_progress():
    """Load last position from file"""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, 'r') as f:
            content = f.read().strip()
            if '|' in content:
                filename, position = content.split('|')
                return filename, int(position)
    return None, 0

def extract_addresses_from_file(file_path):
    """Extract BTC addresses from file with balances"""
    addresses = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = re.search(
                    r'(?:Address:\s*)?(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})',
                    line
                )
                if match:
                    addresses.append(match.group(1))
        return addresses
    except Exception as e:
        logging.error(f"File read error: {e}")
        return []

def get_user_input():
    """Interactive parameter input with menu"""
    global PROXY_ENABLED

    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.YELLOW + "SCAN PARAMETERS CONFIGURATION")
    print(Fore.CYAN + "="*50 + Style.RESET_ALL)

    # Additional settings menu
    print(Fore.MAGENTA + "\nAdditional settings:")
    print(Fore.CYAN +
          "1. Enable/disable proxy (current state: {'ON' if PROXY_ENABLED else 'OFF'})")
    print(Fore.CYAN + "2. Continue with main settings")

    choice = input(Fore.GREEN + "Select action (1-2): ")
    if choice == '1':
        PROXY_ENABLED = not PROXY_ENABLED
        print(Fore.YELLOW + f"Proxy is now {'enabled' if PROXY_ENABLED else 'disabled'}")

    mode = input(
        Fore.GREEN +
        "\nSelect mode (1 - block scanning, 2 - process file with BTC addresses, 3 - manual hash input): "
    )

    if mode == '1':
        block_range = input(Fore.GREEN +
                            "Enter block range (e.g. '100-200' or '100,150,200'): ")
        if '-' in block_range:
            start_block, end_block = map(int, block_range.split('-'))
            blocks = list(range(start_block, end_block + 1))
        elif ',' in block_range:
            blocks = list(map(int, block_range.split(',')))
        else:
            blocks = [int(block_range)]

        params = {
            'mode': 'blocks',
            'blocks': blocks,
            'MAX_RETRIES': MAX_RETRIES,
            'MAX_WORKERS': int(input(Fore.GREEN +
                                     "Number of threads (1-10, default 3): ") or 3),
            'BASE_DELAY': float(input(Fore.GREEN +
                                      "Delay between requests (0.5-5 sec, default 1.5): ") or 1.5),
            'SCAN_MEMPOOL': input(Fore.GREEN +
                                  "Scan mempool (y/n, default n): ").lower() == 'y'
        }

    elif mode == '2':
        file_path = input(Fore.GREEN + "Enter path to file with BTC addresses: ")
        if not os.path.exists(file_path):
            print(Fore.RED + "File not found!")
            exit()

        progress_file, progress_pos = load_progress()
        resume = False
        if progress_file == os.path.abspath(file_path):
            resume = input(Fore.YELLOW +
                           f"Found saved position ({progress_pos}). Continue from this point? (y/n): "
                           ).lower() == 'y'

        params = {
            'mode': 'address_file',
            'file_path': file_path,
            'resume': resume,
            'resume_pos': progress_pos if resume else 0,
            'MAX_WORKERS': int(input(Fore.GREEN +
                                     "Number of threads (1-10, default 3): ") or 3),
            'BASE_DELAY': float(input(Fore.GREEN +
                                      "Delay between requests (0.5-5 sec, default 1.5): ") or 1.5)
        }

    elif mode == '3':
        custom_hash = input(Fore.GREEN + "Enter hash for key generation: ")
        params = {
            'mode': 'custom',
            'custom_hash': custom_hash
        }

    else:
        print(Fore.RED + "Invalid mode!")
        exit()

    # Input validation
    if 'MAX_WORKERS' in params:
        params['MAX_WORKERS'] = max(1, min(10, params['MAX_WORKERS']))
    if 'BASE_DELAY' in params:
        params['BASE_DELAY'] = max(0.5, min(5.0, params['BASE_DELAY']))

    return params

def print_config(config):
    """Print current configuration"""
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.YELLOW + "CURRENT CONFIGURATION:")
    print(Fore.CYAN + "="*50)
    for key, value in config.items():
        print(Fore.GREEN + f"{key}: {Fore.WHITE}{value}")
    print(Fore.CYAN + "="*50 + Style.RESET_ALL)

    if config.get('mode') != 'custom' and input(
        Fore.YELLOW + "\nStart scanning? (y/n): ").lower() != 'y':
        exit()

def print_banner():
    """Fancy greeting"""
    print(Fore.CYAN + """
    ██████╗ ████████╗ ██████╗     ██╗  ██╗ ██████╗ ████████╗
    ██╔══██╗╚══██╔══╝██╔════╝     ██║  ██║██╔═══██╗╚══██╔══╝
    ██████╔╝   ██║   ██║  ███╗    ███████║██║   ██║   ██║   
    ██╔══██╗   ██║   ██║   ██║    ██╔══██║██║   ██║   ██║   
    ██████╔╝   ██║   ╚██████╔╝    ██║  ██║╚██████╔╝   ██║   
    ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   
    """)

def setup_logging():
    """Configure logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def check_btc_balance(address):
    """Check Bitcoin balance with optimized requests"""
    session = get_request_session()
    try:
        url = f"https://blockchain.info/balance?active={address}"
        response = session.get(url, timeout=REQUEST_TIMEOUT).json()
        if address in response:
            balance = response[address]['total_received']
            return balance, balance > 0
        return 0, False

    except Exception as e:
        logging.error(f"Bitcoin balance check error: {e}")
        return 0, False

def check_eth_balance(address):
    """Check Ethereum balance with optimized requests"""
    session = get_request_session()
    try:
        url = (
            f"https://api.etherscan.io/api?module=account"
            f"&action=balancemulti&address={address}"
            f"&tag=latest&apikey={ETHERSCAN_API}"
        )
        response = session.get(url, timeout=REQUEST_TIMEOUT).json()
        if response.get('status') == '1' and response.get('result'):
            balance_wei = int(response['result'][0]['balance'])
            return balance_wei, balance_wei > 0
        return 0, False

    except Exception as e:
        logging.error(f"Ethereum balance check error: {e}")
        return 0, False

def check_balances(key_info):
    """Check BTC (both compressed & uncompressed) and ETH balances"""
    results = {
        'btc': {'balance': 0, 'found': False},
        'eth': {'balance': 0, 'found': False}
    }

    # Проверяем сжатый BTC-адрес
    btc_balance_c, btc_found_c = check_btc_balance(
        key_info['btc']['address_compressed']
    )
    # Проверяем несжатый BTC-адрес
    btc_balance_u, btc_found_u = check_btc_balance(
        key_info['btc']['address_uncompressed']
    )

    results['btc']['balance'] = btc_balance_c + btc_balance_u
    results['btc']['found'] = btc_found_c or btc_found_u

    # Ethereum
    eth_balance, eth_found = check_eth_balance(key_info['eth']['address'])
    results['eth']['balance'] = eth_balance
    results['eth']['found'] = eth_found

    return results

def save_result(data, balances):
    """Save results to file"""
    if not os.path.exists('results'):
        os.makedirs('results')

    found = balances['btc']['found'] or balances['eth']['found']
    filename = 'FOUND_KEYS.txt' if found else 'all_results.txt'

    with open(f'results/{filename}', 'a', encoding='utf-8') as f:
        if found:
            f.write("="*80 + "\n")
            f.write("BALANCE FOUND!\n")
            f.write(f"Source data: {data.get('input_data', data.get('block_hash', 'N/A'))}\n")
            f.write(f"Time: {data['timestamp']}\n\n")

            if balances['btc']['found']:
                f.write("BITCOIN:\n")
                f.write(f"Compressed Address: {data['btc']['address_compressed']}\n")
                f.write(f"Uncompressed Address: {data['btc']['address_uncompressed']}\n")
                f.write(f"Private key (WIF): {data['btc']['private_key']}\n")
                f.write(f"Balance: {balances['btc']['balance']} satoshi\n\n")

            if balances['eth']['found']:
                eth_balance = balances['eth']['balance'] / 10**18
                f.write("ETHEREUM:\n")
                f.write(f"Address: {data['eth']['address']}\n")
                f.write(f"Private key: {data['eth']['private_key']}\n")
                f.write(f"Balance: {eth_balance} ETH\n\n")

            f.write("="*80 + "\n\n")
        else:
            f.write(
                f"{data['timestamp']} | "
                f"Source data: {data.get('input_data', data.get('block_hash', 'N/A'))[:20]}... | "
            )
            f.write(f"BTC (compressed): {data['btc']['address_compressed']} | ")
            f.write(f"BTC (uncompressed): {data['btc']['address_uncompressed']} | ")
            f.write(f"ETH: {data['eth']['address']} | ")
            f.write(
                f"Balances: BTC={balances['btc']['balance']}, "
                f"ETH={balances['eth']['balance']/10**18}\n"
            )

def process_address(address, params, position=None):
    """Optimized address processing with three check methods"""
    try:
        print(Fore.CYAN + f"\n[{datetime.now().strftime('%H:%M:%S')}] Processing address: {address}")

        if position is not None and params.get('file_path'):
            save_progress(position, os.path.abspath(params['file_path']))

        methods = [
            ("RAW", address),
            ("HASHED", hashlib.sha256(address.encode()).hexdigest()),
            ("HASH_ONLY", hashlib.sha256(address.encode()).hexdigest())
        ]

        for method_name, data in methods:
            key_info = generate_key_info(data)
            if not key_info:
                continue

            balances = check_balances(key_info)
            result = {
                'input_data': f"{method_name}({address})",
                **key_info,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            save_result(result, balances)

            if balances['btc']['found'] or balances['eth']['found']:
                print_found_balances(address, method_name, key_info, balances)

        if 'BASE_DELAY' in params:
            time.sleep(params['BASE_DELAY'] * random.uniform(0.8, 1.2))

        return True

    except Exception as e:
        logging.error(f"Address processing error {address}: {e}")
        return False

def process_address_file(file_path, params):
    """Process file with BTC addresses"""
    try:
        addresses = extract_addresses_from_file(file_path)
        if not addresses:
            print(Fore.RED + "Failed to extract addresses from file!")
            return

        print(Fore.GREEN + f"\nFound {len(addresses)} addresses to process")

        # If need to continue from saved position
        if params.get('resume', False):
            addresses = addresses[params['resume_pos']:]
            print(Fore.YELLOW + f"Continuing from position {params['resume_pos']}. {len(addresses)} addresses left")

        with ThreadPoolExecutor(max_workers=params['MAX_WORKERS']) as executor:
            futures = {}

            for idx, addr in enumerate(addresses, start=1):
                if params.get('resume', False):
                    position = params['resume_pos'] + idx
                else:
                    position = idx

                futures[executor.submit(process_address, addr, params, position)] = addr

                # Limit number of concurrent tasks
                if len(futures) >= params['MAX_WORKERS'] * 2:
                    for future in as_completed(futures):
                        addr = futures[future]
                        try:
                            future.result()
                        except Exception as e:
                            logging.error(f"Address processing error {addr[:10]}...: {e}")
                        del futures[future]
                        break

            # Wait for remaining tasks
            for future in as_completed(futures):
                addr = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Address processing error {addr[:10]}...: {e}")

    except Exception as e:
        logging.error(f"File processing error: {e}")
    finally:
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)

def process_block(height, params):
    """Process single block"""
    try:
        print(Fore.CYAN + f"\n[{datetime.now().strftime('%H:%M:%S')}] Processing block: {height}")

        # Get block hash
        block_hash = requests.get(
            f"https://blockchain.info/block-height/{height}?format=json",
            timeout=10
        ).json()['blocks'][0]['hash']

        # Generate keys
        key_info = generate_key_info(block_hash)
        if not key_info:
            return None

        # Check balances
        balances = check_balances(key_info)

        # Prepare result
        result = {
            'height': height,
            'block_hash': block_hash,
            **key_info,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Save result
        save_result(result, balances)

        # Print found balance info
        if balances['btc']['found'] or balances['eth']['found']:
            print(Fore.GREEN + Back.BLACK + Style.BRIGHT + "\n" + "="*60)
            print(Fore.YELLOW + "BALANCE FOUND!")
            print(Fore.CYAN + f"Block: {height}")
            print(Fore.CYAN + f"Block hash: {block_hash}")

            if balances['btc']['found']:
                print(Fore.GREEN + "\nBITCOIN:")
                print(Fore.WHITE + f"Compressed Address: {key_info['btc']['address_compressed']}")
                print(Fore.WHITE + f"Uncompressed Address: {key_info['btc']['address_uncompressed']}")
                print(Fore.WHITE + f"Private key: {key_info['btc']['private_key']}")
                print(Fore.WHITE + f"Balance: {balances['btc']['balance']} satoshi")

            if balances['eth']['found']:
                eth_balance = balances['eth']['balance'] / 10**18
                print(Fore.BLUE + "\nETHEREUM:")
                print(Fore.WHITE + f"Address: {key_info['eth']['address']}")
                print(Fore.WHITE + f"Private key: {key_info['eth']['private_key']}")
                print(Fore.WHITE + f"Balance: {eth_balance} ETH")

            print("="*60 + "\n")

        # Delay
        if 'BASE_DELAY' in params:
            time.sleep(params['BASE_DELAY'] * random.uniform(0.8, 1.2))

        return result

    except Exception as e:
        logging.error(f"Block processing error {height}: {e}")
        return None

def scan_mempool(params):
    """Scan mempool (unconfirmed transactions)"""
    try:
        print(Fore.CYAN + "\nStarting mempool scan...")
        txs = requests.get(
            "https://blockchain.info/unconfirmed-transactions?format=json",
            timeout=15
        ).json()['txs']

        for tx in txs:
            try:
                txid = tx['hash']
                key_info = generate_key_info(txid)
                if not key_info:
                    continue

                balances = check_balances(key_info)
                result = {
                    'txid': txid,
                    **key_info,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                save_result(result, balances)

                if balances['btc']['found'] or balances['eth']['found']:
                    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + "\n" + "="*60)
                    print(Fore.YELLOW + "BALANCE FOUND IN MEMPOOL!")
                    print(Fore.CYAN + f"TXID: {txid}")

                    if balances['btc']['found']:
                        print(Fore.GREEN + "\nBITCOIN:")
                        print(Fore.WHITE + f"Compressed Address: {key_info['btc']['address_compressed']}")
                        print(Fore.WHITE + f"Uncompressed Address: {key_info['btc']['address_uncompressed']}")
                        print(Fore.WHITE + f"Private key: {key_info['btc']['private_key']}")
                        print(Fore.WHITE + f"Balance: {balances['btc']['balance']} satoshi")

                    if balances['eth']['found']:
                        eth_balance = balances['eth']['balance'] / 10**18
                        print(Fore.BLUE + "\nETHEREUM:")
                        print(Fore.WHITE + f"Address: {key_info['eth']['address']}")
                        print(Fore.WHITE + f"Private key: {key_info['eth']['private_key']}")
                        print(Fore.WHITE + f"Balance: {eth_balance} ETH")

                    print("="*60 + "\n")

                time.sleep(params['BASE_DELAY'] * random.uniform(0.8, 1.2))

            except Exception as e:
                logging.error(f"TXID processing error {txid[:10]}...: {e}")
                continue

    except Exception as e:
        logging.error(f"Mempool scan error: {e}")

def process_hash(custom_hash, params):
    """Process custom hash"""
    try:
        print(Fore.CYAN + f"\nProcessing custom hash: {custom_hash}")

        key_info = generate_key_info(custom_hash)
        if not key_info:
            return None

        balances = check_balances(key_info)
        result = {
            'custom_hash': custom_hash,
            **key_info,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        save_result(result, balances)

        if balances['btc']['found'] or balances['eth']['found']:
            print(Fore.GREEN + Back.BLACK + Style.BRIGHT + "\n" + "="*60)
            print(Fore.YELLOW + "BALANCE FOUND!")
            print(Fore.CYAN + f"Hash: {custom_hash}")

            if balances['btc']['found']:
                print(Fore.GREEN + "\nBITCOIN:")
                print(Fore.WHITE + f"Compressed Address: {key_info['btc']['address_compressed']}")
                print(Fore.WHITE + f"Uncompressed Address: {key_info['btc']['address_uncompressed']}")
                print(Fore.WHITE + f"Private key: {key_info['btc']['private_key']}")
                print(Fore.WHITE + f"Balance: {balances['btc']['balance']} satoshi")

            if balances['eth']['found']:
                eth_balance = balances['eth']['balance'] / 10**18
                print(Fore.BLUE + "\nETHEREUM:")
                print(Fore.WHITE + f"Address: {key_info['eth']['address']}")
                print(Fore.WHITE + f"Private key: {key_info['eth']['private_key']}")
                print(Fore.WHITE + f"Balance: {eth_balance} ETH")

            print("="*60 + "\n")

        return result

    except Exception as e:
        logging.error(f"Hash processing error: {e}")
        return None

def generate_key_info(data):
    """
    Create BTC keys (compressed & uncompressed) + ETH key
    без использования bitcoinutils.
    """
    try:
        # 1) Получаем SHA256-хеш входных данных
        if isinstance(data, str):
            data = data.encode()
        hash_hex = hashlib.sha256(data).hexdigest()

        # 2) Генерируем ECDSA-приватный ключ из hash_hex
        priv_bytes = bytes.fromhex(hash_hex)
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()

        # 3) Несжатый публичный ключ (0x04 + X + Y)
        pub_uncompressed = b'\x04' + vk.to_string()
        # P2PKH-адрес (Bitcoin mainnet) из несжатого PK
        addr_uncmp = pubkey_to_p2pkh(pub_uncompressed)

        # 4) Сжатый публичный ключ: 
        #    если Y последнего байта чётный → 0x02, иначе 0x03, + X
        x_bytes = vk.to_string()[:32]
        y_bytes = vk.to_string()[32:]
        prefix = b'\x02' if (y_bytes[-1] % 2 == 0) else b'\x03'
        pub_compressed = prefix + x_bytes
        addr_cmp = pubkey_to_p2pkh(pub_compressed)

        # 5) Приватный ключ в WIF (compressed)
        wif = private_key_to_wif(priv_bytes, compressed=True)

        # 6) Ethereum-ключ (остается как было)
        eth_priv = "0x" + hash_hex[:64]
        eth_addr = Account.from_key(eth_priv).address

        return {
            'btc': {
                'private_key': wif,
                'address_compressed': addr_cmp,
                'address_uncompressed': addr_uncmp
            },
            'eth': {
                'private_key': eth_priv,
                'address': eth_addr
            },
            'hash_hex': hash_hex
        }

    except Exception as e:
        logging.error(f"Key generation error: {e}")
        return None


def pubkey_to_p2pkh(pubkey_bytes: bytes) -> str:
    """
    Конвертируем публичный ключ (bytes) в P2PKH-адрес (Base58Check).
    """
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripemd = hashlib.new('ripemd160', sha).digest()
    prefix = b'\x00'  # mainnet
    payload = prefix + ripemd
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()


def private_key_to_wif(priv_bytes: bytes, compressed: bool = True) -> str:
    """
    Конвертируем raw-приватный ключ (32 байта) в WIF (Base58Check).
    Если compressed=True, добавляем байт 0x01 перед контрольной суммой.
    """
    prefix = b'\x80'
    suffix = b'\x01' if compressed else b''
    payload = prefix + priv_bytes + suffix
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()


def print_found_balances(source, method, key_info, balances):
    """Print info about found balances"""
    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + "\n" + "="*60)
    print(Fore.YELLOW + f"BALANCE FOUND ({method})!")
    print(Fore.CYAN + f"Source data: {source}")

    if balances['btc']['found']:
        print(Fore.GREEN + "\nBITCOIN:")
        print(Fore.WHITE + f"Compressed Address: {key_info['btc']['address_compressed']}")
        print(Fore.WHITE + f"Uncompressed Address: {key_info['btc']['address_uncompressed']}")
        print(Fore.WHITE + f"Private key: {key_info['btc']['private_key']}")
        print(Fore.WHITE + f"Balance: {balances['btc']['balance']} satoshi")

    if balances['eth']['found']:
        eth_balance = balances['eth']['balance'] / 10**18
        print(Fore.BLUE + "\nETHEREUM:")
        print(Fore.WHITE + f"Address: {key_info['eth']['address']}")
        print(Fore.WHITE + f"Private key: {key_info['eth']['private_key']}")
        print(Fore.WHITE + f"Balance: {eth_balance:.6f} ETH")

    print("="*60 + "\n")

def process_address_file_from(file_path, params, start_address=None):
    """Process file with BTC addresses with option to start from specific address"""
    try:
        addresses = extract_addresses_from_file(file_path)
        if not addresses:
            print(Fore.RED + "Failed to extract addresses from file!")
            return

        # If start address specified, find its position
        start_pos = 0
        if start_address:
            try:
                start_pos = addresses.index(start_address)
                print(Fore.YELLOW +
                      f"\nStarting from address {start_address} (position {start_pos + 1})")
            except ValueError:
                print(Fore.RED +
                      f"\nAddress {start_address} not found in file! Starting from beginning.")
                start_pos = 0

        addresses = addresses[start_pos:]
        print(Fore.GREEN + f"\nFound {len(addresses)} addresses to process")

        with ThreadPoolExecutor(max_workers=params['MAX_WORKERS']) as executor:
            futures = {}

            for idx, addr in enumerate(addresses, start=1):
                position = start_pos + idx
                futures[executor.submit(process_address, addr, params, position)] = addr

                if len(futures) >= params['MAX_WORKERS'] * 2:
                    for future in as_completed(futures):
                        addr = futures[future]
                        try:
                            future.result()
                        except Exception as e:
                            logging.error(f"Address processing error {addr[:10]}...: {e}")
                        del futures[future]
                        break

            for future in as_completed(futures):
                addr = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Address processing error {addr[:10]}...: {e}")

    except Exception as e:
        logging.error(f"File processing error: {e}")
    finally:
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)

def main():
    # Environment setup
    print_banner()
    setup('mainnet')
    setup_logging()

    try:
        while True:
            params = get_user_input()
            print_config(params)

            if params['mode'] == 'custom':
                result = process_hash(params['custom_hash'], params)
                if result:
                    balances = check_balances(result)
                    if balances['btc']['found'] or balances['eth']['found']:
                        print(Fore.GREEN + Back.BLACK + Style.BRIGHT +
                              f"\nFOUND FUNDS IN HASH {params['custom_hash'][:12]}...!")

            elif params['mode'] == 'address_file':
                # Add option to start from specific address
                if input(Fore.YELLOW +
                         "Start from specific address in file? (y/n): ").lower() == 'y':
                    start_addr = input(Fore.GREEN + "Enter address to start from: ").strip()
                    process_address_file_from(params['file_path'], params, start_addr)
                else:
                    process_address_file(params['file_path'], params)

            elif params['mode'] == 'blocks':
                with ThreadPoolExecutor(max_workers=params['MAX_WORKERS']) as executor:
                    futures = {}
                    for height in params['blocks']:
                        futures[executor.submit(process_block, height, params)] = height
                    if params.get('SCAN_MEMPOOL', False):
                        futures[executor.submit(scan_mempool, params)] = "mempool"

                    for future in as_completed(futures):
                        task = futures[future]
                        try:
                            result = future.result()
                            if result and isinstance(task, int):
                                balances = check_balances(result)
                                if balances['btc']['found'] or balances['eth']['found']:
                                    print(Fore.GREEN + Back.BLACK + Style.BRIGHT +
                                          f"\nFOUND FUNDS IN BLOCK {task}!")
                        except Exception as e:
                            logging.error(f"Block error {task}: {e}")

            if input(Fore.YELLOW + "\nContinue working? (y/n): ").lower() != 'y':
                break

    except KeyboardInterrupt:
        print(Fore.RED + "\nScanning interrupted by user")
    except Exception as e:
        logging.error(f"Critical error: {e}")
    finally:
        print(Fore.GREEN + "\nScanning completed. Results saved in 'results' folder")

if __name__ == "__main__":
    main()
