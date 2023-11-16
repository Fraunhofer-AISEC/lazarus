
import subprocess

def get_config_hash_file_name(file_name):
    result = subprocess.run(['./fit_config_hash', '-f', file_name], capture_output=True, text=True)
    config_hash_str = result.stdout.split()[1]
    config_hash = bytes.fromhex(config_hash_str)

    return config_hash
