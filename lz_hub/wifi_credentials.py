import re

def load(wifi_credentials_file_name):

    # Create empty dictionary for the WiFi-credentials
    dict = { 'ssid' : '', 'ip' : '', 'pwd' : '', 'port' : 0}

    # Read WiFi-credentials file
    try:
        with open(wifi_credentials_file_name, "r") as credential_file:
            lines = credential_file.readlines()
    except Exception as e:
        print("Error: Unable to open WiFi credentials file: %s. Exit.." %(str(e)))
        return None

    # Fill dictionary with WiFi credentials
    i = 0
    for line in lines:
        i = i + 1
        key, value = line.split(sep='=', maxsplit=1)
        try:
            value = re.findall(r'"(.*?)"', value)[0]
            if key in dict:
                dict[key] = value
            else:
                print("Error parsing wifi_credentials.txt: Key %s does not exist" %key)
                return None
        except Exception as e:
            print("Error parsing wifi_credentials.txt: %s" %str(e))
            return None
        if i == 4:
            break

    # Convert port into a number
    try:
        dict['port'] = int(dict['port'])
        if dict['port'] < 0 or dict['port'] > 65535:
            print("Invalid port %d. Port must be a number between 0 and 65535" %dict['port'])
            return None
    except Exception as e:
        print("Invalid port %s. Port must be a number between 0 and 65535" %dict['port'])
        return None

    return dict
