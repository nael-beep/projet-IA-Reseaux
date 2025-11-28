import pandas as pd
import re
from datetime import datetime

# ON POINTE VERS NOTRE FICHIER FINAL !
LOG_FILE_PATH = '/var/log/gns3/network-devices.log'

def parse_cisco_log_line(line):
    # Regex pour extraire le timestamp, le hostname (IP) et le message
    log_pattern = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+(.*)'
    )
    match = log_pattern.match(line)
    if match:
        timestamp_str, hostname, message = match.groups()
        current_year = datetime.now().year
        full_timestamp_str = f"{timestamp_str} {current_year}"
        try:
            timestamp = pd.to_datetime(full_timestamp_str, format='%b %d %H:%M:%S %Y')
        except ValueError:
            timestamp = pd.NaT
        return {'timestamp': timestamp, 'hostname': hostname, 'message': message.strip()}
    return None

if __name__ == "__main__":
    print(f"Analyse du fichier de log : {LOG_FILE_PATH}")
    all_log_data = []
    try:
        with open(LOG_FILE_PATH, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"ERREUR : {e}. Essayez avec 'sudo'.")
        exit()

    for line in lines:
        parsed_line = parse_cisco_log_line(line)
        if parsed_line:
            all_log_data.append(parsed_line)

    if not all_log_data:
        print("\nAnalyse terminée. Aucune ligne de log valide n'a été trouvée.")
    else:
        df = pd.DataFrame(all_log_data)
        print("\n--- Aperçu des données ---")
        print(df) # On affiche tout le DataFrame cette fois, puisqu'il est petit

        print("\n--- Informations sur le DataFrame ---")
        df.info()

        print("\n--- Nombre de logs par équipement ---")
        print(df['hostname'].value_counts())
        
        # Extraire le code du message (ex: %SYS-5-CONFIG_I)
        df['msg_code'] = df['message'].str.extract(r'(%(\w+-\d+-\w+))')[0]
        
        print("\n--- Types de messages détectés ---")
        print(df['msg_code'].value_counts())
