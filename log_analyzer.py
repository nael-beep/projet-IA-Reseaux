import pandas as pd
import re
from datetime import datetime, timedelta

# --- CONFIGURATION ---
LOG_FILE_PATH = '/var/log/gns3/network-devices.log'
# Seuil pour la détection de flapping : plus de X changements...
FLAPPING_THRESHOLD = 4 
# ... sur une période de Y minutes.
TIME_WINDOW_MINUTES = 1

# --- Fonctions de Parsing (inchangées) ---
def parse_cisco_log_line(line):
    log_pattern = re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+(.*)')
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

# --- NOUVELLE FONCTION D'ANALYSE D'ANOMALIES ---
def analyze_flapping(df):
    """
    Analyse le DataFrame pour détecter le flapping d'interface.
    """
    print("\n--- Analyse de Détection de Flapping d'Interface ---")
    
    # 1. Filtrer pour ne garder que les messages de changement d'état d'interface
    # On cherche les messages qui contiennent "%LINK-3-UPDOWN"
    link_status_df = df[df['message'].str.contains("%LINK-3-UPDOWN")].copy()

    if link_status_df.empty:
        print("Aucun message de changement d'état d'interface trouvé.")
        return

    # 2. Extraire le nom de l'interface de chaque message
    # La Regex 'Interface ([\w/]+),' capture le nom de l'interface
    link_status_df['interface'] = link_status_df['message'].str.extract(r'Interface ([\w/]+),')

    # 3. Filtrer les logs sur la dernière fenêtre de temps
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=TIME_WINDOW_MINUTES)
    recent_logs = link_status_df[link_status_df['timestamp'] >= start_time]

    if recent_logs.empty:
        print(f"Aucun changement d'état d'interface dans les {TIME_WINDOW_MINUTES} dernières minutes.")
        return

    print(f"Analyse des {len(recent_logs)} changements d'état survenus depuis {start_time.strftime('%H:%M:%S')}...")

    # 4. Compter les changements par switch et par interface
    flapping_counts = recent_logs.groupby(['hostname', 'interface']).size()

    # 5. Identifier les interfaces qui dépassent le seuil
    potential_flapping = flapping_counts[flapping_counts > FLAPPING_THRESHOLD]

    if potential_flapping.empty:
        print("Aucune anomalie de flapping détectée.")
    else:
        print("\n/!\\ ALERTE : FLAPPING D'INTERFACE DÉTECTÉ /!\\")
        for (hostname, interface), count in potential_flapping.items():
            print(f"  - L'interface {interface} sur le switch {hostname} a changé d'état {count} fois !")

# --- SCRIPT PRINCIPAL (modifié pour appeler la nouvelle fonction) ---
if __name__ == "__main__":
    # ... (toute la partie lecture et parsing du fichier reste la même) ...
    print(f"Analyse du fichier de log : {LOG_FILE_PATH}")
    all_log_data = []
    try:
        with open(LOG_FILE_PATH, 'r') as f: lines = f.readlines()
    except Exception as e:
        print(f"ERREUR : {e}. Essayez avec 'sudo'."); exit()

    for line in lines:
        parsed_line = parse_cisco_log_line(line)
        if parsed_line: all_log_data.append(parsed_line)

    if not all_log_data:
        print("Aucune ligne de log valide trouvée.")
    else:
        df = pd.DataFrame(all_log_data)
        # On s'assure que la colonne timestamp est bien au format datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # On appelle notre nouvelle fonction d'analyse !
        analyze_flapping(df)
