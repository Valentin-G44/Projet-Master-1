import subprocess

# Fonction pour exécuter la commande Hydra et enregistrer les résultats dans un fichier
def execute_hydra_command(username, password_list, target, service, output_file):
    command = ["hydra", "-l", username, "-P", password_list, "-f", target, service]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)

# Fonction pour exécuter la commande Nmap pour un scan de ports et enregistrer les résultats dans un fichier
def execute_nmap_port_scan(target, port_range, output_file):
    command = ["nmap", "-p", port_range, target]
    with open(output_file, "w") as file:
        subprocess.run(command, stdout=file)
    print("Le scan de ports a été effectué avec succès. Les résultats ont été enregistrés dans", output_file)

# Fonction pour générer un rapport à partir des fichiers de résultats
def generate_report(hydra_output_file, nmap_output_file, report_file):
    with open(report_file, "w") as report:
        report.write("=== Résultats de Nmap ===\n\n")
        with open(nmap_output_file, "r") as nmap_results:
            report.write(nmap_results.read())

        report.write("\n\n=== Résultats de Hydra ===\n\n")
        with open(hydra_output_file, "r") as hydra_results:
            report.write(hydra_results.read())

        print("Le rapport a été généré avec succès.")

# Fonction principale pour recueillir les paramètres et exécuter les commandes
def main():
    # Affichage du menu pour choisir l'outil à exécuter
    print("Veuillez choisir l'outil à exécuter :")
    print("1. Nmap")
    print("2. Hydra")
    choix = input("Votre choix (1 ou 2) : ")

    # Initialisation de la variable (si nmap n'est pas utiliser elle crée une erreur)
    nmap_output_file = None  # Initialisation de la variable
    # Vérification du choix de l'utilisateur et exécution de l'outil correspondant
    if choix == "1":
        # Demander à l'utilisateur les paramètres nécessaires pour Nmap
        target = input("Adresse IP de la cible : ")
        port_range = input("Plage de ports à scanner (par exemple, 1-1000) : ")
        nmap_output_file = input("Nom du fichier pour les résultats Nmap : ")

        # Exécuter la commande Nmap pour un scan de ports avec les paramètres fournis
        execute_nmap_port_scan(target, port_range, nmap_output_file)
        
    elif choix == "2":
        # Demander à l'utilisateur les paramètres nécessaires pour Hydra
        username = input("Nom d'utilisateur cible : ")
        password_list = "/home/valentingaget/Downloads/password_list.txt"
        target = input("Adresse IP de la cible : ")
        service = input("Service cible (par exemple, ssh, http, etc.) : ")
        hydra_output_file = input("Nom du fichier pour les résultats Hydra : ")

        # Exécuter la commande Hydra avec les paramètres fournis
        execute_hydra_command(username, password_list, target, service, hydra_output_file)

        # Demander à l'utilisateur le nom du fichier pour le rapport
        report_file = input("\nNom du fichier pour le rapport final : ")

        # Générer le rapport à partir des fichiers de résultats
        generate_report(hydra_output_file, nmap_output_file, report_file)

    else:
        print("Choix invalide. Veuillez saisir 1 ou 2.")

# Appeler la fonction principale
if __name__ == "__main__":
    main()
