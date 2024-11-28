#!/bin/bash

# Définir les couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'  # Pas de couleur

figlet -c "SEC "

# Fonction 1 : Bloquer les ports inutiles
function bloquer_ports_inutiles {
    while true; do
        clear  # Efface l'écran avant d'afficher le menu
        # Afficher un menu avec trois options
        echo -e "${YELLOW}Menu de gestion des ports :${NC}"
        echo "1. Voir les ports ouverts"
        echo "2. Autoriser des ports spécifiques (et fermer les autres)"
        echo "3. Scanner les ports ouverts avec Nmap"
        echo "4. Retour au menu principal"

        read -p "Entrez votre choix (1, 2, 3 ou 4) : " choix

        case $choix in
            1)
                clear
                # Option 1 : Voir les ports ouverts
                echo -e "${CYAN}Ports TCP ouverts :${NC}"
                ss -tuln | grep LISTEN  # Affiche les ports en écoute
                echo
                read -p "Appuyez sur Entrée pour revenir au menu..."
                ;;
            2)
                clear
                # Option 2 : Autoriser des ports spécifiques
                echo -e "${YELLOW}Blocage des ports inutiles...${NC}"
                
                # Demander à l'utilisateur quels ports doivent être autorisés
                read -p "Entrez les ports à autoriser (séparés par des virgules, ex: 22,80,443) : " ports_autorises

                # Définir la politique par défaut pour bloquer les ports
                iptables -P INPUT DROP
                iptables -P FORWARD DROP
                iptables -P OUTPUT ACCEPT

                # Autoriser les connexions déjà établies
                iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

                # Séparer les ports par des virgules et les autoriser
                IFS=',' read -ra PORTS <<< "$ports_autorises"
                for port in "${PORTS[@]}"; do
                    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
                    echo -e "${GREEN}Port $port autorisé.${NC}"
                done

                echo -e "${GREEN}Ports inutiles bloqués.${NC}"
                read -p "Appuyez sur Entrée pour revenir au menu..."
                ;;
            3)
                clear
                # Option 3 : Scanner les ports ouverts avec Nmap
                echo -e "${YELLOW}Scan des ports ouverts avec Nmap...${NC}"
                read -p "Entrez l'adresse IP ou la plage IP à scanner (ex: 192.168.1.0/24) : " cible
                nmap -p- -T 5 "$cible"  # Effectue un scan complet de tous les ports
                echo
                read -p "Appuyez sur Entrée pour revenir au menu..."
                ;;
            4)
                # Option 4 : Retour au menu principal
                return
                ;;
            *)
                echo -e "${RED}Choix invalide. Veuillez entrer 1, 2, 3 ou 4.${NC}"
                read -p "Appuyez sur Entrée pour réessayer..."
                ;;
        esac
    done
}





# Fonction 2 : Bloquer une adresse IP suspecte
function bloquer_ip_suspecte {
    # Vérifier si nmap est installé
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}nmap n'est pas installé. Veuillez l'installer avec 'sudo apt install nmap'.${NC}"
        return
    fi

    # Scanner le réseau local pour découvrir les appareils actifs
    echo -e "${YELLOW}Scan du réseau local en cours...${NC}"
    read -p "Entrez le réseau à scanner (ex: 192.168.1.0/24) : " reseau
    nmap -sn $reseau | grep "Nmap scan report for" | awk '{print $5}'

    # Demander à l'utilisateur s'il souhaite bloquer des IP
    echo -e "${CYAN}Entrez les adresses IP à bloquer, séparées par des virgules :${NC}"
    read -p "> " ips

    # Séparer les adresses IP par des virgules et les bloquer
    IFS=',' read -ra IP_ARRAY <<< "$ips"
    for ip in "${IP_ARRAY[@]}"; do
        iptables -A INPUT -s "$ip" -j DROP
        echo -e "${RED}Adresse IP $ip bloquée.${NC}"
    done
}




# Fonction 3 : Limitation d'accès (exemple)
function processus {
    # Supprimer l'affichage précédent
    clear

    # Afficher les en-têtes pour le tableau
    echo -e "============================================="
    echo -e "    Ports en écoute avec processus associés"
    echo -e "============================================="

    # Afficher les ports en écoute avec les processus associés sous forme tabulaire
    echo -e "PORT       |  PROTO  |  PID/PROCESSUS        |  SERVICE"
    echo -e "--------------------------------------------"

    # Utiliser ss pour lister les connexions et les processus associés
    ss -tulnp | grep -v "State" | awk '{print $5 " | " $1 " | " $6 " | " $7}' | sed 's/:/  /'

    # Demander à l'utilisateur s'il souhaite tuer un processus
    echo -e "\n============================================="
    echo -e "Souhaitez-vous tuer un processus ? (y/n)"
    read -r choix

    if [[ "$choix" == "y" || "$choix" == "Y" ]]; then
        # Demander l'ID du processus à tuer
        echo -e "\nEntrez le PID du processus à tuer :"
        read -r pid

        # Vérifier si le PID existe
        if ps -p "$pid" > /dev/null; then
            # Tuer le processus
            echo -e "Killing process with PID $pid..."
            kill -9 "$pid"
            echo -e "Process $pid has been terminated."
        else
            echo -e "PID $pid non trouvé. Aucun processus à tuer."
        fi
    fi

    echo -e "\n============================================="
    echo -e "Appuyez sur Entrée pour continuer ou Ctrl+C pour arrêter."
    read -r  # Attendre que l'utilisateur appuie sur Entrée ou utilise Ctrl+C pour interrompre
}






# Fonction 4 : Filtrage de connexion
function filtrage_connexion {
    echo -e "${YELLOW}Application des règles de filtrage des connexions...${NC}"
    iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
    echo -e "${GREEN}Filtrage de connexion appliqué.${NC}"
}

# Fonction 5 : Protection des services
function protection_ssh {
    # Demander à l'utilisateur de saisir le port SSH
    read -p "Entrez le port SSH (par défaut 22) : " port_ssh
    port_ssh=${port_ssh:-22}  # Si aucun port n'est entré, on utilise le port 22 par défaut

    # Afficher un menu pour choisir l'action
    echo -e "${YELLOW}Protection SSH : Choisissez une option:${NC}"
    echo -e "1. Démarrer SSH"
    echo -e "2. Arrêter SSH"
    echo -e "3. Voir le port du SSH"
    echo -e "4. Autoriser des IPs spécifiques et bloquer les autres (Port $port_ssh)"
    echo -e "5. Quitter"

    # Demander à l'utilisateur de choisir une option
    read -p "Entrez votre choix (1-5): " choix

    case $choix in
        1)
            # Démarrer SSH
            echo -e "${YELLOW}Démarrage du service SSH...${NC}"
            service ssh start  # Démarre le service SSH
            echo -e "${GREEN}SSH a été démarré.${NC}"
            ;;
        2)
            # Arrêter SSH
            echo -e "${YELLOW}Arrêt du service SSH...${NC}"
            service ssh stop  # Arrête le service SSH
            echo -e "${GREEN}SSH a été arrêté.${NC}"
            ;;
        3)
            # Voir le port utilisé par SSH
            echo -e "${YELLOW}Affichage du port utilisé par SSH...${NC}"
            # Utiliser ss pour trouver le port SSH en écoute
            ss -tuln | grep ":$port_ssh "  # Recherche du port spécifié
            # Alternative avec netstat
            # netstat -tuln | grep ":$port_ssh "
            ;;
        4)
            # Autoriser des IPs spécifiques et bloquer les autres
            echo -e "${YELLOW}Entrez les adresses IP autorisées (séparées par des virgules) :${NC}"
            read -p "IPs autorisées : " ip_list

            # Supprimer les espaces et séparer par des virgules si nécessaire
            ip_list=$(echo $ip_list | tr -s ' ' ',')

            # Autoriser d'abord les IPs spécifiées
            echo -e "${YELLOW}Mise à jour des règles de filtrage...${NC}"
            
            IFS=',' read -ra ips <<< "$ip_list"
            for ip in "${ips[@]}"; do
                iptables -A INPUT -p tcp --dport "$port_ssh" -s "$ip" -j ACCEPT
                echo -e "${GREEN}Connexion SSH autorisée depuis $ip.${NC}"
            done

            # Bloquer toutes les connexions SSH restantes
            iptables -A INPUT -p tcp --dport "$port_ssh" -j DROP
            echo -e "${GREEN}Toutes les autres connexions SSH sont bloquées.${NC}"

            ;;
        5)
            # Quitter le menu
            echo -e "${GREEN}Quitter le menu de protection SSH.${NC}"
            return
            ;;
        *)
            # Option invalide
            echo -e "${RED}Choix invalide. Veuillez entrer un nombre entre 1 et 5.${NC}"
            ;;
    esac

    # Retourner au menu principal
    protection_ssh
}



# Fonction 6 : Protection FTP
function protection_ftp {
    echo -e "${YELLOW}Activation de la protection FTP...${NC}"
    iptables -A INPUT -p tcp --dport 21 -j ACCEPT
    echo -e "${GREEN}Protection FTP activée.${NC}"
}

# Fonction 7 : Protection DNS
function protection_dns {
    echo -e "${YELLOW}Activation de la protection DNS...${NC}"
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    echo -e "${GREEN}Protection DNS activée.${NC}"
}

# Fonction 8 : Protection DHCP
function protection_dhcp {
    echo -e "${YELLOW}Activation de la protection DHCP...${NC}"
    iptables -A INPUT -p udp --dport 67:68 -j ACCEPT
    echo -e "${GREEN}Protection DHCP activée.${NC}"
}

# Fonction 9 : Protection SynFlood
function protection_synflood {
    echo -e "${YELLOW}Activation de la protection SynFlood...${NC}"
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    echo -e "${GREEN}Protection SynFlood activée.${NC}"
}

# Fonction 10 : Protection HTTP
function protection_http {
    echo -e "${YELLOW}Activation de la protection HTTP...${NC}"
    iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
    echo -e "${GREEN}Protection HTTP activée.${NC}"
}

# Fonction 11 : Configuration de la chaîne INPUT
function config_input {
    echo -e "${YELLOW}Configuration de la chaîne INPUT...${NC}"
    iptables -P INPUT DROP
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    echo -e "${GREEN}Chaîne INPUT configurée.${NC}"
}

# Fonction 12 : Configuration de la chaîne OUTPUT
function config_output {
    echo -e "${YELLOW}Configuration de la chaîne OUTPUT...${NC}"
    iptables -P OUTPUT ACCEPT
    echo -e "${GREEN}Chaîne OUTPUT configurée.${NC}"
}

# Fonction 13 : Configuration de la chaîne FORWARD
function config_forward {
    echo -e "${YELLOW}Configuration de la chaîne FORWARD...${NC}"
    iptables -P FORWARD DROP
    echo -e "${GREEN}Chaîne FORWARD configurée.${NC}"
}

# Fonction 14 : Filtrage IP
function filtrage_ip {
    echo -e "${YELLOW}Application du filtrage IP...${NC}"
    iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT  # Exemple de plage IP
    echo -e "${GREEN}Filtrage IP appliqué.${NC}"
}

# Fonction 15 : Configuration des logs
function config_logs {
    echo -e "${YELLOW}Configuration de la journalisation des paquets...${NC}"
    iptables -A INPUT -j LOG --log-prefix "Paquet bloqué : "
    echo -e "${GREEN}Logs configurés.${NC}"
}

# Fonction 16 : Afficher les tables iptables
function afficher_tables {
    echo -e "${YELLOW}Affichage des règles iptables...${NC}"
    iptables -L -v -n
}

# Fonction 17 : Nettoyer toutes les règles
function nettoyer_regles {
    echo -e "${YELLOW}Nettoyage de toutes les règles iptables...${NC}"
    iptables -F
    iptables -X
    echo -e "${GREEN}Règles iptables nettoyées.${NC}"
}

# Fonction 18 : Sauvegarder les règles
function sauvegarder_regles {
    echo -e "${YELLOW}Sauvegarde des règles iptables...${NC}"
    iptables-save > /etc/iptables/rules.v4
    echo -e "${GREEN}Règles sauvegardées.${NC}"
}

# Fonction 19 : Restaurer les règles
function restaurer_regles {
    echo -e "${YELLOW}Restauration des règles iptables...${NC}"
    iptables-restore < /etc/iptables/rules.v4
    echo -e "${GREEN}Règles restaurées.${NC}"
}

# Fonction 20 : Quitter le script
function quitter {
    echo -e "${RED}Au revoir !${NC}"
    exit 0
}

# Menu principal
function afficher_menu {
    echo -e "${BLUE}Choisissez une option :${NC}"
    echo -e "${WHITE}1.${NC} ${GREEN}Bloquer les ports inutiles${NC}"
    echo -e "${WHITE}2.${NC} ${GREEN}Bloquer une adresse IP suspecte${NC}"
    echo -e "${WHITE}3.${NC} ${GREEN}Process Monitoring...${NC}"
    echo -e "${WHITE}4.${NC} ${GREEN}Filtrage de connexion${NC}"
    echo -e "${WHITE}5.${NC} ${GREEN}Protection ssh${NC}"
    echo -e "${WHITE}6.${NC} ${GREEN}Protection FTP${NC}"
    echo -e "${WHITE}7.${NC} ${GREEN}Protection DNS${NC}"
    echo -e "${WHITE}8.${NC} ${GREEN}Protection DHCP${NC}"
    echo -e "${WHITE}9.${NC} ${GREEN}Protection HTTP${NC}"
    echo -e "${WHITE}10.${NC} ${GREEN}Protection SynFlood${NC}"
    echo -e "${WHITE}11.${NC} ${GREEN}Configuration de la chaîne INPUT${NC}"
    echo -e "${WHITE}12.${NC} ${GREEN}Configuration de la chaîne OUTPUT${NC}"
    echo -e "${WHITE}13.${NC} ${GREEN}Configuration de la chaîne FORWARD${NC}"
    echo -e "${WHITE}14.${NC} ${GREEN}Filtrage IP${NC}"
    echo -e "${WHITE}15.${NC} ${GREEN}Configuration des logs${NC}"
    echo -e "${WHITE}16.${NC} ${GREEN}Afficher les tables iptables${NC}"
    echo -e "${WHITE}17.${NC} ${GREEN}Nettoyer toutes les règles${NC}"
    echo -e "${WHITE}18.${NC} ${GREEN}Sauvegarder les règles${NC}"
    echo -e "${WHITE}19.${NC} ${GREEN}Restaurer les règles${NC}"
    echo -e "${WHITE}20.${NC} ${RED}Quitter${NC}"
}

# Fonction pour exécuter le choix de l'utilisateur
function executer_choix {
    read -p "Entrez votre choix (1-20): " choix
    
    case $choix in
        1) bloquer_ports_inutiles ;;
        2) bloquer_ip_suspecte ;;
        3) processus ;;
        4) filtrage_connexion ;;
        5) protection_ssh ;;
        6) protection_ftp ;;
        7) protection_dns ;;
        8) protection_dhcp ;;
        9) protection_http ;;
        10) protection_synflood ;;
        11) config_input ;;
        12) config_output ;;
        13) config_forward ;;
        14) filtrage_ip ;;
        15) config_logs ;;
        16) afficher_tables ;;
        17) nettoyer_regles ;;
        18) sauvegarder_regles ;;
        19) restaurer_regles ;;
        20) quitter ;;
        *) echo -e "${RED}Choix invalide. Veuillez entrer un numéro entre 1 et 20.${NC}" ;;
    esac
}

# Script principal
while true; do
    afficher_menu
    executer_choix
done
