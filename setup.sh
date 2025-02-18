#!/bin/bash

echo apt update

# Installation de python sur Ubuntu/Débian et CentOS
echo "Installantion de python..."
sudo apt install python3
sudo yum install python3

# Installation de Nmap avec sudo
echo "Installation de Nmap..."
sudo apt install -y nmap


# Installation de Dirb avec sudo
echo "Installation de Dirb..."
sudo apt install -y dirb

# Installation de Nikto avec sudo
echo "Installation de Nikto..."
sudo apt install -y nikto

# Installation de Hydra avec sudo
echo "Installation de Hydra..."
sudo apt install -y hydra

echo "Installation de reportlab.."
sudo apt install python3-reportlab


pip install reportlab
pip install os
pip install sys
