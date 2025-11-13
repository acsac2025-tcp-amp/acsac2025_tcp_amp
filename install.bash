#!/bin/bash

sudo apt-get install build-essential -y
sudo apt-get install -y "python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')-venv"
# install corresponding python venv dep


python3 -m venv .
source bin/activate
pip install numpy scapy pandas scikit-learn scipy bs4 requests matplotlib seaborn plotly