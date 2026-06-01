import re 
import json 
import time
import requests 
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv
import os

# load th API key from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

#settings
FIREWALL_LOG = "logs/firewall.log"
DNS_LOG = "logs/dns.log"
OUTPUT_FILE = "output/alert.json"