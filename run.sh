#!/bin/bash
set -e

PCAP=$1

python3 predict_custom_new.py "$PCAP"