import pandas as pd
import numpy as np
import joblib
import sys
import subprocess

FLOW_CSV = "extracted_flows.csv"
OUTPUT_CSV = "output.csv"
GOFLOWS_CONFIG = "4tuple_bidi.json"
MODEL_FILE = "model_new.joblib"

def extract_flows(pcap_file):
    subprocess.run([
        "./go-flows", "run",
        "features", GOFLOWS_CONFIG,
        "export", "csv", FLOW_CSV,
        "source", "libpcap", pcap_file
    ], check=True)

def preprocess_ports_data(data):
    known_ports = [20, 21, 22, 23, 25, 53, 80, 110, 443, 465, 587, 993, 995, 1433, 3306]
    
    for port in known_ports:
        data['sourcePort_' + str(port)] = (data['sourceTransportPort'] == port).astype(int)
        data['destinationPort_' + str(port)] = (data['destinationTransportPort'] == port).astype(int)

    return data

def extract_tcp_flag_features(df):
    flag_map = ['F', 'S', 'R', 'P', 'A', 'U', 'E', 'C'] 
    for flag in flag_map:
        df['tcpFlag_' + str(flag)] = df['_tcpFlags'].str.contains(flag).fillna(False).astype(int)
    return df

def calculate_unique_ports_per_source_ip(data):
    unique_ports_per_source_ip = data.groupby('sourceIPAddress')['destinationTransportPort'].nunique()

    unique_ports_per_ip_source_df = unique_ports_per_source_ip.reset_index()
    unique_ports_per_ip_source_df.columns = ['sourceIPAddress', 'uniqueDestinationPorts']

    return unique_ports_per_ip_source_df

def calculate_unique_destination_ips_per_source_ip(data):
    unique_destination_ips_per_source_ip = data.groupby('sourceIPAddress')['destinationIPAddress'].nunique()

    unique_destination_ips_per_source_ip_df = unique_destination_ips_per_source_ip.reset_index()
    unique_destination_ips_per_source_ip_df.columns = ['sourceIPAddress', 'uniqueDestinationIPs']

    return unique_destination_ips_per_source_ip_df


def calculate_total_packet_count(data):
    total_packet_count = data.groupby(['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])['packetTotalCount'].sum()

    total_packet_count_df = total_packet_count.reset_index()
    total_packet_count_df.columns = ['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort', 'packetTotalCountAllFlows']

    return total_packet_count_df


def entropy(series):
    probs = series.value_counts(normalize=True)
    return -np.sum(probs * np.log2(probs))

def calculate_port_entropy_per_source_ip(data):
    port_entropy = data.groupby('sourceIPAddress')['destinationTransportPort'].agg(port_entropy_per_source_ip=entropy)

    port_entropy_df = port_entropy.reset_index()
    port_entropy_df.columns = ['sourceIPAddress', 'portEntropy']
    return port_entropy_df

def compute_time_based_features(data):
    max_time = data.groupby(['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])['flowStartMilliseconds'].max()
    min_time = data.groupby(['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])['flowStartMilliseconds'].min()
    
    total_time_per_flow = (max_time - min_time)
    total_time_per_flow.name = 'totalCommunicationTime'
    
    avg_packets_count = data.groupby(['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])['packetTotalCount'].count() / total_time_per_flow.replace(0, -1)
    avg_packets_count.name = 'avgPackets'
    
    avg_total_packets_count = data.groupby(['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])['packetTotalCount'].sum() / total_time_per_flow.replace(0, -1)
    avg_total_packets_count.name = 'avgTotalPackets'
    
    data = pd.merge(data, total_time_per_flow.reset_index(), how='left', on=['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])
    data = pd.merge(data, avg_packets_count.reset_index(), how='left', on=['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])
    data = pd.merge(data, avg_total_packets_count.reset_index(), how='left', on=['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'])
    
    return data

def perform_feature_engineering(data):
    unique_ports_per_source_ip = calculate_unique_ports_per_source_ip(data)
    unique_destination_ips_per_source_ip = calculate_unique_destination_ips_per_source_ip(data)
    total_packet_count = calculate_total_packet_count(data)
    port_entropy = calculate_port_entropy_per_source_ip(data)

    data = pd.merge(data, unique_ports_per_source_ip, on='sourceIPAddress', how='left')
    data = pd.merge(data, unique_destination_ips_per_source_ip, on='sourceIPAddress', how='left')
    data = pd.merge(data, port_entropy, on='sourceIPAddress', how='left')
    data = pd.merge(data, total_packet_count, on=['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort'], how='left')
   
    return data


def preprocess_data(data):
    data = perform_feature_engineering(data)
    data = compute_time_based_features(data)
    data = preprocess_ports_data(data)
    data = extract_tcp_flag_features(data)

    return data.drop(columns=['sourceIPAddress', 'destinationIPAddress', 'sourceTransportPort', 'destinationTransportPort', 'flowStartMilliseconds', '_tcpFlags'], axis=1)

def run_prediction():
    df = pd.read_csv(FLOW_CSV)
    key_cols = ["flowStartMilliseconds", "sourceIPAddress", "destinationIPAddress", "sourceTransportPort", "destinationTransportPort"]

    X = preprocess_data(df)

    clf = joblib.load(MODEL_FILE)
    #X = X.reindex(columns=clf.feature_names_in_, fill_value=0)

    # Predict
    y_pred = clf.predict(X)

    # Output CSV in required format
    output = df[key_cols].copy()
    output["prediction"] = y_pred
    output.to_csv(OUTPUT_CSV, index=False)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("run command: python3 predict_custom.py <input.pcap>")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    
    extract_flows(pcap_path)
    run_prediction()

