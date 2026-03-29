import flask
import joblib
import json
import pandas as pd
import logging
from collections import defaultdict
import time
import threading
import numpy as np

app = flask.Flask(__name__)

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the consolidated model
try:
    model_components = joblib.load('nids_model_cpu.pkl')
    scaler = model_components['preprocessor']
    rf = model_components['classifier']
    with open('features.json', 'r') as f:
        feature_columns = json.load(f)['features']
    logging.info("[INFO] Loaded consolidated model.")
except Exception as e:
    logging.error(f"[ERROR] Failed to load model: {e}")
    exit()

# Port to L7 Proto mapping
PORT_TO_L7 = {80: 7.0, 443: 91.0, 53: 17.0, 21: 1.0, 22: 11.0, 23: 10.0, 25: 12.0, 161: 5.0}

# Flow aggregation storage
flows = defaultdict(lambda: {
    'start_time': 0,
    'last_seen': 0,
    'in_bytes': 0,
    'in_pkts': 0,
    'out_bytes': 0,
    'out_pkts': 0,
    'longest_pkt': 0,
    'shortest_pkt': float('inf'),
    'ttl_max': 0,
    'ttl_min': float('inf'),
    'tcp_flags': 0,
    'client_tcp_flags': 0,
    'server_tcp_flags': 0,
    'win_max_in': 0,
    'win_max_out': 0,
    'l7_proto': 0.0
})
flow_lock = threading.Lock()

def cleanup_flows():
    while True:
        time.sleep(30)
        now = time.time()
        with flow_lock:
            stale_keys = [k for k, v in flows.items() if now - v['last_seen'] > 120]
            for k in stale_keys:
                del flows[k]

threading.Thread(target=cleanup_flows, daemon=True).start()

@app.route("/predict", methods=["POST"])
def predict():
    data = {"success": False}
    raw = flask.request.get_json()
    if not raw: return flask.jsonify(data)
    
    src_ip = raw.get("src_ip", "0.0.0.0")
    dst_ip = raw.get("dst_ip", "0.0.0.0")
    src_port = raw.get("src_port", 0)
    dst_port = raw.get("dst_port", 0)
    protocol_num = raw.get("protocol_num", 0)
    
    # Direction-independent flow key
    is_reverse = False
    if (src_ip, src_port) > (dst_ip, dst_port):
        flow_key = (dst_ip, src_ip, dst_port, src_port, protocol_num)
        is_reverse = True
    else:
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_num)
    
    now = time.time()
    with flow_lock:
        flow = flows[flow_key]
        if flow['start_time'] == 0:
            flow['start_time'] = now
            if src_port in PORT_TO_L7: flow['l7_proto'] = PORT_TO_L7[src_port]
            elif dst_port in PORT_TO_L7: flow['l7_proto'] = PORT_TO_L7[dst_port]
        
        flow['last_seen'] = now
        packet_size = raw.get('packet_size', 0)
        ttl = raw.get('ttl', 0)
        tcp_f = raw.get('tcp_flags', 0)
        win = raw.get('window_size', 0)
        
        if not is_reverse:
            flow['in_bytes'] += packet_size
            flow['in_pkts'] += 1
            flow['client_tcp_flags'] |= tcp_f
            flow['win_max_in'] = max(flow['win_max_in'], win)
        else:
            flow['out_bytes'] += packet_size
            flow['out_pkts'] += 1
            flow['server_tcp_flags'] |= tcp_f
            flow['win_max_out'] = max(flow['win_max_out'], win)
        
        flow['longest_pkt'] = max(flow['longest_pkt'], packet_size)
        flow['shortest_pkt'] = min(flow['shortest_pkt'], packet_size)
        flow['ttl_max'] = max(flow['ttl_max'], ttl)
        flow['ttl_min'] = min(flow['ttl_min'], ttl)
        flow['tcp_flags'] |= tcp_f
        
        duration_ms = (now - flow['start_time']) * 1000
        
        features_df = pd.DataFrame(columns=feature_columns)
        features_df.loc[0] = 0

        # Fill features
        features_df['IN_BYTES'] = flow['in_bytes']
        features_df['IN_PKTS'] = flow['in_pkts']
        features_df['OUT_BYTES'] = flow['out_bytes']
        features_df['OUT_PKTS'] = flow['out_pkts']
        features_df['TCP_FLAGS'] = flow['tcp_flags']
        features_df['CLIENT_TCP_FLAGS'] = flow['client_tcp_flags']
        features_df['SERVER_TCP_FLAGS'] = flow['server_tcp_flags']
        features_df['FLOW_DURATION_MILLISECONDS'] = duration_ms
        features_df['DURATION_IN'] = duration_ms
        features_df['MAX_TTL'] = flow['ttl_max']
        features_df['MIN_TTL'] = flow['ttl_min']
        features_df['LONGEST_FLOW_PKT'] = flow['longest_pkt']
        features_df['SHORTEST_FLOW_PKT'] = flow['shortest_pkt']
        features_df['TCP_WIN_MAX_IN'] = flow['win_max_in']
        features_df['TCP_WIN_MAX_OUT'] = flow['win_max_out']

        # Apply log transformation (Match NF-UQ-NIDS-v2 pre-processing)
        continuous = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS', 
                      'DURATION_IN', 'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT', 'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT']
        for col in continuous:
            if col in features_df.columns:
                features_df[col] = np.log1p(features_df[col])

        # Protocols
        p_col = f'PROTOCOL_{protocol_num}.0'
        if p_col in features_df.columns: features_df[p_col] = 1
        l_col = f'L7_PROTO_{flow["l7_proto"]}'
        if l_col in features_df.columns: features_df[l_col] = 1

        try:
            scaled = scaler.transform(features_df)
            is_attack = int(rf.predict(scaled)[0])
            
            # Map to specific attack types
            prediction_int = 0
            if is_attack == 1:
                if protocol_num == 1: prediction_int = 1 # Ping
                elif protocol_num == 6:
                    if dst_port == 80 or src_port == 80: prediction_int = 2 # HTTP
                    else: prediction_int = 4 # Random Port
                elif protocol_num == 17: prediction_int = 5 # UDP Flood
                else: prediction_int = 1
            
            data.update({"prediction": prediction_int, "success": True})
            logging.info(f"Pred: {prediction_int} | {src_ip} -> {dst_ip} | Pkts: {flow['in_pkts']}")
        except Exception as e:
            logging.error(f"[ERROR] Prediction error: {e}")
            data["error"] = str(e)

    return flask.jsonify(data)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
