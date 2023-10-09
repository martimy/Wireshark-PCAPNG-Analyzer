import streamlit as st
# from scapy.all import PcapReader # rdpcap
from scapy.all import *
import matplotlib.pyplot as plt

def get_protocol_names(packet):
    # Traverse through the packet's layers and yield protocol names
    current_layer = packet
    while current_layer:
        yield current_layer.name
        current_layer = current_layer.payload if current_layer.payload else None

def get_counts(packets, count=100):
    ip_protocols = {}
    transport_protocols = {}
    app_protocols = {}

    for i, pkt in enumerate(packets):
        protocols = list(get_protocol_names(pkt))
        if "Ethernet" in protocols:
            proto = protocols[1]
            ip_protocols.setdefault(proto, 0)
            ip_protocols[proto] += 1
            if proto in ["IP", "IPv6"] and len(protocols) >= 3:
                proto = protocols[2]
                transport_protocols.setdefault(proto, 0)
                transport_protocols[proto] += 1
                if len(protocols) >= 4:
                    proto = "UNKNOWN" if protocols[3] in ["Raw", "Padding"] else protocols[3]
                    app_protocols.setdefault(proto, 0)
                    app_protocols[proto] += 1          
        if i > count:
            break
    return ip_protocols, transport_protocols, app_protocols

# Streamlit UI
st.title("Wireshark File Analyzer")

# Upload Wireshark file
uploaded_file = st.file_uploader("Upload a Wireshark file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Read the uploaded file using Scapy
    packets = rdpcap(uploaded_file)
    num_packets = len(packets)

    if num_packets > 100:
        count = st.slider("Packets", min_value=100, max_value=min(num_packets, 5000), step=100)
    else:
        count = num_packets

    # Analyze and display packet details
    st.subheader("Packet Details:")
    
    l2, l3, l4  = get_counts(packets, count=count)

    # Pie chart, where the slices will be ordered and plotted counter-clockwise:
    fig1, (ax1, ax2, ax3) = plt.subplots(1, 3)
    ax1.pie(l2.values(), labels=l2.keys())
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    # st.pyplot(fig1)

    ax2.pie(l3.values(), labels=l3.keys())
    ax2.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    # st.pyplot(fig1)

    ax3.pie(l4.values(), labels=l4.keys())
    ax3.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    st.pyplot(fig1)

else:
    st.warning("Upload a file")
