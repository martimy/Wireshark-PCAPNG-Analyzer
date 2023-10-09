from scapy.all import *  # PcapReader # rdpcap
import streamlit as st
import matplotlib.pyplot as plt
import plotly.express as px
import pandas as pd


def trim_labels(labels, LEN=12):
    trimmed_labels = []
    for label in labels:
        if len(label) > LEN:
            print(label)
            trimmed_label = label[:LEN] + "..."
        else:
            trimmed_label = label
        trimmed_labels.append(trimmed_label)
    return trimmed_labels


def get_protocol_names(packet):
    """
    Traverse through the packet's layers and yield protocol names
    """
    current_layer = packet
    while current_layer:
        yield current_layer.name
        current_layer = current_layer.payload if current_layer.payload else None


def get_counts(packets, count=100):
    """
    Count multiple packet stats
    """

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
                    proto = (
                        "Unspecified"
                        if protocols[3] in ["Raw", "Padding"]
                        else protocols[3]
                    )
                    app_protocols.setdefault(proto, 0)
                    app_protocols[proto] += 1
        if i > count:
            break
    return ip_protocols, transport_protocols, app_protocols


@st.cache_data
def read_packets(file):
    return rdpcap(file)


# Streamlit UI
st.title("Wireshark File Analyzer")

# Upload Wireshark file
uploaded_file = st.file_uploader("Upload a Wireshark file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Read the uploaded file using Scapy
    packets = read_packets(uploaded_file)
    num_packets = len(packets)

    if num_packets > 100:
        count = st.slider(
            "Packets", min_value=100, max_value=min(num_packets, 5000), step=100
        )
    else:
        count = num_packets

    # Analyze and display packet details
    st.subheader("Protocols:")

    l2, l3, l4 = get_counts(packets, count=count)

    row_0 = st.columns([1, 1])
    with row_0[0]:
        data = {"protocols": trim_labels(l2.keys()), "packets": l2.values()}
        df = pd.DataFrame(data)
        fig = px.pie(df, values=data["packets"], names=data["protocols"], height=350)
        st.plotly_chart(fig, use_container_width=True)
    with row_0[1]:
        data = {"protocols": trim_labels(l3.keys()), "packets": l3.values()}
        df = pd.DataFrame(data)
        fig = px.pie(df, values=data["packets"], names=data["protocols"], height=350)
        st.plotly_chart(fig, use_container_width=True)

    row_1 = st.columns([1, 1])
    with row_1[0]:
        data = {"protocols": trim_labels(l4.keys()), "packets": l4.values()}
        df = pd.DataFrame(data)
        fig = px.pie(df, values=data["packets"], names=data["protocols"], height=350)
        st.plotly_chart(fig, use_container_width=True)


else:
    st.warning("Upload a file")
