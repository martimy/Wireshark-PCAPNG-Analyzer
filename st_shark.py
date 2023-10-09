from scapy.all import *  # PcapReader # rdpcap
import streamlit as st
import plotly.express as px
import pandas as pd


def trim_labels(labels, LEN=12):
    trimmed_labels = []
    for label in labels:
        if len(label) > LEN:
            trimmed_label = label[: LEN - 3] + "..."
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


def get_protocol_count(packets, count=100):
    """
    Count multiple packet stats
    """

    net_count = {}
    tcp_count = {}
    app_count = {}
    service_count = {}

    for i, pkt in enumerate(packets):
        protocols = list(get_protocol_names(pkt))
        if "Ethernet" in protocols:
            proto = protocols[1]
            net_count.setdefault(proto, 0)
            net_count[proto] += 1
            if proto in ["IP", "IPv6"] and len(protocols) >= 3:
                proto = protocols[2]
                tcp_count.setdefault(proto, 0)
                tcp_count[proto] += 1

                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    port = min(sport, dport)
                    service = TCP_SERVICES[port] if port in TCP_SERVICES else port
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    port = min(sport, dport)
                    service = UDP_SERVICES[port] if port in UDP_SERVICES else port

                service_count.setdefault(service, 0)
                service_count[service] += 1

                if len(protocols) >= 4:
                    proto = (
                        "Unspecified"
                        if protocols[3] in ["Raw", "Padding"]
                        else protocols[3]
                    )
                    app_count.setdefault(proto, 0)
                    app_count[proto] += 1
        if i > count:
            break
    return {
        "network": net_count,
        "transport": tcp_count,
        "application": app_count,
        "port": service_count,
    }


def get_address_count(packets):

    src_count = {}
    dst_count = {}
    s2d_count = {}

    # Iterate through the packets
    for i, pkt in enumerate(packets):
        if "IP" in pkt:
            # Extract source and destination IP addresses
            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst

            # Update the source IP count
            src_count.setdefault(src_ip, 0)
            src_count[src_ip] += 1

            # Update the destination IP count
            dst_count.setdefault(dst_ip, 0)
            dst_count[dst_ip] += 1

            # Update the conversation count
            s2d = src_ip + " >> " + dst_ip
            s2d_count.setdefault(s2d, 0)
            s2d_count[s2d] += 1

        if i > count:
            break

    return {"src": src_count, "dst": dst_count, "s2d": s2d_count}


def get_top_items(dict_data, count=3):
    # Sort the dictionary by values in descending order
    sorted_by_value = sorted(dict_data.items(), key=lambda x: x[1], reverse=True)

    top_items = {}
    sum_of_other_values = 0

    counter = 0
    for key, value in sorted_by_value:
        if counter < count:
            top_items[key] = value
        else:
            sum_of_other_values += value
        counter += 1
    if sum_of_other_values > 0:
        top_items["other"] = sum_of_other_values
    return top_items


@st.cache_data
def read_packets(file):
    return rdpcap(file)


# Streamlit UI
st.set_page_config(layout="wide")
st.title("Wireshark File Analyzer")

# Upload Wireshark file
uploaded_file = st.sidebar.file_uploader(
    "Upload a Wireshark file", type=["pcap", "pcapng"]
)

if uploaded_file is not None:
    # Read the uploaded file using Scapy
    packets = read_packets(uploaded_file)
    num_packets = len(packets)

    if num_packets > 100:
        count = st.sidebar.slider(
            "Number of Packets to Analyze",
            min_value=100,
            max_value=min(num_packets, 5000),
            step=100,
        )
    else:
        count = num_packets

    proto_counts = get_protocol_count(packets, count=count)

    row_0 = st.columns([1, 1])
    with row_0[0]:
        l2 = proto_counts["network"]
        data = {"protocols": trim_labels(l2.keys()), "packets": l2.values()}
        df = pd.DataFrame(data)
        fig = px.pie(
            df,
            values=data["packets"],
            names=data["protocols"],
            height=400,
            title="Network Protocols",
        )
        st.plotly_chart(fig, use_container_width=True)
    with row_0[1]:
        l3 = proto_counts["transport"]
        data = {"protocols": trim_labels(l3.keys()), "packets": l3.values()}
        df = pd.DataFrame(data)
        fig = px.pie(
            df,
            values=data["packets"],
            names=data["protocols"],
            height=400,
            title="Transport Protocols",
        )
        st.plotly_chart(fig, use_container_width=True)

    # row_1 = st.columns([1, 1])
    # with row_1[0]:
    #     l4 = proto_counts["application"]
    #     data = {"protocols": trim_labels(l4.keys()), "packets": l4.values()}
    #     df = pd.DataFrame(data)
    #     fig = px.pie(
    #         df,
    #         values=data["packets"],
    #         names=data["protocols"],
    #         height=400,
    #         title="Applications",
    #     )
    #     st.plotly_chart(fig, use_container_width=True)
    # with row_1[1]:

    lp = get_top_items(proto_counts["port"], count=10)
    data = {"port": lp.keys(), "count": lp.values()}
    df = pd.DataFrame(data)
    fig = px.pie(
        df,
        values=data["count"],
        names=data["port"],
        height=400,
        title="Services",
    )
    st.plotly_chart(fig, use_container_width=True)

    addr_count = get_address_count(packets)
    top_sources = get_top_items(addr_count["src"])
    top_destinations = get_top_items(addr_count["dst"])
    top_s2d = get_top_items(addr_count["s2d"], count=5)

    row_2 = st.columns([1, 1])
    with row_2[0]:
        data = {"Address": top_sources.keys(), "Count": top_sources.values()}
        df = pd.DataFrame(data)
        fig = px.pie(
            df,
            values=data["Count"],
            names=data["Address"],
            height=400,
            title="Top Sources",
        )
        st.plotly_chart(fig, use_container_width=True)
    with row_2[1]:
        data = {"Address": top_destinations.keys(), "Count": top_destinations.values()}
        df = pd.DataFrame(data)
        fig = px.pie(
            df,
            values=data["Count"],
            names=data["Address"],
            height=400,
            title="Top Destinations",
        )
        st.plotly_chart(fig, use_container_width=True)

    data = {"Address": top_s2d.keys(), "Count": top_s2d.values()}
    df = pd.DataFrame(data)
    fig = px.pie(
        df,
        values=data["Count"],
        names=data["Address"],
        height=400,
        title="Top Conversations",
    )
    st.plotly_chart(fig, use_container_width=True)

else:
    st.warning("Upload a file")
