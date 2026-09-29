import networkx as nx
import plotly.graph_objects as go
from typing import Dict, Any, List, Tuple

class AttackGraphBuilder:
    """Generates NetworkX graph representations of passive network traffic and correlated attack chains."""
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_flow_event(self, alert_data: Dict[str, Any]):
        """Add nodes and directed edges for a passive flow observation."""
        src_ip = alert_data.get("src_ip", "Unknown")
        dst_ip = alert_data.get("dst_ip", "Unknown")
        threat = alert_data.get("threat", "BENIGN")
        risk = float(alert_data.get("risk_score", 0.0))
        protocol = alert_data.get("protocol", "TCP")
        chain_id = alert_data.get("attack_chain_id", "CHAIN-00000")

        # Source node
        if not self.graph.has_node(src_ip):
            self.graph.add_node(src_ip, type="IP_SOURCE", label=src_ip, risk=risk)
        else:
            self.graph.nodes[src_ip]["risk"] = max(self.graph.nodes[src_ip].get("risk", 0.0), risk)

        # Target node
        if not self.graph.has_node(dst_ip):
            self.graph.add_node(dst_ip, type="IP_TARGET", label=dst_ip, risk=risk)
        else:
            self.graph.nodes[dst_ip]["risk"] = max(self.graph.nodes[dst_ip].get("risk", 0.0), risk)

        # Threat node
        threat_node_id = f"THREAT:{threat}:{chain_id}"
        if threat != "BENIGN":
            self.graph.add_node(
                threat_node_id,
                type="THREAT",
                label=f"{threat} ({risk:.0f})",
                risk=risk,
                threat_type=threat
            )
            # Add edges
            self.graph.add_edge(src_ip, threat_node_id, relation="suspicious_activity", protocol=protocol)
            self.graph.add_edge(threat_node_id, dst_ip, relation="correlated_with", protocol=protocol)
        else:
            self.graph.add_edge(src_ip, dst_ip, relation="communicates_with", protocol=protocol)

    def generate_plotly_figure(self) -> go.Figure:
        """Create interactive Plotly network graph visualization."""
        if len(self.graph.nodes) == 0:
            fig = go.Figure()
            fig.update_layout(title="Attack Graph (Empty)")
            return fig

        pos = nx.spring_layout(self.graph, k=0.5, seed=42)

        edge_x = []
        edge_y = []
        edge_hover = []

        for edge in self.graph.edges(data=True):
            u, v, d = edge
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            rel = d.get("relation", "communicates_with")
            proto = d.get("protocol", "TCP")
            edge_hover.append(f"Relation: {rel} | Protocol: {proto}")

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.5, color="#4A5568"),
            hoverinfo="none",
            mode="lines"
        )

        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []
        node_text = []

        for node in self.graph.nodes(data=True):
            n_id, data = node
            x, y = pos[n_id]
            node_x.append(x)
            node_y.append(y)

            n_type = data.get("type", "IP")
            risk = data.get("risk", 0.0)
            label = data.get("label", n_id)

            if n_type == "THREAT":
                color = "#E53E3E" if risk >= 75 else "#DD6B20"
                size = 28
            elif n_type == "IP_SOURCE":
                color = "#805AD5" if risk < 50 else "#C53030"
                size = 22
            else:
                color = "#3182CE"
                size = 20

            node_colors.append(color)
            node_sizes.append(size)
            node_text.append(f"Node: {label}<br>Type: {n_type}<br>Max Risk: {risk:.1f}")

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode="markers+text",
            hoverinfo="text",
            text=[self.graph.nodes[n].get("label", n) for n in self.graph.nodes],
            textposition="top center",
            hovertext=node_text,
            marker=dict(
                color=node_colors,
                size=node_sizes,
                line=dict(width=2, color="#1A202C")
            )
        )

        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(
            title="SentinelGraph Attack & Topology Graph (Passive Correlated Nodes)",
            title_font_color="#E2E8F0",
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=20, r=20, t=50),
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        return fig
