"""Interactive HTML network topology visualizer using pyvis + networkx."""

import json
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.base_module import Device, FuzzResult


class TopologyVisualizer:
    """Builds an interactive HTML network map from discovery seeds and fuzz results.

    Usage:
        viz = TopologyVisualizer()
        viz.add_device(device)          # once per discovered device
        viz.add_edge(src, dst, proto)   # once per observed src↔dst flow
        viz.add_result(fuzz_result)     # annotates nodes with anomaly/crash counts
        viz.render("output/")           # writes topology.html + topology.graphml
    """

    _PROTOCOL_COLORS = {
        "modbus":     "#e74c3c",
        "opcua":      "#3498db",
        "dnp3":       "#2ecc71",
        "ethernetip": "#f39c12",
        "bacnet":     "#9b59b6",
        "iec104":     "#1abc9c",
        "iec61850":   "#e67e22",
    }

    _COLOR_CRASH   = "#ff2222"
    _COLOR_ANOMALY = "#ff9900"
    _COLOR_DEFAULT = "#95a5a6"

    def __init__(self):
        # node_id -> {label, protocol, device_type, anomalies, crashes}
        self._nodes: dict[str, dict] = {}
        # Normalized key (min, max, proto) merges A→B and B→A into one link
        self._edge_counts: dict[tuple, int] = defaultdict(int)

    def add_device(self, device: "Device") -> None:
        key = device.ip or device.mac or "unknown"
        if key not in self._nodes:
            self._nodes[key] = {
                "label": key,
                "protocol": device.protocol,
                "device_type": device.device_type,
                "anomalies": 0,
                "crashes": 0,
            }

    def add_edge(self, src: str, dst: str, protocol: str) -> None:
        # Normalize direction: A↔B and B↔A accumulate into the same counter
        key = (min(src, dst), max(src, dst), protocol)
        self._edge_counts[key] += 1

    def add_result(self, result: "FuzzResult") -> None:
        """Annotate the target node with anomaly/crash data from a fuzz case."""
        target_ip = result.target.rsplit(":", 1)[0]
        node = self._nodes.get(target_ip)
        if node is None:
            return
        if result.anomaly:
            node["anomalies"] += 1
        if result.crash_indicator:
            node["crashes"] += 1

    def _build_legend_html(self) -> str:
        rows = []
        for proto, color in self._PROTOCOL_COLORS.items():
            rows.append(
                f'<div><span style="display:inline-block;width:14px;height:14px;'
                f'border-radius:50%;background:{color};vertical-align:middle;'
                f'margin-right:6px;"></span>{proto.upper()}</div>'
            )
        rows.append(
            '<div style="margin-top:6px;border-top:1px solid #555;padding-top:6px;">'
            f'<span style="display:inline-block;width:14px;height:14px;border-radius:50%;'
            f'background:{self._COLOR_ANOMALY};vertical-align:middle;margin-right:6px;'
            f'"></span>Anomaly detected</div>'
        )
        rows.append(
            f'<div><span style="display:inline-block;width:14px;height:14px;border-radius:50%;'
            f'background:{self._COLOR_CRASH};vertical-align:middle;margin-right:6px;'
            f'"></span>Crash indicator</div>'
        )
        inner = "\n    ".join(rows)
        return (
            '<div style="position:fixed;bottom:20px;right:20px;background:#2d2d44;'
            'border:1px solid #555;border-radius:8px;padding:14px 18px;'
            'font-family:monospace;font-size:13px;color:#fff;z-index:9999;">\n'
            '  <div style="font-weight:bold;margin-bottom:8px;border-bottom:1px solid #555;'
            'padding-bottom:4px;">ICS Protocol Legend</div>\n'
            '  <div style="display:flex;flex-direction:column;gap:4px;">\n'
            f'    {inner}\n'
            '  </div>\n'
            '</div>'
        )

    def render(self, output_dir: str) -> Path:
        """Generate topology.html and topology.graphml in output_dir.

        Requires: pip install networkx pyvis
        """
        try:
            import networkx as nx
            from pyvis.network import Network
        except ImportError:
            raise RuntimeError("networkx and pyvis are required: pip install networkx pyvis")

        # Undirected graph — edges are already normalized (bidirectional merged)
        G = nx.Graph()

        for node_id, attrs in self._nodes.items():
            if attrs["crashes"] > 0:
                color = self._COLOR_CRASH
            elif attrs["anomalies"] > 0:
                color = self._COLOR_ANOMALY
            else:
                color = self._PROTOCOL_COLORS.get(attrs["protocol"], self._COLOR_DEFAULT)

            G.add_node(
                node_id,
                label=node_id,
                color=color,
                title=(
                    f"{attrs['protocol'].upper()} — {attrs['device_type']}\n"
                    f"Anomalies: {attrs['anomalies']}  Crashes: {attrs['crashes']}"
                ),
                size=20 + min(attrs["crashes"] * 5, 30),
            )

        for (src, dst, proto), count in self._edge_counts.items():
            if src in G.nodes and dst in G.nodes:
                G.add_edge(
                    src, dst,
                    label=proto.upper(),
                    title=f"{count} packets observed",
                    width=max(1, min(count // 10 + 1, 8)),
                )

        net = Network(
            height="800px",
            width="100%",
            directed=False,
            bgcolor="#1a1a2e",
            font_color="#ffffff",
        )
        net.from_nx(G)
        net.set_options(json.dumps({
            "physics": {
                "barnesHut": {"gravitationalConstant": -5000},
                "stabilization": {"iterations": 200},
            },
            "interaction": {"hover": True, "tooltipDelay": 100},
            "edges": {"smooth": {"type": "dynamic"}},
        }))

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # HTML with injected legend panel
        html_path = out / "topology.html"
        net.save_graph(str(html_path))
        raw = html_path.read_text(encoding="utf-8")
        html_path.write_text(
            raw.replace("</body>", self._build_legend_html() + "\n</body>"),
            encoding="utf-8",
        )
        print(f"[viz] Interactive topology → {html_path}")

        # GraphML for Gephi / yEd
        graphml_path = out / "topology.graphml"
        nx.write_graphml(G, str(graphml_path))
        print(f"[viz] GraphML export       → {graphml_path}")

        return html_path
