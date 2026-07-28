import glob
import json
import os
import tempfile

import networkx as nx
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

# --- 1. Page setup ---
st.set_page_config(layout="wide")
st.title("🛡️ Attack Graph Visualization")

# Default output path of save_final_graph in server.py, so a graph produced by
# a pipeline run is picked up from the working directory without extra setup.
DEFAULT_GRAPH_FILE = "attack_graph.json"

# Relationship types defined by the framework, with a colour for each so the
# taxonomy is visible in the rendered graph.
RELATION_COLORS = {
    "incomplete_fix": "#D9534F",
    "precondition_met": "#2B7CE9",
    "similar_attack_pattern": "#5CB85C",
    "reconnaissance": "#F0AD4E",
}
UNKNOWN_RELATION_COLOR = "#999999"

# Flags a generator may use to mark the vulnerability a graph is centred on.
CENTRAL_FLAGS = ("is_central", "is_anchor", "is_central_node")


# --- 2. Graph selection ---
st.sidebar.header("Graph selection")

available = sorted(glob.glob(os.path.join("outputs", "*", "*", "run_*.json")))
if os.path.exists(DEFAULT_GRAPH_FILE):
    available.append(DEFAULT_GRAPH_FILE)

if available:
    graph_file = st.sidebar.selectbox("Attack graph", available)
else:
    st.sidebar.info(
        "No graphs found under `outputs/`. Run this app from the repository "
        "root, or enter a path below. A pipeline run writes its final graph "
        f"to `{DEFAULT_GRAPH_FILE}` in the working directory by default."
    )
    graph_file = st.sidebar.text_input("Path to graph JSON", DEFAULT_GRAPH_FILE)

if not graph_file or not os.path.exists(graph_file):
    st.error(f"Cannot find file '{graph_file}'.")
    st.warning(
        "Run this app from the repository root so that the generated graphs "
        "under `outputs/` are discoverable, or enter a path to a graph JSON "
        "file in the sidebar."
    )
    st.stop()

# Derive a caption from the path, e.g. outputs/log4j/proposed/run_1.json
parts = os.path.normpath(graph_file).split(os.sep)
if len(parts) >= 4 and parts[0] == "outputs":
    st.caption(f"Dataset: **{parts[1]}**  |  Method: **{parts[2]}**  |  {parts[3]}")
else:
    st.caption(graph_file)


# --- 3. Load data ---
st.subheader("1. Data Loading")
try:
    with open(graph_file, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
except (OSError, json.JSONDecodeError) as e:
    st.error(f"Error loading '{graph_file}': {e}")
    st.stop()

raw_nodes = graph_data.get("nodes", [])
raw_links = graph_data.get("links", [])
st.info(
    f"✅ Loaded '{graph_file}' "
    f"(Nodes: {len(raw_nodes)}, Links: {len(raw_links)})"
)


# --- 4. Normalize nodes ---
# Generated graphs do not share a single node schema. Some records carry
# `cve_id`, some carry `id`, and some nest their attributes under `data` or
# `properties`. In every case the identifier is the CVE string that the links
# reference, so resolve it to a consistent `id` before building the graph.
# Without this, networkx falls back to the array index and every link creates a
# second, attribute-less copy of its endpoints.
def normalize_node(node):
    if isinstance(node, str):
        node = {"cve_id": node}
    if not isinstance(node, dict):
        return None

    flat = dict(node)
    for nested_key in ("data", "properties"):
        nested = flat.pop(nested_key, None)
        if isinstance(nested, dict):
            for k, v in nested.items():
                flat.setdefault(k, v)

    node_id = flat.get("cve_id") or flat.get("id") or flat.get("name")
    if not node_id:
        return None

    flat["id"] = node_id
    flat.setdefault("cve_id", node_id)
    return flat


nodes, skipped = [], 0
for node in raw_nodes:
    normalized = normalize_node(node)
    if normalized is None:
        skipped += 1
    else:
        nodes.append(normalized)

if skipped:
    st.warning(f"⚠️ Skipped {skipped} node(s) with no usable identifier.")


# --- 5. Create NetworkX graph ---
try:
    # `edges="links"` is required: networkx 3.6 renamed the parameter from
    # `link` and changed the default key to "edges".
    G = nx.node_link_graph(
        {"nodes": nodes, "links": raw_links},
        directed=True,
        multigraph=False,
        edges="links",
    )
    st.success(
        f"NetworkX graph created "
        f"({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)."
    )
except Exception as e:
    st.error(f"Error creating NetworkX graph: {e}")
    st.stop()

orphans = [n for n in G.nodes() if not G.nodes[n]]
if orphans:
    st.warning(
        f"⚠️ {len(orphans)} node(s) appear only in links and carry no "
        f"attributes: {', '.join(map(str, orphans[:5]))}"
        + (" …" if len(orphans) > 5 else "")
    )


# --- 6. Interactive graph visualization using Pyvis ---
st.subheader("2. Interactive Graph (Pyvis)")

net = Network(
    height="750px",
    width="100%",
    bgcolor="#ffffff",
    font_color="black",
    notebook=False,
    directed=True,
    # Embed the vis.js assets in the generated HTML. The default ("local")
    # copies them into a lib/ directory in the working tree, and "remote"
    # would require network access to view the graph.
    cdn_resources="in_line",
)

# Pick the vulnerability to highlight from the data rather than hard-coding a
# single CVE, so the highlight works on every dataset.
central = next(
    (n for n in G.nodes() if any(G.nodes[n].get(f) for f in CENTRAL_FLAGS)),
    None,
)
if central is None and G.number_of_nodes():
    central = max(G.nodes(), key=lambda n: G.degree(n))

for n in G.nodes():
    data = G.nodes[n]

    if data:
        title = (
            f"ID: {n}\n"
            f"Type: {data.get('vulnerability_type', 'N/A')}\n"
            f"Description: {data.get('description', 'N/A')}\n"
        )
    else:
        title = f"ID: {n}"

    value = G.degree(n) * 5 + 10
    color = "#6E9BFF"

    if n == central:
        color = "#FF4136"
        value = max(value, 50)

    net.add_node(str(n), label=str(n), title=title, shape="ellipse",
                 color=color, value=value)

for u, v, data in G.edges(data=True):
    # Generated links do not agree on which key holds the justification text:
    # `description`, `reason`, and `evidence` all occur across the outputs.
    edge_title = (
        data.get("description")
        or data.get("reason")
        or data.get("evidence")
        or "N/A"
    )
    relation = data.get("relation_type", "")
    net.add_edge(
        str(u),
        str(v),
        label=relation,
        title=edge_title,
        arrows="to",
        color=RELATION_COLORS.get(relation, UNKNOWN_RELATION_COLOR),
    )

net.toggle_physics(True)

options_json = """
{
  "nodes": {
    "font": {
      "color": "#000000",
      "size": 14
    },
    "borderWidth": 2
  },
  "edges": {
    "font": {
      "color": "#000000",
      "size": 12,
      "align": "middle",
      "strokeWidth": 3,
      "strokeColor": "#ffffff"
    },
    "arrows": {
      "to": { "enabled": true, "scaleFactor": 0.5 }
    },
    "smooth": {
      "type": "continuous"
    }
  },
  "physics": {
    "barnesHut": {
      "gravitationalConstant": -1000,
      "centralGravity": 0.1,
      "springLength": 100,
      "springConstant": 0.05
    },
    "minVelocity": 0.75,
    "solver": "barnesHut"
  }
}
"""
# Edge colours are set per edge from the relationship type, so no global edge
# colour is declared here.
net.set_options(options_json)

st.sidebar.header("Relationship types")
for relation, color in RELATION_COLORS.items():
    st.sidebar.markdown(
        f"<span style='color:{color}'>&#9632;</span> `{relation}`",
        unsafe_allow_html=True,
    )
st.sidebar.markdown(
    f"<span style='color:{UNKNOWN_RELATION_COLOR}'>&#9632;</span> "
    "outside the taxonomy",
    unsafe_allow_html=True,
)


# --- 7. Render the graph in Streamlit ---
# pyvis can only render to a file, so write it outside the working tree to
# avoid dropping an artifact into the repository on every run.
try:
    with tempfile.TemporaryDirectory() as tmpdir:
        html_file = os.path.join(tmpdir, "attack_graph_viz.html")
        net.save_graph(html_file)
        with open(html_file, "r", encoding="utf-8") as f:
            source_code = f.read()
    components.html(source_code, height=770, scrolling=False)
except Exception as e:
    st.error(f"Error rendering the Pyvis graph: {e}")


# --- 8. Display raw data ---
st.subheader("3. Raw Graph Data (JSON)")
with st.expander(f"View {os.path.basename(graph_file)} contents"):
    st.json(graph_data)