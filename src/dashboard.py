import glob
import json
import os
import re

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

# Graphs live in <repo>/outputs, but streamlit resolves relative paths against
# the working directory. Look there first, then fall back to the repository
# root inferred from this file, so the app works from any directory.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEARCH_ROOTS = [os.getcwd(), REPO_ROOT]

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

# Flags a generator may use to mark the vulnerability a graph is centred on.
CENTRAL_FLAGS = ("is_central", "is_anchor", "is_central_node")


# --- 2. Graph selection ---
st.sidebar.header("Graph selection")

available, base_dir = [], os.getcwd()
for root in SEARCH_ROOTS:
    hits = sorted(glob.glob(os.path.join(root, "outputs", "*", "*", "run_*.json")))
    default_graph = os.path.join(root, DEFAULT_GRAPH_FILE)
    if os.path.exists(default_graph):
        hits.append(default_graph)
    if hits:
        available, base_dir = hits, root
        break

if available:
    graph_file = st.sidebar.selectbox(
        "Attack graph",
        available,
        format_func=lambda p: os.path.relpath(p, base_dir),
    )
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

# Derive a caption from the trailing path components, e.g.
# .../outputs/log4j/proposed/run_1.json
parts = os.path.normpath(graph_file).split(os.sep)
if len(parts) >= 4 and parts[-4] == "outputs":
    st.caption(
        f"Dataset: **{parts[-3]}**  |  Method: **{parts[-2]}**  |  {parts[-1]}"
    )
else:
    st.caption(os.path.basename(graph_file))


# --- 3. Load data ---
st.subheader("1. Data Loading")
try:
    with open(graph_file, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
except (OSError, json.JSONDecodeError) as e:
    st.error(f"Error loading '{graph_file}': {e}")
    st.stop()

raw_nodes = graph_data.get("nodes", [])
# The four prompting methods emit "links" with source/target. The RAG baseline
# emits "edges" with from/to, so accept both spellings.
raw_links = graph_data.get("links")
if not raw_links:
    raw_links = graph_data.get("edges", [])
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
# Built directly rather than through nx.node_link_graph, whose keyword for the
# link list changed across networkx versions (`link` before 3.4, `edges` from
# 3.6) and which silently falls back to the array index when a node record has
# no `id`.
try:
    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})
    for link in raw_links:
        source = link.get("source", link.get("from"))
        target = link.get("target", link.get("to"))
        if source is None or target is None:
            continue
        G.add_edge(
            source,
            target,
            **{
                k: v for k, v in link.items()
                if k not in ("source", "target", "from", "to")
            },
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

    # RAG graphs identify nodes as N01, N02 … and carry the CVE inside `label`,
    # so surface the CVE when one is present and fall back to the label text.
    label = data.get("cve_id")
    if not label:
        text = data.get("label") or str(n)
        match = CVE_PATTERN.search(text)
        label = match.group(0) if match else text
    if len(label) > 32:
        label = label[:29] + "…"

    if data:
        lines = [f"ID: {n}"]
        if data.get("label") and data.get("label") != label:
            lines.append(f"Name: {data['label']}")
        lines.append(f"Type: {data.get('vulnerability_type', 'N/A')}")
        if data.get("precondition"):
            lines.append(f"Precondition: {data['precondition']}")
        if data.get("postcondition"):
            lines.append(f"Postcondition: {data['postcondition']}")
        lines.append(f"Description: {data.get('description', 'N/A')}")
        title = "\n".join(lines)
    else:
        title = f"ID: {n}"

    value = G.degree(n) * 5 + 10
    color = "#6E9BFF"

    if n == central:
        color = "#FF4136"
        value = max(value, 50)

    net.add_node(str(n), label=label, title=title, shape="ellipse",
                 color=color, value=value)

for u, v, data in G.edges(data=True):
    # Generated links do not agree on which key holds the justification text:
    # description, reason, evidence, and label all occur across the outputs.
    edge_title = (
        data.get("description")
        or data.get("reason")
        or data.get("evidence")
        or data.get("label")
        or "N/A"
    )
    net.add_edge(str(u), str(v), label="", title=edge_title, arrows="to")

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
      "size": 14,
      "align": "middle",
      "strokeWidth": 0
    },
    "color": {
      "color": "#2B7CE9",
      "highlight": "#0055FF",
      "hover": "#0055FF"
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
net.set_options(options_json)

# --- 7. Render the graph in Streamlit ---
# pyvis's save_graph() opens the output file without specifying an encoding, so
# it fails on non-UTF-8 locales (cp949, for example) because the bundled vis.js
# contains characters outside that codec. Generate the HTML in memory instead,
# which also avoids leaving an artifact in the working tree.
try:
    try:
        source_code = net.generate_html(notebook=False)
    except TypeError:  # older pyvis without the notebook keyword
        source_code = net.generate_html()
    components.html(source_code, height=770, scrolling=False)
except Exception as e:
    st.error(f"Error rendering the Pyvis graph: {e}")


# --- 8. Display raw data ---
st.subheader("3. Raw Graph Data (JSON)")
with st.expander(f"View {os.path.basename(graph_file)} contents"):
    st.json(graph_data)