# 1. --- Library Imports ---
import asyncio
import json
import os
import glob
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Set

from mcp.server import FastMCP
import nvdlib

# --- 2. Data Classes ---
@dataclass
class GraphGenerationResult:
    ok: bool = False
    message: str = ""
    output_file: Optional[str] = None
    nodes_count: int = 0
    links_count: int = 0

# Data class for candidate graph load results
@dataclass
class CandidateLoadResult:
    ok: bool = False
    message: str = ""
    candidate_count: int = 0
    candidates: Optional[List[Dict[str, Any]]] = None

@dataclass
class CveTaggedData:
    cve_id: str
    description: str
    product: str
    platform: Optional[str] = None
    affected_version_range: Optional[str] = None  # For 'version'
    vulnerability_type: Optional[str] = None
    precondition: Optional[str] = None
    postcondition: Optional[str] = None

@dataclass
class BulkFetchResult:
    ok: bool = False
    message: str = ""
    output_file: Optional[str] = None
    cves_found: int = 0
    keyword: str = ""

@dataclass
class FileReadResult:
    ok: bool = False
    message: str = ""
    file_path: str = ""
    data: Optional[Any] = None  # JSON content

@dataclass
class FileWriteResult:
    ok: bool = False
    message: str = ""
    output_file: Optional[str] = None

@dataclass
class DirectoryInfo:
    ok: bool = False
    message: str = ""
    current_directory: str = ""
    files_in_directory: List[str] = None

# --- 3. Helper Functions ---
def _parse_nvdlib_cve(result: Any, keyword: str) -> CveTaggedData:
    """Parses an nvdlib.classes.CVE object into our CveTaggedData."""
    description = next(
        (desc.value for desc in result.descriptions if desc.lang == "en"),
        "No description provided."
    )
    return CveTaggedData(
        cve_id=result.id,
        description=description,
        product=keyword,
    )

def _bulk_fetch_workflow_sync(
    keyword: str, output_file: str, search_limit: int
) -> BulkFetchResult:
    """
    Sync helper to perform the nvdlib keyword search and save the results.
    """
    try:
        logging.info(f"Starting nvdlib search for '{keyword}' with limit {search_limit}...")
        results = nvdlib.searchCVE(keywordSearch=keyword, limit=search_limit)

        if not results:
            return BulkFetchResult(
                ok=True,
                message=f"No CVEs found for keyword: {keyword}",
                keyword=keyword,
                cves_found=0
            )

        print(f"Found {len(results)} CVEs. Parsing and tagging...")
        all_cve_data: List[CveTaggedData] = []
        for res in results:
            all_cve_data.append(_parse_nvdlib_cve(res, keyword))

        data_to_save = [asdict(cve) for cve in all_cve_data]
        abs_output_path = os.path.abspath(output_file)

        with open(abs_output_path, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=2, ensure_ascii=False)

        return BulkFetchResult(
            ok=True,
            message=f"Successfully fetched and saved {len(all_cve_data)} CVEs.",
            output_file=abs_output_path,
            cves_found=len(all_cve_data),
            keyword=keyword
        )

    except Exception as e:
        return BulkFetchResult(
            ok=False,
            message=f"nvdlib bulk search failed: {e}",
            keyword=keyword
        )

# --- 4. Graph Generation Helper (V4 - LOGIC FIXED) ---
def _save_graph_json_sync(
    graph_data: Dict[str, Any],
    output_file: str
) -> GraphGenerationResult:
    """
    Sync helper to save a graph JSON object to a file.
    Creates directories if they don't exist.
    """
    try:
        abs_output_path = os.path.abspath(output_file)

        # Create the directory if it doesn't exist (needed for the candidates folder, etc.)
        os.makedirs(os.path.dirname(abs_output_path), exist_ok=True)

        with open(abs_output_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)

        nodes_count = len(graph_data.get("nodes", []))
        links_count = len(graph_data.get("links", []))

        return GraphGenerationResult(
            ok=True,
            message=f"Graph saved successfully to {os.path.basename(output_file)}.",
            output_file=abs_output_path,
            nodes_count=nodes_count,
            links_count=links_count
        )

    except Exception as e:
        return GraphGenerationResult(ok=False, message=f"Graph JSON saving failed: {e}")

# --- 5. MCP Tools (Async) ---
mcp = FastMCP("attack-graph-mcp-server")

@mcp.tool()
async def fetch_cves_by_keyword(
    keyword: str,
    output_file: str,
    search_limit: int = 2000,
    timeout: int = 600
) -> BulkFetchResult:
    """
    Fetches ALL CVEs from NVD matching a keyword using nvdlib and saves them
    as a tagged JSON file. (Implements Plan Step 1 & 2).

    Args:
        keyword (str): The search term.
        output_file (str): The path to save the resulting JSON.
        search_limit (int, optional): Max number of results to fetch.
        Defaults to 2000.
        timeout (int, optional): Total timeout for the entire operation in seconds.
        Defaults to 600.

    Returns:
        BulkFetchResult: An object reporting the success, output file path, and count.
    """
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                _bulk_fetch_workflow_sync, keyword, output_file, search_limit
            ),
            timeout=timeout,
        )
        return result
    except asyncio.TimeoutError:
        return BulkFetchResult(ok=False, message=f"Error: Operation timed out after {timeout}s.")
    except Exception as e:
        return BulkFetchResult(ok=False, message=f"Unexpected error: {e}")

@mcp.tool()
async def load_json_data(file_path: str, timeout: int = 30) -> FileReadResult:
    """
    Reads a JSON file from the server's disk and returns its content.
    Supports both NVD source lists and generated Attack Graph objects.

    Args:
        file_path (str): The path to the JSON file to be read.
        timeout (int, optional): Operation timeout in seconds. Defaults to 30.

    Returns:
        FileReadResult: An object containing success status, a message, and the file content.
    """

    clean_path = file_path.strip().strip('"').strip("'")

    def _read_sync():
        try:
            abs_path = os.path.abspath(clean_path)

            if not os.path.exists(abs_path):
                return FileReadResult(
                    ok=False,
                    message=f"File not found at path: {abs_path}",
                    file_path=abs_path
                )

            with open(abs_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            data_type = type(data).__name__

            return FileReadResult(
                ok=True,
                message=f"Successfully read JSON ({data_type}) from {abs_path}",
                file_path=abs_path,
                data=data
            )
        except json.JSONDecodeError:
             return FileReadResult(
                ok=False,
                message="File exists but is not valid JSON.",
                file_path=abs_path
            )
        except Exception as e:
            return FileReadResult(
                ok=False,
                message=f"Failed to read file: {str(e)}",
                file_path=clean_path
            )

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_read_sync),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        return FileReadResult(
            ok=False,
            message=f"File read timed out after {timeout} seconds.",
            file_path=clean_path
        )

@mcp.tool()
async def save_tagged_cves(data: List[Dict[str, Any]], output_file: str, timeout: int = 30) -> FileWriteResult:
    """
    Takes a JSON (List[Dict]) provided by the LLM host and saves it
    to the server's disk. This is used to save the tagged results.

    Args:
        data (List[Dict[str, Any]]): The JSON-serializable data (typically a list of dictionaries) provided by the LLM host to be saved.
        output_file (str): The path where the JSON file will be saved.
        timeout (int, optional): Operation timeout in seconds. Defaults to 30.

    Returns:
        FileWriteResult: An object reporting the success status and the final output file path.
    """
    async def _write_sync():
        try:
            abs_path = os.path.abspath(output_file)
            with open(abs_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return FileWriteResult(ok=True, message="File saved successfully.", output_file=abs_path)
        except Exception as e:
            return FileWriteResult(ok=False, message=f"Failed to save file: {e}", output_file=output_file)

    try:
        return await asyncio.wait_for(_write_sync(), timeout=timeout)
    except asyncio.TimeoutError:
        return FileWriteResult(ok=False, message="File save timed out.", output_file=output_file)

@mcp.tool()
async def save_candidate_graph(
    graph_data: Dict[str, Any],
    candidate_id: int,
    timeout: int = 60
) -> GraphGenerationResult:
    """
    Saves an intermediate candidate attack graph.
    Used during the 'Preliminary Candidate Generation' phase of CoG.
    Files are saved to a 'candidates' subdirectory (e.g., candidates/graph_1.json).

    Args:
        graph_data: The JSON object containing nodes and links.
        candidate_id: An integer identifier (e.g., 1, 2, 3) for this candidate.
        timeout: Timeout in seconds.
    """
    # Automatically assign the save path
    output_path = f"candidates/graph_{candidate_id}.json"

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                _save_graph_json_sync, graph_data, output_path
            ),
            timeout=timeout,
        )
        return result
    except asyncio.TimeoutError:
        return GraphGenerationResult(ok=False, message=f"Error: Saving candidate {candidate_id} timed out.")
    except Exception as e:
        return GraphGenerationResult(ok=False, message=f"Unexpected error: {e}")

# --- [Phase 1 New Tool] 2. Load all candidates ---
@mcp.tool()
async def load_all_candidates(timeout: int = 30) -> CandidateLoadResult:
    """
    Loads ALL candidate graphs from the 'candidates' directory.
    Used during the 'Ranking & Finalization' phase to compare candidates.

    Returns:
        CandidateLoadResult: Contains a list of all loaded graph objects.
    """
    async def _load_sync():
        try:
            candidates = []
            # Search all json files in the candidates folder
            files = glob.glob("candidates/graph_*.json")
            files.sort() # Sort to guarantee order

            if not files:
                return CandidateLoadResult(ok=False, message="No candidate files found in 'candidates/' directory.")

            for file_path in files:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Optionally extract the ID from the filename and add it to the metadata
                    data["_source_file"] = os.path.basename(file_path)
                    candidates.append(data)

            return CandidateLoadResult(
                ok=True,
                message=f"Successfully loaded {len(candidates)} candidates.",
                candidate_count=len(candidates),
                candidates=candidates
            )
        except Exception as e:
            return CandidateLoadResult(ok=False, message=f"Failed to load candidates: {e}")

    try:
        return await asyncio.wait_for(_load_sync(), timeout=timeout)
    except asyncio.TimeoutError:
        return CandidateLoadResult(ok=False, message="Loading candidates timed out.")

# --- [Phase 1 New Tool] 3. Save final graph (with validation) ---
@mcp.tool()
async def save_final_graph(
    graph_json_object: Dict[str, Any],
    output_file_path: str = "attack_graph.json",
    timeout: int = 60
) -> GraphGenerationResult:
    """
    Saves the FINAL, agreed-upon attack graph after ranking/majority voting.
    Includes basic validation to ensure 'nodes' and 'links' exist.

    Args:
        graph_json_object: The final JSON object.
        output_file_path: Defaults to 'attack_graph.json'.
    """
    # Simple validation check
    if "nodes" not in graph_json_object or "links" not in graph_json_object:
        return GraphGenerationResult(
            ok=False,
            message="Validation Failed: Final graph must contain 'nodes' and 'links' keys."
        )

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                _save_graph_json_sync, graph_json_object, output_file_path
            ),
            timeout=timeout,
        )
        return result
    except asyncio.TimeoutError:
        return GraphGenerationResult(ok=False, message=f"Error: Final graph saving timed out.")
    except Exception as e:
        return GraphGenerationResult(ok=False, message=f"Unexpected error: {e}")

# --- 6. Entry Point ---
def main():
    """Run the MCP server."""
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
