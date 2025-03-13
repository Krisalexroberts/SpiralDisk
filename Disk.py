import os
import win32security
import datetime
import json
import math
import time
import concurrent.futures
from pathlib import Path
import argparse
from tqdm import tqdm
import queue
import threading
import webbrowser

def get_file_owner(file_path):
    """Get the owner/author of a file."""
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, domain, type = win32security.LookupAccountSid(None, owner_sid)
        return f"{domain}\\{name}"
    except Exception:
        return "Unknown"

def get_file_stats(file_path):
    """Get last modified and last accessed times for a file."""
    try:
        stat_info = os.stat(file_path)
        return {
            "modified": datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "accessed": datetime.datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception:
        return {"modified": "Unknown", "accessed": "Unknown"}

def convert_size(size_bytes):
    """Convert bytes to human-readable format."""
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.log(size_bytes, 1024)) if size_bytes > 0 else 0
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def scan_directory_fast(start_path, verbose=True, max_workers=16, max_depth=None):
    """
    Optimized directory scanning using producer-consumer pattern with threading.
    
    Args:
        start_path: Path to scan
        verbose: Whether to show progress
        max_workers: Maximum number of concurrent workers
        max_depth: Maximum directory depth to scan (None for unlimited)
    """
    start_time = time.time()
    
    # Skip these system directories
    skip_dirs = {
        "$RECYCLE.BIN", 
        "System Volume Information", 
        "pagefile.sys", 
        "swapfile.sys",
        "hiberfil.sys",
        "Documents and Settings",  # Windows Vista+ junction
        "Recovery",                # Windows recovery partition
        "Config.Msi",              # Windows installer files
        "$SysReset",               # Windows reset files
        "$Windows.~BT",            # Windows upgrade files
        "$Windows.~WS",            # Windows upgrade files
        "WindowsApps",             # Windows store apps
        "WinSxS",                  # Windows component store (huge)
        "PerfLogs"                 # Performance logs
    }
    
    # Stats counters
    stats = {
        "files_processed": 0,
        "dirs_processed": 0,
        "errors_encountered": 0,
        "bytes_counted": 0,
        "last_status_time": time.time()
    }
    
    # Create thread-safe counters
    stats_lock = threading.Lock()
    
    # Store path metadata (to avoid recalculating)
    metadata_cache = {}
    metadata_lock = threading.Lock()
    
    def get_cached_metadata(path, is_file=None):
        """Get metadata for a path, using cache if available."""
        with metadata_lock:
            if path in metadata_cache:
                return metadata_cache[path]
        
        if is_file is None:
            is_file = os.path.isfile(path)
        
        try:
            # For files, get full metadata
            if is_file:
                size = os.path.getsize(path)
                with stats_lock:
                    stats["files_processed"] += 1
                    stats["bytes_counted"] += size
                
                result = {
                    "name": os.path.basename(path),
                    "path": path,
                    "size": size,
                    "human_size": convert_size(size),
                    "type": "file",
                    "owner": get_file_owner(path),
                    "modified": get_file_stats(path)["modified"],
                    "accessed": get_file_stats(path)["accessed"]
                }
            # For directories, just placeholder data until we process its contents
            else:
                with stats_lock:
                    stats["dirs_processed"] += 1
                    
                result = {
                    "name": os.path.basename(path) or path,
                    "path": path,
                    "children": [],
                    "size": 0,
                    "type": "directory",
                    "owner": get_file_owner(path),
                    "modified": get_file_stats(path)["modified"],
                    "accessed": get_file_stats(path)["accessed"]
                }
        except Exception as e:
            with stats_lock:
                stats["errors_encountered"] += 1
            result = {
                "name": os.path.basename(path),
                "path": path,
                "size": 0,
                "human_size": "0 B",
                "type": "error",
                "error": str(e)
            }
        
        # Cache the result
        with metadata_lock:
            metadata_cache[path] = result
        
        return result
    
    # Directory structure will be built bottom-up
    dir_structure = {}
    dir_lock = threading.Lock()
    
    # Queue for directories to process
    dir_queue = queue.Queue()
    
    # Add the start path to the queue
    base_name = os.path.basename(start_path) or start_path
    dir_queue.put((start_path, 0))  # (path, depth)
    
    # Start the status update thread if verbose mode is on
    stop_status_thread = threading.Event()
    
    def status_update_thread():
        """Thread to periodically display status updates."""
        while not stop_status_thread.is_set():
            with stats_lock:
                current_stats = dict(stats)
            
            elapsed = time.time() - start_time
            print(f"\rProcessed: {current_stats['dirs_processed']} dirs, "
                  f"{current_stats['files_processed']} files, "
                  f"{convert_size(current_stats['bytes_counted'])} in {elapsed:.1f}s", end="")
            
            time.sleep(0.5)
    
    if verbose:
        status_thread = threading.Thread(target=status_update_thread)
        status_thread.daemon = True
        status_thread.start()
    
    # Worker function to process directories
    def process_directory():
        while True:
            try:
                # Get a directory from the queue
                dir_path, depth = dir_queue.get(timeout=1)
                
                # Stop if we've reached max depth
                if max_depth is not None and depth > max_depth:
                    dir_queue.task_done()
                    continue
                
                # Get directory metadata
                dir_data = get_cached_metadata(dir_path, is_file=False)
                
                # Skip if there was an error
                if dir_data.get("type") == "error":
                    dir_queue.task_done()
                    continue
                
                try:
                    # Scan the directory
                    items = os.scandir(dir_path)
                    children_data = []
                    
                    # Process each item in the directory
                    for item in items:
                        item_path = item.path
                        
                        # Skip system directories
                        if item.name in skip_dirs:
                            continue
                        
                        try:
                            # First check if we can access it
                            if not os.access(item_path, os.R_OK):
                                continue
                            
                            # Process based on file type
                            if item.is_file():
                                # For files, just get metadata
                                file_data = get_cached_metadata(item_path, is_file=True)
                                children_data.append(file_data)
                            elif item.is_dir():
                                # For directories, add to queue and create placeholder
                                dir_queue.put((item_path, depth + 1))
                                # Also create an entry in the directory structure
                                with dir_lock:
                                    dir_structure[item_path] = []
                                children_data.append(get_cached_metadata(item_path, is_file=False))
                        except Exception as e:
                            with stats_lock:
                                stats["errors_encountered"] += 1
                            # Skip items we can't access
                            continue
                    
                    # Store children list in directory structure
                    with dir_lock:
                        dir_structure[dir_path] = children_data
                
                except Exception as e:
                    with stats_lock:
                        stats["errors_encountered"] += 1
                
                dir_queue.task_done()
                
            except queue.Empty:
                # Queue is empty, check if we're done
                if dir_queue.unfinished_tasks == 0:
                    break
    
    # Create and start worker threads
    workers = []
    for _ in range(min(max_workers, os.cpu_count() * 2)):
        thread = threading.Thread(target=process_directory)
        thread.daemon = True
        thread.start()
        workers.append(thread)
    
    # Wait for all directories to be processed
    dir_queue.join()
    
    # Stop workers
    for worker in workers:
        worker.join(0.1)
    
    if verbose:
        stop_status_thread.set()
        if status_thread.is_alive():
            status_thread.join(0.1)
    
    # Post-process to calculate sizes
    def finalize_directory_data(path):
        """Calculate sizes for directories and prepare final structure."""
        # Check if we have info for this path
        if path not in dir_structure:
            # This is either a file or an empty/unreadable directory
            return get_cached_metadata(path)
        
        # Get children data
        children = dir_structure[path]
        
        # Process each child
        for i, child in enumerate(children):
            if child["type"] == "directory":
                # Recursively finalize child directories
                child_data = finalize_directory_data(child["path"])
                children[i] = child_data
        
        # Calculate directory size
        total_size = sum(child["size"] for child in children)
        
        # Update directory metadata
        dir_data = get_cached_metadata(path, is_file=False)
        dir_data["children"] = sorted(children, key=lambda x: x["size"], reverse=True)
        dir_data["size"] = total_size
        dir_data["human_size"] = convert_size(total_size)
        
        return dir_data
    
    # Build final tree from the root
    if verbose:
        print("\nFinalizing directory structure...")
    
    result = finalize_directory_data(start_path)
    
    # Print final statistics
    if verbose:
        elapsed = time.time() - start_time
        print(f"Scan completed in {elapsed:.2f} seconds.")
        print(f"Processed {stats['dirs_processed']} directories and {stats['files_processed']} files.")
        print(f"Total size: {convert_size(stats['bytes_counted'])} ({stats['bytes_counted']} bytes)")
        print(f"Errors encountered: {stats['errors_encountered']}")
    
    return result

def create_html_visualization(data, output_file="disk_visualization.html"):
    """Create HTML file with the visualization."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Disk Space Visualizer</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                overflow: hidden;
                height: 100vh;
                width: 100vw;
            }
            
            #container {
                display: flex;
                height: 100vh;
            }
            
            #visualization {
                flex: 3;
                position: relative;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100%;
            }
            
            #details {
                flex: 1;
                background-color: white;
                padding: 20px;
                overflow-y: auto;
                height: 100%;
                box-sizing: border-box;
                min-width: 300px;
                max-width: 400px;
                box-shadow: -2px 0 10px rgba(0, 0, 0, 0.1);
            }
            
            #details h2 {
                margin-top: 0;
                padding-bottom: 10px;
                border-bottom: 1px solid #eee;
            }
            
            .detail-row {
                margin-bottom: 10px;
            }
            
            .detail-label {
                font-weight: bold;
                color: #555;
            }
            
            .detail-value {
                margin-top: 3px;
            }
            
            .breadcrumb {
                position: absolute;
                top: 20px;
                left: 20px;
                z-index: 10;
                background-color: rgba(255, 255, 255, 0.9);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                max-width: 80%;
                overflow-x: auto;
                white-space: nowrap;
            }
            
            .breadcrumb span {
                cursor: pointer;
                color: #0066cc;
            }
            
            .breadcrumb span:hover {
                text-decoration: underline;
            }
            
            .breadcrumb .separator {
                margin: 0 5px;
                color: #777;
            }
            
            path {
                cursor: pointer;
                stroke: white;
                stroke-width: 0.05;  /* Thinner strokes for the scaled visualization */
            }
            
            path:hover {
                opacity: 0.8;
            }
            
            .tooltip {
                position: absolute;
                background-color: rgba(0, 0, 0, 0.8);
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 14px;
                pointer-events: none;
                z-index: 1000;
                white-space: nowrap;
            }
            
            .center-label {
                font-size: 16px;
                text-anchor: middle;
                cursor: pointer;
            }
            
            #legend {
                position: absolute;
                bottom: 20px;
                left: 20px;
                z-index: 10;
                background-color: rgba(255, 255, 255, 0.9);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                max-height: 300px;
                overflow-y: auto;
            }
            
            .legend-item {
                display: flex;
                align-items: center;
                margin-bottom: 8px;
                cursor: pointer;
            }
            
            .legend-color {
                width: 16px;
                height: 16px;
                margin-right: 8px;
                border: 1px solid rgba(0, 0, 0, 0.2);
            }
            
            #chart-container {
                width: 85vmin;
                height: 85vmin;
            }
        </style>
    </head>
    <body>
        <div id="container">
            <div id="visualization">
                <div class="breadcrumb"></div>
                <div id="chart-container"></div>
                <div id="legend"></div>
            </div>
            <div id="details">
                <h2>File/Folder Details</h2>
                <div id="detail-content">
                    <div id="no-data">Click on a segment to view details</div>
                </div>
            </div>
        </div>

        <script>
            // Load the data
            const data = DATA_PLACEHOLDER;
            
            // Set up dimensions
            const width = Math.min(window.innerWidth, window.innerHeight) * 0.85;
            const height = width;
            const radius = width / 2;
            
            // Create the color scale
            const colorScale = d3.scaleOrdinal(d3.quantize(d3.interpolateRainbow, 20));
            
            // Create the SVG container with proper scaling
            const svg = d3.select("#chart-container")
                .append("svg")
                .attr("width", width)
                .attr("height", height)
                .attr("viewBox", `0 0 ${width} ${height}`)
                .style("width", "100%")
                .style("height", "100%")
                .append("g")
                .attr("transform", `translate(${width / 2}, ${height / 2}) scale(10)`);
            
            // Create tooltip
            const tooltip = d3.select("body").append("div")
                .attr("class", "tooltip")
                .style("opacity", 0);
            
            // Create partition layout
            const partition = d3.partition()
                .size([2 * Math.PI, radius]);
            
            // Create arc generator
            const arc = d3.arc()
                .startAngle(d => d.x0)
                .endAngle(d => d.x1)
                .innerRadius(d => Math.sqrt(d.y0))
                .outerRadius(d => Math.sqrt(d.y1))
                .padAngle(0.002)  // Add small padding between arcs
                .padRadius(radius / 2);
            
            // Create hierarchy from data
            const root = d3.hierarchy(data)
                .sum(d => d.size)
                .sort((a, b) => b.value - a.value);
            
            // Apply partition layout
            partition(root);
            
            // Current view state
            let currentNode = root;
            
            // Add center circle (scaled down to match the scale(10) transform)
            svg.append("circle")
                .attr("fill", "white")
                .attr("r", radius / 150)  // 10x smaller due to scale(10)
                .attr("stroke", "#ddd")
                .attr("stroke-width", 0.1)  // 10x smaller due to scale(10)
                .style("cursor", "pointer")
                .on("click", () => {
                    if (currentNode.parent) {
                        update(currentNode.parent);
                    }
                });
            
            // Create paths for all nodes
            const path = svg.selectAll("path")
                .data(root.descendants().slice(1))
                .enter().append("path")
                .attr("fill", d => {
                    while (d.depth > 1) d = d.parent;
                    return colorScale(d.data.name);
                })
                .attr("fill-opacity", d => 1 - d.depth * 0.1)
                .attr("d", arc)
                .on("click", (event, d) => {
                    update(d);
                    event.stopPropagation();
                })
                .on("dblclick", (event, d) => {
                    // Set as new root on double-click
                    setNewRoot(d);
                    event.stopPropagation();
                })
                .on("mouseover", (event, d) => {
                    tooltip.transition()
                        .duration(200)
                        .style("opacity", 0.9);
                    tooltip.html(`${d.data.name} (${d.data.human_size})`)
                        .style("left", (event.pageX + 10) + "px")
                        .style("top", (event.pageY - 28) + "px");
                })
                .on("mouseout", () => {
                    tooltip.transition()
                        .duration(500)
                        .style("opacity", 0);
                });
            
            // Function to check if a node is a descendant of another node
            function ancestors(node, target) {
                let current = node;
                while (current && current !== target) {
                    if (current === target) return true;
                    current = current.parent;
                }
                return true;
            }
            
            // Update the details panel
            function updateDetails(node) {
                const content = document.getElementById("detail-content");
                
                const details = `
                    <div class="detail-row">
                        <div class="detail-label">Name:</div>
                        <div class="detail-value">${node.data.name}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Path:</div>
                        <div class="detail-value">${node.data.path}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Size:</div>
                        <div class="detail-value">${node.data.human_size} (${node.value.toLocaleString()} bytes)</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Type:</div>
                        <div class="detail-value">${node.data.type === 'directory' ? 'Folder' : 'File'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Owner:</div>
                        <div class="detail-value">${node.data.owner || 'Unknown'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Last Modified:</div>
                        <div class="detail-value">${node.data.modified || 'Unknown'}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Last Accessed:</div>
                        <div class="detail-value">${node.data.accessed || 'Unknown'}</div>
                    </div>
                `;
                
                content.innerHTML = details;
                
                // If it's a directory, also show the top 10 largest children
                if (node.data.type === 'directory' && node.children && node.children.length > 0) {
                    const childrenList = document.createElement("div");
                    childrenList.className = "detail-row";
                    
                    const label = document.createElement("div");
                    label.className = "detail-label";
                    label.textContent = "Largest Items:";
                    childrenList.appendChild(label);
                    
                    const value = document.createElement("div");
                    value.className = "detail-value";
                    
                    // Display up to 10 largest children
                    const sortedChildren = [...node.children]
                        .sort((a, b) => b.value - a.value)
                        .slice(0, 10);
                    
                    sortedChildren.forEach(child => {
                        const item = document.createElement("div");
                        const percentage = (child.value / node.value * 100).toFixed(1);
                        item.textContent = `${child.data.name} — ${child.data.human_size} (${percentage}%)`;
                        item.style.cursor = "pointer";
                        item.style.marginBottom = "5px";
                        item.style.color = "#0066cc";
                        item.onclick = () => update(child);
                        value.appendChild(item);
                    });
                    
                    childrenList.appendChild(value);
                    content.appendChild(childrenList);
                }
            }
            
            // Update the breadcrumb trail
            function updateBreadcrumb(nodes) {
                const breadcrumb = d3.select(".breadcrumb");
                breadcrumb.html("");
                
                nodes.forEach((node, i) => {
                    if (i > 0) {
                        breadcrumb.append("span")
                            .attr("class", "separator")
                            .text(" > ");
                    }
                    
                    breadcrumb.append("span")
                        .text(node.data.name)
                        .on("click", () => update(node));
                });
            }
            
            // Update the center label
            function updateCenterLabel(node) {
                // Remove existing label
                svg.selectAll(".center-label").remove();
                
                // Add new label
                svg.append("text")
                    .attr("class", "center-label")
                    .attr("dy", "0.35em")
                    .attr("transform", "scale(0.1)")  // Scale the text to be readable
                    .text(() => {
                        if (node === root) {
                            return "Click to zoom in";
                        } else if (node.parent === null) {
                            return "Current root";
                        } else {
                            return "↩ Back";
                        }
                    })
                    .on("click", () => {
                        if (node !== root && node.parent) {
                            update(node.parent);
                        }
                    });
            }
            
            // Update the legend
            function updateLegend(node) {
                const legend = d3.select("#legend");
                legend.html("");
                
                // Get direct children for the legend
                const children = node.children || [];
                
                // Only show top 10 by size
                const topItems = children
                    .sort((a, b) => b.value - a.value)
                    .slice(0, 10);
                
                topItems.forEach(item => {
                    const row = legend.append("div")
                        .attr("class", "legend-item")
                        .on("click", () => update(item));
                    
                    row.append("div")
                        .attr("class", "legend-color")
                        .style("background-color", colorScale(item.data.name));
                    
                    const percentage = (item.value / node.value * 100).toFixed(1);
                    row.append("div")
                        .text(`${item.data.name} (${item.data.human_size}, ${percentage}%)`);
                });
            }
            
            // Update function to zoom into a specific node
            function update(node) {
                currentNode = node;
                
                // Get the ancestors for breadcrumb
                const ancestorPath = node.ancestors().reverse();
                
                // Update the visualization
                path.transition()
                    .duration(750)
                    .attr("opacity", d => {
                        // Show the node itself and all descendants
                        const isDescendant = d.ancestors().includes(node);
                        // Also show siblings if the node is not root
                        const isSibling = node !== root && d.parent === node.parent;
                        return isDescendant || isSibling ? 1 : 0.3;
                    })
                    .attr("pointer-events", d => {
                        // Only the descendants should be clickable
                        const isDescendant = d.ancestors().includes(node);
                        const isSibling = node !== root && d.parent === node.parent;
                        return isDescendant || isSibling ? "auto" : "none";
                    });
                
                // Update panel and navigation
                updateDetails(node);
                updateBreadcrumb(ancestorPath);
                updateCenterLabel(node);
                updateLegend(node);
            }
            
            // Function to set a new root node
            function setNewRoot(node) {
                // Create a new hierarchy with this node as root
                const newRoot = d3.hierarchy(node.data)
                    .sum(d => d.size)
                    .sort((a, b) => b.value - a.value);
                
                // Replace the global root
                root = newRoot;
                currentNode = newRoot;
                
                // Update partition layout
                partition(root);
                
                // Rebuild all paths
                svg.selectAll("path").remove();
                
                const newPaths = svg.selectAll("path")
                    .data(root.descendants().slice(1))
                    .enter().append("path")
                    .attr("fill", d => {
                        while (d.depth > 1) d = d.parent;
                        return colorScale(d.data.name);
                    })
                    .attr("fill-opacity", d => 1 - d.depth * 0.1)
                    .attr("d", arc)
                    .on("click", (event, d) => {
                        update(d);
                        event.stopPropagation();
                    })
                    .on("dblclick", (event, d) => {
                        // Set as new root on double-click
                        setNewRoot(d);
                        event.stopPropagation();
                    })
                    .on("mouseover", (event, d) => {
                        tooltip.transition()
                            .duration(200)
                            .style("opacity", 0.9);
                        tooltip.html(`${d.data.name} (${d.data.human_size})`)
                            .style("left", (event.pageX + 10) + "px")
                            .style("top", (event.pageY - 28) + "px");
                    })
                    .on("mouseout", () => {
                        tooltip.transition()
                            .duration(500)
                            .style("opacity", 0);
                    });
                
                // Update the global path selection
                path = newPaths;
                
                // Update visualization
                updateDetails(root);
                updateBreadcrumb([root]);
                updateCenterLabel(root);
                updateLegend(root);
            }
            
            // Initialize visualization
            updateDetails(root);
            updateBreadcrumb([root]);
            updateCenterLabel(root);
            updateLegend(root);
            
            // Background click to go up a level
            svg.on("click", () => {
                if (currentNode !== root && currentNode.parent) {
                    update(currentNode.parent);
                }
            }).on("dblclick", () => {
                // Return to original root on double-click of background
                window.location.reload();
            });
        </script>
    </body>
    </html>
    """
    
    # Replace the placeholder with actual data
    html_content = html_content.replace('DATA_PLACEHOLDER', json.dumps(data))
    
    # Write HTML file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_file

def main():
    parser = argparse.ArgumentParser(description='Scan a directory and create a visualization of disk usage.')
    parser.add_argument('--path', default='S:/', help='Path to scan (default: S:/)')
    parser.add_argument('--output', default='disk_visualization.html', help='Output HTML file (default: disk_visualization.html)')
    parser.add_argument('--threads', type=int, default=16, help='Number of worker threads for scanning (default: 16)')
    parser.add_argument('--depth', type=int, default=None, help='Maximum directory depth to scan (default: unlimited)')
    parser.add_argument('--quiet', action='store_true', help='Reduce output verbosity')
    args = parser.parse_args()
    
    verbose = not args.quiet
    
    if verbose:
        print(f"Starting disk space analyzer")
        print(f"Path: {args.path}")
        print(f"Output: {args.output}")
        print(f"Threads: {args.threads}")
        print(f"Max depth: {args.depth if args.depth is not None else 'unlimited'}")
        print("-" * 50)
    
    start_time = time.time()
    
    try:
        data = scan_directory_fast(args.path, verbose=verbose, max_workers=args.threads, max_depth=args.depth)
        
        if verbose:
            scan_time = time.time() - start_time
            print(f"Scan completed in {scan_time:.2f} seconds")
            print(f"Creating visualization...")
        
        output_file = create_html_visualization(data, args.output)
        
        total_time = time.time() - start_time
        print(f"Visualization created: {output_file}")
        print(f"Total processing time: {total_time:.2f} seconds")
        print(f"Open this file in your web browser to view the visualization.")
        
        # Try to open the file automatically
        try:
            file_url = f"file://{os.path.abspath(output_file)}"
            print(f"Opening visualization in browser: {file_url}")
            webbrowser.open(file_url)
        except Exception as e:
            print(f"Could not open browser automatically: {e}")
            print(f"Please open the file manually: {output_file}")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
