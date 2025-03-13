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
    i = int(math.log(size_bytes, 1024))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def scan_directory(start_path, verbose=True, max_workers=8):
    """
    Scan directory recursively and build tree structure with file statistics.
    Uses multithreading to speed up the scanning process.
    """
    start_time = time.time()
    files_processed = 0
    dirs_processed = 0
    errors_encountered = 0
    
    # Global counters for progress reporting
    stats = {
        "files_processed": 0,
        "dirs_processed": 0,
        "errors_encountered": 0,
        "bytes_counted": 0
    }
    
    if not os.path.exists(start_path):
        if verbose:
            print(f"Error: Path does not exist: {start_path}")
        return {"name": os.path.basename(start_path), "size": 0, "error": "Path does not exist"}
    
    # Skip certain system directories that might cause issues
    skip_dirs = [
        "$RECYCLE.BIN", 
        "System Volume Information", 
        "pagefile.sys", 
        "swapfile.sys",
        "hiberfil.sys"
    ]
    
    def process_file(file_path):
        """Process a single file and return its data."""
        try:
            size = os.path.getsize(file_path)
            owner = get_file_owner(file_path)
            stats_info = get_file_stats(file_path)
            
            stats["files_processed"] += 1
            stats["bytes_counted"] += size
            
            if verbose and stats["files_processed"] % 100 == 0:
                elapsed = time.time() - start_time
                print(f"\rProcessed: {stats['dirs_processed']} dirs, {stats['files_processed']} files, "
                      f"{convert_size(stats['bytes_counted'])} in {elapsed:.1f}s", end="")
            
            return {
                "name": os.path.basename(file_path),
                "path": file_path,
                "size": size,
                "human_size": convert_size(size),
                "type": "file",
                "owner": owner,
                "modified": stats_info["modified"],
                "accessed": stats_info["accessed"]
            }
        except (PermissionError, OSError) as e:
            stats["errors_encountered"] += 1
            return {
                "name": os.path.basename(file_path),
                "path": file_path,
                "size": 0,
                "human_size": "0 B",
                "type": "error",
                "error": str(e)
            }
    
    def scan_recursive(path):
        """Recursively scan a directory with multithreading for children."""
        try:
            if os.path.isfile(path):
                return process_file(path)
            
            result = {
                "name": os.path.basename(path) or path,
                "path": path,
                "children": [],
                "size": 0
            }
            
            # Get all items in the directory
            try:
                items = os.listdir(path)
                stats["dirs_processed"] += 1
                
                if verbose and stats["dirs_processed"] % 10 == 0:
                    elapsed = time.time() - start_time
                    print(f"\rProcessed: {stats['dirs_processed']} dirs, {stats['files_processed']} files, "
                          f"{convert_size(stats['bytes_counted'])} in {elapsed:.1f}s", end="")
            except (PermissionError, OSError) as e:
                stats["errors_encountered"] += 1
                return {
                    "name": os.path.basename(path),
                    "path": path,
                    "size": 0,
                    "human_size": "0 B",
                    "type": "error",
                    "error": str(e)
                }
            
            # Filter out items to skip
            items = [item for item in items if item not in skip_dirs]
            
            # Create full paths
            item_paths = [os.path.join(path, item) for item in items]
            
            # Filter for readable items
            readable_items = []
            for item_path in item_paths:
                try:
                    if os.access(item_path, os.R_OK):
                        readable_items.append(item_path)
                except (PermissionError, OSError):
                    pass
            
            # Process immediate children with a ThreadPoolExecutor
            children_data = []
            if readable_items:
                # For top-level items, process them in parallel
                if path == start_path:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                        future_to_path = {executor.submit(scan_recursive, item_path): item_path for item_path in readable_items}
                        
                        if verbose:
                            futures = concurrent.futures.as_completed(future_to_path)
                            futures = tqdm(futures, total=len(readable_items), desc="Scanning top-level directories", unit="dir")
                        else:
                            futures = concurrent.futures.as_completed(future_to_path)
                        
                        for future in futures:
                            try:
                                item_data = future.result()
                                children_data.append(item_data)
                            except Exception as e:
                                stats["errors_encountered"] += 1
                                print(f"Error processing {future_to_path[future]}: {str(e)}")
                else:
                    # For deeper levels, process sequentially to avoid thread explosion
                    for item_path in readable_items:
                        try:
                            item_data = scan_recursive(item_path)
                            children_data.append(item_data)
                        except Exception as e:
                            stats["errors_encountered"] += 1
            
            # Add children data to result
            result["children"] = children_data
            result["size"] = sum(child["size"] for child in children_data)
            
            # Add metadata for directory
            result["human_size"] = convert_size(result["size"])
            result["type"] = "directory"
            result["owner"] = get_file_owner(path)
            stats_info = get_file_stats(path)
            result["modified"] = stats_info["modified"]
            result["accessed"] = stats_info["accessed"]
            
            # Sort children by size (descending)
            result["children"] = sorted(result["children"], key=lambda x: x["size"], reverse=True)
            
            return result
            
        except (PermissionError, OSError) as e:
            stats["errors_encountered"] += 1
            return {
                "name": os.path.basename(path),
                "path": path,
                "size": 0,
                "human_size": "0 B",
                "type": "error",
                "error": str(e)
            }
    
    # Start the scan
    if verbose:
        print(f"Starting scan of {start_path}...")
    
    result = scan_recursive(start_path)
    
    # Print final statistics
    if verbose:
        elapsed = time.time() - start_time
        print(f"\nScan completed in {elapsed:.2f} seconds.")
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
                background-color: #f5f5f5;
                height: 100vh;
                overflow: hidden;
            }
            #container {
                display: flex;
                height: 100vh;
                width: 100vw;
                overflow: hidden;
            }
            #visualization {
                flex: 3;
                display: flex;
                justify-content: center;
                align-items: center;
                position: relative;
                overflow: hidden;
            }
            #chart {
                width: 100%;
                height: 100%;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            #details {
                flex: 1;
                padding: 20px;
                background-color: #fff;
                box-shadow: -2px 0 10px rgba(0, 0, 0, 0.1);
                overflow-y: auto;
                min-width: 300px;
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
            }
            #legend {
                position: absolute;
                bottom: 20px;
                left: 20px;
                background-color: rgba(255, 255, 255, 0.9);
                padding: 10px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }
            .legend-item {
                display: flex;
                align-items: center;
                margin-bottom: 5px;
            }
            .legend-color {
                width: 15px;
                height: 15px;
                margin-right: 5px;
            }
            #no-data {
                text-align: center;
                font-size: 18px;
                color: #777;
            }
        </style>
    </head>
    <body>
        <div id="container">
            <div id="visualization">
                <div class="breadcrumb"></div>
                <div id="chart"></div>
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
            const data = DISK_DATA_PLACEHOLDER;
            
            // Set up dimensions - make it responsive and fill most of the screen
            const getChartDimensions = () => {
                const visualizationDiv = document.getElementById("visualization");
                const width = visualizationDiv.clientWidth - 40; // Account for padding
                const height = visualizationDiv.clientHeight - 100; // Account for breadcrumb and padding
                return {
                    width: width,
                    height: height,
                    radius: Math.min(width, height) / 2
                };
            };
            
            let dims = getChartDimensions();
            const width = dims.width;
            const height = dims.height;
            const radius = dims.radius;
            
            // Create the color scale
            const colorScale = d3.scaleOrdinal(d3.quantize(d3.interpolateRainbow, 20));
            
            // Create the SVG container
            const svg = d3.select("#chart")
                .append("svg")
                .attr("width", width)
                .attr("height", height)
                .append("g")
                .attr("transform", `translate(${width / 2}, ${height / 2})`);
            
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
                .outerRadius(d => Math.sqrt(d.y1));
            
            // Create hierarchy from data
            const root = d3.hierarchy(data)
                .sum(d => d.size)
                .sort((a, b) => b.value - a.value);
            
            // Current view state
            let currentNode = root;
            
            // Update the visualization
            function update(node) {
                currentNode = node;
                
                // Set focus to the given node
                const descendants = root.descendants();
                
                // Apply new data to partition layout
                partition(root);
                
                // Calculate the positions of all arcs relative to the current node
                const ancestorPath = node.ancestors().reverse();
                const maxDepth = Math.max(...descendants.map(d => d.depth)) - node.depth;
                const path = svg.selectAll("path")
                    .data(
                        descendants.filter(d => 
                            d.depth >= node.depth && 
                            d.depth <= node.depth + 3 && // Show only 3 levels deep
                            ancestors(d, node)
                        ),
                        d => d.data.path
                    );
                
                // Update paths
                path.enter()
                    .append("path")
                    .attr("fill", d => {
                        // Color by common parents
                        while (d.depth > node.depth + 1) d = d.parent;
                        return colorScale(d.data.name);
                    })
                    .attr("fill-opacity", d => 1 - (d.depth - node.depth) * 0.15)
                    .attr("d", arc)
                    .on("click", (event, d) => {
                        // Zoom in when clicking
                        update(d);
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
                    })
                    .merge(path)
                    .transition()
                    .duration(750)
                    .attrTween("d", d => {
                        const i = d3.interpolate(
                            {x0: d.x0, x1: d.x1, y0: d.y0, y1: d.y1},
                            {x0: d.x0, x1: d.x1, y0: d.y0, y1: d.y1}
                        );
                        return t => arc(i(t));
                    });
                
                path.exit().remove();
                
                // Update the detail panel
                updateDetails(node);
                
                // Update the breadcrumb
                updateBreadcrumb(ancestorPath);
                
                // Update center label
                updateCenterLabel(node);
                
                // Update the legend
                updateLegend(node);
            }
            
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
                        <div class="detail-value">${node.data.human_size} (${node.value} bytes)</div>
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
                    .text(() => {
                        if (node === root) {
                            return "Click to zoom in";
                        } else {
                            return "↩ Back up";
                        }
                    })
                    .on("click", () => {
                        if (node !== root) {
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
                        .style("cursor", "pointer")
                        .on("click", () => update(item));
                    
                    row.append("div")
                        .attr("class", "legend-color")
                        .style("background-color", colorScale(item.data.name));
                    
                    row.append("div")
                        .text(`${item.data.name} (${item.data.human_size})`);
                });
            }
            
            // Start visualization with the root
            update(root);
            
            // Allow clicking the SVG background to go up a level
            svg.on("click", () => {
                if (currentNode !== root && currentNode.parent) {
                    update(currentNode.parent);
                }
            });
            
            // Handle window resize - make it truly responsive
            window.addEventListener("resize", () => {
                const dims = getChartDimensions();
                
                d3.select("#chart svg")
                    .attr("width", dims.width)
                    .attr("height", dims.height);
                
                d3.select("#chart svg g")
                    .attr("transform", `translate(${dims.width / 2}, ${dims.height / 2})`);
                
                // Update the radius to match the new dimensions
                const newRadius = dims.radius;
                
                // Update the partition layout
                partition.size([2 * Math.PI, newRadius]);
                
                // Update the arc generator
                arc.innerRadius(d => Math.sqrt(d.y0))
                   .outerRadius(d => Math.sqrt(d.y1));
                
                // Re-partition the hierarchy
                partition(root);
                
                // Update the visualization
                update(currentNode);
            });
        </script>
    </body>
    </html>
    """
    
    # Replace the placeholder with actual data
    html_content = html_content.replace('DISK_DATA_PLACEHOLDER', json.dumps(data))
    
    # Write HTML file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_file

def main():
    
    parser = argparse.ArgumentParser(description='Scan a directory and create a visualization of disk usage.')
    parser.add_argument('--path', default='S:/', help='Path to scan (default: S:/)')
    parser.add_argument('--output', default='disk_visualization.html', help='Output HTML file (default: disk_visualization.html)')
    parser.add_argument('--threads', type=int, default=8, help='Number of worker threads for scanning (default: 8)')
    parser.add_argument('--quiet', action='store_true', help='Reduce output verbosity')
    args = parser.parse_args()
    
    verbose = not args.quiet
    
    if verbose:
        print(f"Starting disk space analyzer")
        print(f"Path: {args.path}")
        print(f"Output: {args.output}")
        print(f"Threads: {args.threads}")
        print(f"Verbose: {verbose}")
        print("-" * 50)
    
    start_time = time.time()
    
    if verbose:
        print(f"Scanning {args.path}...")
    
    try:
        data = scan_directory(args.path, verbose=verbose, max_workers=args.threads)
        
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
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(output_file)}")
            print(f"Attempting to open visualization in your default browser...")
        except:
            pass
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
