# NMON to NDJSON Converter ... FOR POWERBI/EXCEL

This repository contains a Python script that processes `.nmon` files  into structured NDJSON (Newline-Delimited JSON) files for further analysis in POWERBI.

## Features

- Parses `.nmon` files into various categories: `CPU`, `Memory`, `Disk`, `Network`, `LPAR`, and more.
- Outputs structured NDJSON files in categorized subdirectories.
- Supports multiprocessing for faster processing.

## Requirements

- Python 3.6+
- Required libraries: `argparse`, `json`, `os`, `multiprocessing`, `re`, `hashlib`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the script from the command line:

```bash
python nmon2ndjson.py  --input_dir <path_to_nmon_files> --output_dir <output_path> --processes <num_processes>
```

### Example

```bash
python nmon2ndjson.py --input_dir ./nmon_folder --output_dir ./nmon --processes 4
```

### Arguments

- `--input_dir`: Directory containing `.nmon` files.
- `--output_dir`: Directory where NDJSON files will be saved.
- `--processes`: (Optional) Number of processes for parallel execution.

## Output Structure

The script creates subdirectories under the specified output directory:

- `all/`: Combined CPU, memory, and other data by timestamp.
- `top/`: Data for each process.
- `fc/`: Fibre Channel statistics.
- `vg/`: Volume group statistics.
- `net/`: Network interface data.
- `jfs/`: JFS filesystem usage.
- `disk/`: Disk statistics.
- `uargs/`: User arguments for each process.

## How It Works

1. **Parse \*\*\*\*\*\*\*\*\*\*\*\*****`.nmon`**: The script reads `.nmon` files and extracts data.
2. **Build NDJSON**: It processes data into various categories.
3. **Save Files**: Writes structured NDJSON to the respective directories.

## Example Workflow

1. Place all `.nmon` files in a directory, e.g., `./nmon_logs`.
2. Run the script using the command provided above.
3. Navigate to the output directory, where you will find the parsed NDJSON files categorized into subfolders.

## Power BI Integration

To integrate the processed data into Power BI, you can use the following DAX queries:

### Timestamp Table

```DAX
TimestampTable = 
SUMMARIZE(
    FILTER('all', NOT(ISBLANK('all'[@timestamp]))),
    'all'[@timestamp],
    "Hour", HOUR('all'[@timestamp]),
    "Minute", MINUTE('all'[@timestamp])
)
```

### Frame and Node Table

```DAX
FrameNodeTable = DISTINCT(SELECTCOLUMNS('all',"Frame",[lpar_info.Frame],"Node",[lpar_info.Node]))
```

These DAX formulas are designed to create relationships in the Power BI data model. By using the `TimestampTable` and `FrameNodeTable`, you can establish a one-to-all relationship with the main data table (`'all'`). This enables filtering and selection based on timestamps, frames, and nodes across all metrics, providing a seamless experience for data exploration and analysis.

### UARGS and TOP Relationship

The `UARGS` and `TOP` data tables are interconnected, even though `UARGS` may contain duplicate `PID` values. This relationship is maintained by associating each `PID` in the `TOP` table with its corresponding entry in the `UARGS` table through a unique identifier (`UARGSID`).

- Each `UARGSID` is derived from a combination of `PID`, timestamp, and file-specific details, ensuring uniqueness.
- This allows you to connect and filter the `TOP` table based on user arguments (`UARGS`)

In the Power BI data model, you can establish a one-to-many relationship between the `UARGS` table and the `TOP` table using the `UARGSID` field. This enables seamless filtering and analysis of process-level data alongside user arguments.
