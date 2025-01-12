# NMON to NDJSON Converter ... FOR POWERBI/EXCEL

This repository contains a Python script that processes `.nmon` files  into structured NDJSON (Newline-Delimited JSON) files for further analysis in POWERBI.
![alt text](https://github.com/nazihous/nmon2pbi/blob/main/capture5.jpg?raw=true)

## Features

- Parses `.nmon` files into various categories: `CPU`, `Memory`, `Disk`, `Network`, `LPAR`, and more.
- Outputs structured NDJSON files in categorized subdirectories.
- Supports multiprocessing for faster processing.

## Requirements

- Python 3.6+
- Required libraries: `argparse`, `json`, `os`, `multiprocessing`, `re`, `hashlib`

## Usage

Run the script from the command line:

```bash
python nmon2ndjson.py  --input_dir <path_to_nmon_files> --output_dir <output_path> --processes <num_processes>
```

### Example

```bash
python nmon2ndjson.py --input_dir ./nmon_folder --output_dir ./json_folder --processes 4
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

## Power BI Integration
![alt text](https://github.com/nazihous/nmon2pbi/blob/main/capture3.jpg?raw=true)

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

These DAX formulas are designed to create relationships in the Power BI data model. By using the `TimestampTable` and `FrameNodeTable`, you can establish a one-to-all relationship with the main data tables . This enables filtering and selection based on timestamps, frames, and nodes across all metrics, providing a seamless experience for data exploration and analysis.

### UARGS and TOP Relationship
![alt text](https://github.com/nazihous/nmon2pbi/blob/main/capture6.jpg?raw=true)
![alt text](https://github.com/nazihous/nmon2pbi/blob/main/capture7.jpg?raw=true)

If you're familiar with NMON, this script enables you to map UARGS (-T for nmon recording) data (collected once) to TOP data using a special primary/secondary key. This lets you display information like PID, command, and %CPU from TOP, alongside the corresponding full command, user, and group from UARGS.
you can drill down into specific time intervals to identify processes causing CPU spikes based on PID, PPID, full command, command, or user.
- Each `UARGSID` is derived from a combination of `PID`, timestamp, and file-specific details, ensuring uniqueness.
- This allows you to connect and filter the `TOP` table based on user arguments (`UARGS`)
