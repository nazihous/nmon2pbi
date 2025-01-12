#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import glob
import re
from datetime import datetime
from multiprocessing import Pool, cpu_count
import argparse
import hashlib

################################################################################
# 1) Parsing de base du .nmon
################################################################################

def parse_date_time(date_str, time_str):
    """
    On NE convertit PAS en ISO8601. On garde '19-DEC-2024 00:01:54'.
    """
    return f"{date_str} {time_str}"

def read_in_chunks(file_object, chunk_size=10000):
    """
    Lit le fichier en morceaux (chunks) de N lignes pour économiser la mémoire.
    """
    chunk = []
    for line in file_object:
        chunk.append(line)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

def time_str_to_seconds(dt_str):
    """
    Convertit '19-DEC-2024 00:01:54' en nombre de secondes depuis minuit.
    On récupère le HH:MM:SS final.
    """
    time_part = dt_str[-8:]  # ex: '00:01:54'
    h, m, s = time_part.split(':')
    return int(h)*3600 + int(m)*60 + int(s)

def remove_env_suffix(key):
    """
    Supprime le suffixe d'environnement (ex: 'NIM72') s'il y en a
    dans une clé 'Disk Read KB/s NIM72' => 'Disk Read KB/s'.
    """
    if re.search(r' [A-Z0-9]+$', key):
        return ' '.join(key.split(' ')[:-1])
    return key

################################################################################
# 2) parse_nmon_file => lit un .nmon et renvoie tous les dictionnaires
#    (dont top_data_by_tag, fc*, disk*, net*, vg*, jfs*, zzzz_map, etc.)
################################################################################

def parse_nmon_file(nmon_file, file_id=None):

    if file_id is None:
        file_id = os.path.splitext(os.path.basename(nmon_file))[0]

    zzzz_map = {}

    # For date fallback: we'll store AAA,date,<value> if found
    fallback_date = None

    # CPU, MEM, etc. => 1 doc par Txxx
    cpu_data_by_tag = {}
    memnew_data_by_tag = {}
    mem_data_by_tag = {}
    memuse_data_by_tag = {}
    lpar_data_by_tag = {}
    page_data_by_tag = {}
    proc_data_by_tag = {}
    pools_data_by_tag = {}

    # TOP => multiples lignes par Txxx
    top_data_by_tag = {}

    # FC
    fc_read_data_by_tag = {}
    fc_write_data_by_tag = {}
    fc_xferin_data_by_tag = {}
    fc_xferout_data_by_tag = {}
    fc_adapters = []
    fc_header_parsed = False

    # VG
    vg_read_data_by_tag = {}
    vg_write_data_by_tag = {}
    vg_volume_groups = []
    vg_header_parsed = False

    # NET
    net_data_by_tag = {}
    net_packet_data_by_tag = {}
    net_size_data_by_tag = {}
    net_error_data_by_tag = {}
    network_ports = []
    is_network_header_parsed = False

    # DISK
    disk_read_data_by_tag = {}
    disk_write_data_by_tag = {}
    disk_readserv_data_by_tag = {}
    disk_writeserv_data_by_tag = {}
    disk_devices = []
    disk_header_parsed = False

    # DISKWAIT
    disk_wait_data_by_tag = {}

    # DISKBUSY
    diskbusy_data_by_tag = {}
    diskbusy_devices = []
    diskbusy_header_parsed = False

    # JFSFILE
    jfsfile_data_by_tag = {}
    jfs_filesystems = []
    jfsfile_header_parsed = False

    # UARG
    pid_to_uarg = {}
    uarg_data = []

    # LPAR info
    frame = None
    node = None
    oslevel = None

    # FILE I/O
    file_io_data_by_tag = {}
    file_io_header_parsed = False
    file_io_columns = []

    # On lit le fichier
    with open(nmon_file, 'r', encoding='utf-8') as f:
        for chunk_lines in read_in_chunks(f, chunk_size=100000):
            for line in chunk_lines:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',')
                key = parts[0]

                # ZZZZ => timestamp
                if key == 'ZZZZ' and len(parts) >= 4:
                    tag = parts[1]
                    time_str = parts[2]
                    date_str = parts[3].strip()

                    # If date_str is messed up, try fallback_date from AAA
                    if not re.match(r'^\d{2}-[A-Z]{3}-\d{4}$', date_str.upper()):
                        if fallback_date:
                            date_str = fallback_date

                    zzzz_map[tag] = parse_date_time(date_str, time_str)
                    continue

                # CPU_ALL
                if key == 'CPU_ALL' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    # If some field is missing, we set it to 0.0
                    user_val = float(parts[2]) if len(parts) > 2 and parts[2].strip() else 0.0
                    sys_val = float(parts[3]) if len(parts) > 3 and parts[3].strip() else 0.0
                    wait_val = float(parts[4]) if len(parts) > 4 and parts[4].strip() else 0.0
                    idle_val = float(parts[5]) if len(parts) > 5 and parts[5].strip() else 0.0
                    busy_val = float(parts[6]) if len(parts) > 6 and parts[6].strip() else 0.0
                    phys_val = float(parts[7]) if len(parts) > 7 and parts[7].strip() else 0.0

                    cpu_data_by_tag[tag] = {
                        'User%': user_val,
                        'Sys%':  sys_val,
                        'Wait%': wait_val,
                        'Idle%': idle_val,
                        'Busy':  busy_val,
                        'PhysicalCPUs': phys_val
                    }
                    continue

                # MEMNEW
                if key == 'MEMNEW' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    try:
                        memnew_data_by_tag[tag] = {
                            'Process%': float(parts[2]),
                            'FScache%': float(parts[3]),
                            'System%': float(parts[4]),
                            'Free%':    float(parts[5]),
                            'Pinned%':  float(parts[6]),
                            'User%':    float(parts[7])
                        }
                    except:
                        pass
                    continue

                # MEM
                if key == 'MEM' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    try:
                        rf = float(parts[2])
                        vf = float(parts[3])
                        mem_data_by_tag[tag] = {
                            'Real_Free%':       rf,
                            'Real_Used%':       100.0 - rf,
                            'Virtual_Free%':    vf,
                            'Virtual_Used%':    100.0 - vf,
                            'Real_Free_MB':     float(parts[4]),
                            'Virtual_Free_MB':  float(parts[5]),
                            'Real_Total_MB':    float(parts[6]),
                            'Virtual_Total_MB': float(parts[7])
                        }
                    except:
                        pass
                    continue

                # MEMUSE
                if key == 'MEMUSE' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    try:
                        memuse_data_by_tag[tag] = {
                            '%numperm':    float(parts[2]),
                            '%minperm':    float(parts[3]),
                            '%maxperm':    float(parts[4]),
                            'minfree':     float(parts[5]),
                            'maxfree':     float(parts[6]),
                            '%numclient':  float(parts[7]),
                            '%maxclient':  float(parts[8]),
                            'lruablepages':float(parts[9]),
                        }
                    except:
                        pass
                    continue

                # LPAR
                if key == 'LPAR' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    try:
                        lpar_data_by_tag[tag] = {
                            'PhysicalCPU':    float(parts[2]),
                            'VirtualCPUs':    int(parts[3]),
                            'LogicalCPUs':    int(parts[4]),
                            'PoolCPUs':       int(parts[5]),
                            'Entitled':       float(parts[6]),
                            'Weight':         int(parts[7]),
                            'PoolIdle':       float(parts[8]),
                            'UsedAllCPU%':    float(parts[9]),
                            'UsedPoolCPU%':   float(parts[10]),
                            'SharedCPU':      float(parts[11]),
                            'Capped':         float(parts[12]),
                            'EC_User%':       float(parts[13]),
                            'EC_Sys%':        float(parts[14]),
                            'EC_Wait%':       float(parts[15]),
                            'EC_Idle%':       float(parts[16]),
                            'VP_User%':       float(parts[17]),
                            'VP_Sys%':        float(parts[18]),
                            'VP_Wait%':       float(parts[19]),
                            'VP_Idle%':       float(parts[20]),
                            'Folded':         int(parts[21]),
                            'Pool_id':        int(parts[22])
                        }
                    except:
                        pass
                    continue

                # PROC
                if key == 'PROC' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    try:
                        proc_data_by_tag[tag] = {
                            'Runnable':       float(parts[2]),
                            'Swap-in':        float(parts[3]),
                            'pswitch':        int(parts[4]),
                            'syscall':        int(parts[5]),
                            'read':           int(parts[6]),
                            'write':         -int(parts[7]),
                            'fork':           int(parts[8]),
                            'exec':           int(parts[9]),
                            'sem':            int(parts[10]),
                            'msg':            int(parts[11]),
                            'asleep_bufio':   int(parts[12]),
                            'asleep_rawio':   int(parts[13]),
                            'asleep_diocio':  int(parts[14])
                        }
                    except:
                        pass
                    continue

                # POOLS
                if key == 'POOLS' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    try:
                        pools_data_by_tag[tag] = {
                            'shcpus_in_sys':          int(parts[2]),
                            'max_pool_capacity':      float(parts[3]),
                            'entitled_pool_capacity': float(parts[4]),
                            'pool_max_time':          float(parts[5]),
                            'pool_busy_time':         float(parts[6]),
                            'shcpu_tot_time':         float(parts[7]),
                            'shcpu_busy_time':        float(parts[8]),
                            'Pool_id':                int(parts[9]),
                            'entitled':               float(parts[10])
                        }
                    except:
                        pass
                    continue

                # TOP => ex: TOP,T0001,PID,%CPU,%Usr,%Sys,Threads,Size,ResText,ResData,ResTotal,CharIO,%RAM,Paging,Command,WLMclass
                if key == 'TOP' and len(parts) > 2 and any(ch.isdigit() for ch in parts[2]):
                    tag = parts[2]
                    if len(parts) < 15:
                        continue
                    try:
                        if tag not in top_data_by_tag:
                            top_data_by_tag[tag] = []
                        res_text = int(parts[8])
                        res_data = int(parts[9])
                        res_total = res_text + res_data
                        dct = {
                            'PID':     parts[1],
                            '%CPU':    float(parts[3]),
                            '%Usr':    float(parts[4]),
                            '%Sys':    float(parts[5]),
                            'Threads': int(parts[6]),
                            'Size':    int(parts[7]),
                            'ResText': res_text,
                            'ResData': res_data,
                            'ResTotal':res_total,
                            'CharIO':  int(parts[10]),
                            '%RAM':    float(parts[11]),
                            'Paging':  int(parts[12]),
                            'Command': parts[13],
                            'WLMclass':parts[14]
                        }
                        top_data_by_tag[tag].append(dct)
                    except:
                        pass
                    continue

                # PAGE
                if key == 'PAGE' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    try:
                        page_data_by_tag[tag] = {
                            'faults':   float(parts[2]),
                            'pgin':     float(parts[3]),
                            'pgout':   -float(parts[4]),
                            'pgsin':    float(parts[5]),
                            'pgsout':  -float(parts[6]),
                            'reclaims': float(parts[7]),
                            'scans':    float(parts[8]),
                            'cycles':   float(parts[9])
                        }
                    except:
                        pass
                    continue

                # FC => entête
                if (not fc_header_parsed) and key in ['FCREAD','FCWRITE','FCXFERIN','FCXFEROUT'] and not parts[1].startswith('T'):
                    fc_adapters = parts[2:]
                    fc_header_parsed = True
                    continue

                if key == 'FCREAD' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    fc_read_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                if key == 'FCWRITE' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    fc_write_data_by_tag[tag] = [-float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                if key == 'FCXFERIN' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    fc_xferin_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                if key == 'FCXFEROUT' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    fc_xferout_data_by_tag[tag] = [-float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                # VG => entête
                if (not vg_header_parsed) and key in ['VGREAD','VGWRITE'] and not parts[1].startswith('T'):
                    vg_volume_groups = parts[2:]
                    vg_header_parsed = True
                    continue

                if key == 'VGREAD' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    vg_read_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                if key == 'VGWRITE' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    vg_write_data_by_tag[tag] = [-float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                # NET => entête
                if key in ['NET','NETPACKET','NETSIZE','NETERROR'] and not parts[1].startswith('T'):
                    if not is_network_header_parsed:
                        raw_ports = parts[2:]
                        for raw_port in raw_ports:
                            if '-' in raw_port:
                                port_name = raw_port.split('-')[0]
                                if port_name not in network_ports:
                                    network_ports.append(port_name)
                        is_network_header_parsed = True
                    continue

                if key == 'NET' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    vals = parts[2:]
                    net_data_by_tag[tag] = []
                    for i in range(0, len(vals), 2):
                        read_val = float(vals[i]) if vals[i].strip() else 0.0
                        write_val = -float(vals[i+1]) if (i+1 < len(vals) and vals[i+1].strip()) else 0.0
                        net_data_by_tag[tag].append(read_val)
                        net_data_by_tag[tag].append(write_val)
                    continue

                if key == 'NETPACKET' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    vals = parts[2:]
                    net_packet_data_by_tag[tag] = []
                    for i in range(0, len(vals), 2):
                        r_val = float(vals[i]) if vals[i].strip() else 0.0
                        w_val = -float(vals[i+1]) if (i+1 < len(vals) and vals[i+1].strip()) else 0.0
                        net_packet_data_by_tag[tag].append(r_val)
                        net_packet_data_by_tag[tag].append(w_val)
                    continue

                if key == 'NETSIZE' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    vals = parts[2:]
                    net_size_data_by_tag[tag] = []
                    for i in range(0, len(vals), 2):
                        rr = float(vals[i]) if vals[i].strip() else 0.0
                        ww = -float(vals[i+1]) if (i+1 < len(vals) and vals[i+1].strip()) else 0.0
                        net_size_data_by_tag[tag].append(rr)
                        net_size_data_by_tag[tag].append(ww)
                    continue

                if key == 'NETERROR' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    vals = parts[2:]
                    net_error_data_by_tag[tag] = []
                    for i in range(0, len(vals), 2):
                        ierr = float(vals[i]) if vals[i].strip() else 0.0
                        oerr = -float(vals[i+1]) if (i+1 < len(vals) and vals[i+1].strip()) else 0.0
                        net_error_data_by_tag[tag].append(ierr)
                        net_error_data_by_tag[tag].append(oerr)
                    continue

                # DISK => entête
                if (not disk_header_parsed) and key in ['DISKREAD','DISKWRITE','DISKREADSERV','DISKWRITESERV']:
                    if len(parts) > 1 and not parts[1].startswith('T'):
                        disk_devices = parts[2:]
                        disk_header_parsed = True
                    continue

                if key == 'DISKREAD' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    disk_read_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                if key == 'DISKWRITE' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    disk_write_data_by_tag[tag] = [-float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                if key == 'DISKREADSERV' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    disk_readserv_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                if key == 'DISKWRITESERV' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    disk_writeserv_data_by_tag[tag] = [-float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                # DISKWAIT
                if key == 'DISKWAIT' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    disk_wait_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                # DISKBUSY
                if key == 'DISKBUSY':
                    if (not diskbusy_header_parsed) and len(parts) > 1 and not parts[1].startswith('T'):
                        diskbusy_devices = parts[2:]
                        diskbusy_header_parsed = True
                        continue
                    if len(parts) > 1 and parts[1].startswith('T'):
                        tag = parts[1]
                        diskbusy_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                # JFSFILE => entête
                if (not jfsfile_header_parsed) and key == 'JFSFILE' and not parts[1].startswith('T'):
                    jfs_filesystems = parts[2:]
                    jfsfile_header_parsed = True
                    continue

                if key == 'JFSFILE' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    jfsfile_data_by_tag[tag] = [float(x) if x.strip() else 0.0 for x in parts[2:]]
                    continue

                # UARG => correspondances PID
                if key == 'UARG' and len(parts) > 1 and parts[1].startswith('T'):
                    tag = parts[1]
                    if tag not in zzzz_map:
                        continue
                    uarg_timestamp = zzzz_map[tag]
                    try:
                        pid_str = parts[2].strip()
                        ppid_str = parts[3].strip()
                        comm = parts[4].strip()
                        thcount_str = parts[5].strip()
                        user = parts[6].strip()
                        group = parts[7].strip()
                        fullcommand = ",".join(parts[8:]).strip() if len(parts) > 8 else ""
                        pid = int(pid_str)
                        thcount = int(thcount_str)
                        seconds_midnight = time_str_to_seconds(uarg_timestamp)
                        unique_str = f"{file_id}:{pid}:{seconds_midnight}"
                        sha1 = hashlib.sha1(unique_str.encode('utf-8')).hexdigest()[:16]
                        UARGSID = "UARGSID" + sha1.upper()
                        uarg_entry = {
                            '@timestamp':  uarg_timestamp,
                            'PID':         pid,
                            'PPID':        ppid_str,
                            'COMM':        comm,
                            'THCOUNT':     thcount,
                            'USER':        user,
                            'GROUP':       group,
                            'FullCommand': fullcommand,
                            'UARGSID':     UARGSID
                        }
                        pid_to_uarg[pid] = uarg_entry
                        uarg_data.append(uarg_entry)
                    except:
                        pass
                    continue

                # FILE I/O => parse file I/O stats
                # Example lines:
                #   FILE,File I/O ISPBSK1,iget,namei,dirblk,readch,writech,ttyrawch,ttycanch,ttyoutch (header)
                #   FILE,T0001,0,4192,0,262674836,101710358,0,0,0 (values)
                if key == 'FILE':
                    # If we haven't parsed the header yet and the 2nd field
                    # looks like "File I/O ..." then parse columns:
                    if (not file_io_header_parsed) and len(parts) > 2 and "File I/O" in parts[1]:
                        file_io_columns = parts[2:]
                        file_io_header_parsed = True
                        continue
                    # Otherwise, if we have Txxx lines:
                    if len(parts) > 1 and parts[1].startswith('T') and file_io_header_parsed:
                        tag = parts[1]
                        numeric_vals = [
                            float(x) if x.strip() else 0.0
                            for x in parts[2:]
                        ]
                        d = {}
                        for col_index, col_name in enumerate(file_io_columns):
                            if col_index < len(numeric_vals):
                                value = numeric_vals[col_index]
                                # The only change: if it's "writech", make it negative
                                if col_name == 'writech':
                                    value = -abs(value)
                                d[col_name] = value
                            else:
                                d[col_name] = 0.0
                        file_io_data_by_tag[tag] = d
                    continue

                # AAA => LPAR info or date, etc.
                if key == 'AAA' and len(parts) > 2:
                    somekey = parts[1]
                    value = parts[2]
                    if somekey == 'AIX':
                        oslevel = value
                    elif somekey == 'SerialNumber':
                        frame = value
                    elif somekey == 'NodeName':
                        node = value
                    elif somekey == 'date':
                        fallback_date = value  # store for fallback usage

    # On associe la clé UARGSID dans les entrées TOP si possible
    for tag, top_list in top_data_by_tag.items():
        for top_entry in top_list:
            pid_str = top_entry.get('PID')
            try:
                pid_val = int(pid_str)
                if pid_val in pid_to_uarg:
                    top_entry['UARGSID'] = pid_to_uarg[pid_val]['UARGSID']
            except:
                pass

    return (
        cpu_data_by_tag,
        memnew_data_by_tag,
        mem_data_by_tag,
        memuse_data_by_tag,
        lpar_data_by_tag,
        top_data_by_tag,
        page_data_by_tag,
        proc_data_by_tag,
        pools_data_by_tag,
        fc_read_data_by_tag,
        fc_write_data_by_tag,
        fc_xferin_data_by_tag,
        fc_xferout_data_by_tag,
        fc_adapters,
        vg_read_data_by_tag,
        vg_write_data_by_tag,
        vg_volume_groups,
        net_data_by_tag,
        net_packet_data_by_tag,
        net_size_data_by_tag,
        net_error_data_by_tag,
        network_ports,
        disk_read_data_by_tag,
        disk_write_data_by_tag,
        disk_readserv_data_by_tag,
        disk_writeserv_data_by_tag,
        disk_wait_data_by_tag,

        disk_devices,

        diskbusy_data_by_tag,
        diskbusy_devices,

        jfsfile_data_by_tag,
        jfs_filesystems,
        zzzz_map,
        pid_to_uarg,
        uarg_data,
        frame,
        node,
        oslevel,

        # Return for file I/O
        file_io_data_by_tag
    )

################################################################################
# 3) Construction des docs NDJSON
################################################################################

def build_all_docs(
    zzzz_map, cpu_data_by_tag, memnew_data_by_tag, mem_data_by_tag,
    memuse_data_by_tag, lpar_data_by_tag, page_data_by_tag,
    proc_data_by_tag, pools_data_by_tag,
    file_io_data_by_tag
):
    """
    Regroupe CPU, MEM, PAGE, PROC... + FILE I/O dans un doc par Txxx
    """
    all_docs = []
    all_tags = set(
        zzzz_map.keys()
        | cpu_data_by_tag.keys()
        | memnew_data_by_tag.keys()
        | mem_data_by_tag.keys()
        | memuse_data_by_tag.keys()
        | lpar_data_by_tag.keys()
        | page_data_by_tag.keys()
        | proc_data_by_tag.keys()
        | pools_data_by_tag.keys()
        | file_io_data_by_tag.keys()
    )
    for tag in sorted(all_tags):
        dt = zzzz_map.get(tag)
        if not dt:
            continue
        doc = {"@timestamp": dt}
        if tag in cpu_data_by_tag:
            doc["cpu_all"] = cpu_data_by_tag[tag]
        if tag in mem_data_by_tag:
            doc["mem"] = mem_data_by_tag[tag]
        if tag in memnew_data_by_tag:
            doc["memnew"] = memnew_data_by_tag[tag]
        if tag in memuse_data_by_tag:
            doc["memuse"] = memuse_data_by_tag[tag]
        if tag in lpar_data_by_tag:
            doc["lpar"] = lpar_data_by_tag[tag]
        if tag in page_data_by_tag:
            doc["page"] = page_data_by_tag[tag]
        if tag in proc_data_by_tag:
            doc["proc"] = proc_data_by_tag[tag]
        if tag in pools_data_by_tag:
            doc["pools"] = pools_data_by_tag[tag]
        if tag in file_io_data_by_tag:
            doc["file_io"] = file_io_data_by_tag[tag]

        if len(doc) > 1:
            all_docs.append(doc)
    return all_docs

def build_top_docs(zzzz_map, top_data_by_tag, frame=None, node=None, oslevel=None):
    """
    Un doc par ligne TOP => un doc par PID
    """
    top_docs = []
    for tag, top_list in top_data_by_tag.items():
        dt = zzzz_map.get(tag)
        if not dt:
            continue
        for entry in top_list:
            doc = {"@timestamp": dt}
            if frame or node or oslevel:
                lpar_info = {}
                if frame:
                    lpar_info["Frame"] = frame
                if node:
                    lpar_info["Node"] = node
                if oslevel:
                    lpar_info["oslevel"] = oslevel
                doc["lpar_info"] = lpar_info

            # On ajoute tous les champs TOP (PID, %CPU, etc.)
            doc.update(entry)
            top_docs.append(doc)
    return top_docs

def build_fc_docs(
    zzzz_map,
    fc_read_data_by_tag, fc_write_data_by_tag,
    fc_xferin_data_by_tag, fc_xferout_data_by_tag,
    fc_adapters,
    frame=None, node=None, oslevel=None
):
    """
    Un doc par adaptateur FC
    """
    fc_docs = []
    fc_tags = set(
        zzzz_map.keys()
        | fc_read_data_by_tag.keys()
        | fc_write_data_by_tag.keys()
        | fc_xferin_data_by_tag.keys()
        | fc_xferout_data_by_tag.keys()
    )
    for tag in sorted(fc_tags):
        dt = zzzz_map.get(tag)
        if not dt:
            continue
        read_vals = fc_read_data_by_tag.get(tag, [])
        write_vals = fc_write_data_by_tag.get(tag, [])
        in_vals = fc_xferin_data_by_tag.get(tag, [])
        out_vals = fc_xferout_data_by_tag.get(tag, [])

        # pour chaque fc adapter => un doc
        for i, adapter in enumerate(fc_adapters):
            doc = {"@timestamp": dt}
            if frame or node or oslevel:
                lpar_info = {}
                if frame:
                    lpar_info["Frame"] = frame
                if node:
                    lpar_info["Node"] = node
                if oslevel:
                    lpar_info["oslevel"] = oslevel
                doc["lpar_info"] = lpar_info

            doc["fc_adapter"] = adapter
            doc["Fibre Channel Read KB/s"]       = read_vals[i]  if i < len(read_vals)  else 0.0
            doc["Fibre Channel Write KB/s"]      = write_vals[i] if i < len(write_vals) else 0.0
            doc["Fibre Channel Transfers In/s"]  = in_vals[i]    if i < len(in_vals)    else 0.0
            doc["Fibre Channel Transfers Out/s"] = out_vals[i]   if i < len(out_vals)   else 0.0

            fc_docs.append(doc)

    return fc_docs

def build_disk_docs(
    zzzz_map,
    disk_read_data_by_tag,
    disk_write_data_by_tag,
    disk_readserv_data_by_tag,
    disk_writeserv_data_by_tag,
    disk_wait_data_by_tag,
    disk_devices,
    diskbusy_data_by_tag,
    diskbusy_devices,
    frame=None, node=None, oslevel=None
):
    """
    Un doc par disque, pour chaque Txxx
    """
    disk_docs = []
    all_tags = set(
        zzzz_map.keys()
        | disk_read_data_by_tag.keys()
        | disk_write_data_by_tag.keys()
        | disk_readserv_data_by_tag.keys()
        | disk_writeserv_data_by_tag.keys()
        | disk_wait_data_by_tag.keys()
        | diskbusy_data_by_tag.keys()
    )
    for tag in sorted(all_tags):
        dt = zzzz_map.get(tag)
        if not dt:
            continue
        read_vals = disk_read_data_by_tag.get(tag, [])
        write_vals = disk_write_data_by_tag.get(tag, [])
        readserv_vals = disk_readserv_data_by_tag.get(tag, [])
        writeserv_vals = disk_writeserv_data_by_tag.get(tag, [])
        wait_vals = disk_wait_data_by_tag.get(tag, [])
        busy_vals = diskbusy_data_by_tag.get(tag, [])

        # On va associer tout ça par device name
        for i, dname in enumerate(disk_devices):
            doc = {"@timestamp": dt}
            if frame or node or oslevel:
                lpar_info = {}
                if frame:
                    lpar_info["Frame"] = frame
                if node:
                    lpar_info["Node"] = node
                if oslevel:
                    lpar_info["oslevel"] = oslevel
                doc["lpar_info"] = lpar_info

            doc["disk_name"] = dname
            doc["Disk Read KB/s"]            = read_vals[i]  if i < len(read_vals)  else 0.0
            doc["Disk Write KB/s"]           = write_vals[i] if i < len(write_vals) else 0.0
            doc["Disk Read Service Time"]    = readserv_vals[i]  if i < len(readserv_vals)  else 0.0
            doc["Disk Write Service Time"]   = writeserv_vals[i] if i < len(writeserv_vals) else 0.0
            doc["Disk Wait Queue Time msec/xfer"] = wait_vals[i] if i < len(wait_vals) else 0.0

            # Pour Disk %Busy, on cherche le même index que dans diskbusy_devices (si présent).
            disk_busy_value = 0.0
            if dname in diskbusy_devices:
                idx = diskbusy_devices.index(dname)
                if idx < len(busy_vals):
                    disk_busy_value = busy_vals[idx]
            doc["Disk %Busy"] = disk_busy_value

            disk_docs.append(doc)

    return disk_docs

def build_net_docs(
    zzzz_map, net_data_by_tag, net_packet_data_by_tag,
    net_size_data_by_tag, net_error_data_by_tag,
    network_ports, frame=None, node=None, oslevel=None
):
    """
    Un doc par interface réseau
    """
    net_docs = []
    net_tags = set(
        zzzz_map.keys()
        | net_data_by_tag.keys()
        | net_packet_data_by_tag.keys()
        | net_size_data_by_tag.keys()
        | net_error_data_by_tag.keys()
    )
    for tag in sorted(net_tags):
        dt = zzzz_map.get(tag)
        if not dt:
            continue

        data_vals = net_data_by_tag.get(tag, [])
        pkt_vals = net_packet_data_by_tag.get(tag, [])
        size_vals = net_size_data_by_tag.get(tag, [])
        err_vals = net_error_data_by_tag.get(tag, [])

        # data_vals est stocké en paires [read0,write0, read1,write1, ...]
        for i, iface in enumerate(network_ports):
            doc = {"@timestamp": dt}
            if frame or node or oslevel:
                lpar_info = {}
                if frame:
                    lpar_info["Frame"] = frame
                if node:
                    lpar_info["Node"] = node
                if oslevel:
                    lpar_info["oslevel"] = oslevel
                doc["lpar_info"] = lpar_info

            doc["network_interface"] = iface

            idx_r = 2*i
            idx_w = 2*i + 1

            doc["Network Read KB/s"]      = data_vals[idx_r] if idx_r < len(data_vals) else 0.0
            doc["Network Write KB/s"]     = data_vals[idx_w] if idx_w < len(data_vals) else 0.0

            doc["Network Packet Read/s"]  = pkt_vals[idx_r]  if idx_r < len(pkt_vals)  else 0.0
            doc["Network Packet Write/s"] = pkt_vals[idx_w]  if idx_w < len(pkt_vals)  else 0.0

            doc["Network Read Size"]      = size_vals[idx_r] if idx_r < len(size_vals) else 0.0
            doc["Network Write Size"]     = size_vals[idx_w] if idx_w < len(size_vals) else 0.0

            doc["Network Input Errors"]   = err_vals[idx_r]  if idx_r < len(err_vals)  else 0.0
            doc["Network Output Errors"]  = err_vals[idx_w]  if idx_w < len(err_vals)  else 0.0

            net_docs.append(doc)

    return net_docs

def build_vg_docs(
    zzzz_map, vg_read_data_by_tag, vg_write_data_by_tag, vg_volume_groups,
    frame=None, node=None, oslevel=None
):
    """
    Un doc par volume group
    """
    vg_docs = []
    vg_tags = set(
        zzzz_map.keys()
        | vg_read_data_by_tag.keys()
        | vg_write_data_by_tag.keys()
    )
    for tag in sorted(vg_tags):
        dt = zzzz_map.get(tag)
        if not dt:
            continue
        reads = vg_read_data_by_tag.get(tag, [])
        writes = vg_write_data_by_tag.get(tag, [])

        for i, vg_name in enumerate(vg_volume_groups):
            doc = {"@timestamp": dt}
            if frame or node or oslevel:
                lpar_info = {}
                if frame:
                    lpar_info["Frame"] = frame
                if node:
                    lpar_info["Node"] = node
                if oslevel:
                    lpar_info["oslevel"] = oslevel
                doc["lpar_info"] = lpar_info

            doc["vg_name"] = vg_name
            doc["Disk Read KB/s Volume Group"]  = reads[i]  if i < len(reads)  else 0.0
            doc["Disk Write KB/s Volume Group"] = writes[i] if i < len(writes) else 0.0
            vg_docs.append(doc)
    return vg_docs

def build_jfs_docs(
    zzzz_map, jfsfile_data_by_tag, jfs_filesystems, jfsfile_metric_name,
    frame=None, node=None, oslevel=None
):
    """
    Un doc par filesystem JFS
    """
    jfs_docs = []
    all_tags = set(zzzz_map.keys() | jfsfile_data_by_tag.keys())
    metric_name_no_env = remove_env_suffix(jfsfile_metric_name)
    for tag in sorted(all_tags):
        dt = zzzz_map.get(tag)
        if not dt:
            continue
        if tag not in jfsfile_data_by_tag:
            continue
        vals = jfsfile_data_by_tag[tag]
        for i, fs in enumerate(jfs_filesystems):
            doc = {"@timestamp": dt}
            if frame or node or oslevel:
                lpar_info = {}
                if frame:
                    lpar_info["Frame"] = frame
                if node:
                    lpar_info["Node"] = node
                if oslevel:
                    lpar_info["oslevel"] = oslevel
                doc["lpar_info"] = lpar_info

            doc["filesystem"] = fs
            doc[metric_name_no_env] = vals[i] if i < len(vals) else 0.0
            jfs_docs.append(doc)
    return jfs_docs

################################################################################
# 4) Écriture NDJSON
################################################################################

def write_ndjson(docs, filepath):
    if not docs:
        return
    with open(filepath, "w", encoding="utf-8") as f:
        for doc in docs:
            f.write(json.dumps(doc) + "\n")

################################################################################
# 5) process_file => parse, build docs => NDJSON
################################################################################

def process_file(nmon_file, output_dir):
    base_name = os.path.splitext(os.path.basename(nmon_file))[0]
    parsed = parse_nmon_file(nmon_file)
    (
        cpu_data_by_tag,
        memnew_data_by_tag,
        mem_data_by_tag,
        memuse_data_by_tag,
        lpar_data_by_tag,
        top_data_by_tag,
        page_data_by_tag,
        proc_data_by_tag,
        pools_data_by_tag,
        fc_read_data_by_tag,
        fc_write_data_by_tag,
        fc_xferin_data_by_tag,
        fc_xferout_data_by_tag,
        fc_adapters,
        vg_read_data_by_tag,
        vg_write_data_by_tag,
        vg_volume_groups,
        net_data_by_tag,
        net_packet_data_by_tag,
        net_size_data_by_tag,
        net_error_data_by_tag,
        network_ports,
        disk_read_data_by_tag,
        disk_write_data_by_tag,
        disk_readserv_data_by_tag,
        disk_writeserv_data_by_tag,
        disk_wait_data_by_tag,

        disk_devices,

        diskbusy_data_by_tag,
        diskbusy_devices,

        jfsfile_data_by_tag,
        jfs_filesystems,
        zzzz_map,
        pid_to_uarg,
        uarg_data,
        frame,
        node,
        oslevel,

        # The newly returned file_io_data_by_tag
        file_io_data_by_tag
    ) = parsed

    subdirs = ["all", "top", "fc", "vg", "net", "jfs", "disk", "uargs"]
    for d in subdirs:
        os.makedirs(os.path.join(output_dir, d), exist_ok=True)

    # 1) "all_docs" (CPU, MEM, etc. + FILE I/O)
    all_docs = build_all_docs(
        zzzz_map, 
        cpu_data_by_tag, 
        memnew_data_by_tag, 
        mem_data_by_tag,
        memuse_data_by_tag, 
        lpar_data_by_tag, 
        page_data_by_tag,
        proc_data_by_tag, 
        pools_data_by_tag,
        file_io_data_by_tag
    )
    # On ajoute lpar_info
    for doc in all_docs:
        lpar_info = {}
        if frame:
            lpar_info["Frame"] = frame
        if node:
            lpar_info["Node"] = node
        if oslevel:
            lpar_info["oslevel"] = oslevel
        if lpar_info:
            doc["lpar_info"] = lpar_info

    out_all = os.path.join(output_dir, "all", base_name + "_all.json")
    write_ndjson(all_docs, out_all)
    print(f"Wrote {len(all_docs)} all-docs => {out_all}")

    # 2) "top_docs" => un doc par PID
    top_docs = build_top_docs(zzzz_map, top_data_by_tag, frame, node, oslevel)
    out_top = os.path.join(output_dir, "top", base_name + "_top.json")
    if top_docs:
        write_ndjson(top_docs, out_top)
        print(f"Wrote {len(top_docs)} top docs => {out_top}")
    else:
        print(f"No top docs found => {nmon_file}")

    # 3) "fc_docs" => un doc par adaptateur FC
    fc_docs = build_fc_docs(
        zzzz_map,
        fc_read_data_by_tag, 
        fc_write_data_by_tag,
        fc_xferin_data_by_tag, 
        fc_xferout_data_by_tag,
        fc_adapters, 
        frame, 
        node, 
        oslevel
    )
    out_fc = os.path.join(output_dir, "fc", base_name + "_fc.json")
    write_ndjson(fc_docs, out_fc)
    print(f"Wrote {len(fc_docs)} fc-docs => {out_fc}")

    # 4) "vg_docs" => un doc par volume group
    vg_docs = build_vg_docs(
        zzzz_map, 
        vg_read_data_by_tag, 
        vg_write_data_by_tag, 
        vg_volume_groups,
        frame, 
        node, 
        oslevel
    )
    out_vg = os.path.join(output_dir, "vg", base_name + "_vg.json")
    write_ndjson(vg_docs, out_vg)
    print(f"Wrote {len(vg_docs)} vg-docs => {out_vg}")

    # 5) "net_docs" => un doc par interface réseau
    net_docs = build_net_docs(
        zzzz_map, 
        net_data_by_tag, 
        net_packet_data_by_tag,
        net_size_data_by_tag, 
        net_error_data_by_tag,
        network_ports, 
        frame, 
        node, 
        oslevel
    )
    out_net = os.path.join(output_dir, "net", base_name + "_net.json")
    write_ndjson(net_docs, out_net)
    print(f"Wrote {len(net_docs)} net-docs => {out_net}")

    # 6) "jfs_docs" => un doc par filesystem
    jfs_docs = build_jfs_docs(
        zzzz_map, 
        jfsfile_data_by_tag, 
        jfs_filesystems,
        jfsfile_metric_name="JFS Filespace %Used",
        frame=frame, 
        node=node, 
        oslevel=oslevel
    )
    out_jfs = os.path.join(output_dir, "jfs", base_name + "_jfs.json")
    write_ndjson(jfs_docs, out_jfs)
    print(f"Wrote {len(jfs_docs)} jfs-docs => {out_jfs}")

    # 7) "disk_docs" => un doc par disque
    disk_docs = build_disk_docs(
        zzzz_map,
        disk_read_data_by_tag,
        disk_write_data_by_tag,
        disk_readserv_data_by_tag,
        disk_writeserv_data_by_tag,
        disk_wait_data_by_tag,
        disk_devices,
        diskbusy_data_by_tag,
        diskbusy_devices,
        frame, 
        node, 
        oslevel
    )
    out_disk = os.path.join(output_dir, "disk", base_name + "_disk.json")
    write_ndjson(disk_docs, out_disk)
    print(f"Wrote {len(disk_docs)} disk-docs => {out_disk}")

    # 8) UARGS => on ne change rien (just dumps them)
    out_uargs = os.path.join(output_dir, "uargs", base_name + "_uargs.json")
    if uarg_data:
        with open(out_uargs, "w", encoding="utf-8") as f:
            for rec in uarg_data:
                rec2 = dict(rec)
                # Ajouter le frame/node/oslevel
                if frame:
                    rec2["Frame"] = frame
                if node:
                    rec2["Node"] = node
                if oslevel:
                    rec2["oslevel"] = oslevel
                f.write(json.dumps(rec2) + "\n")
        print(f"Wrote {len(uarg_data)} uargs => {out_uargs}")
    else:
        print(f"No UARG data => {nmon_file}")

################################################################################
# 6) main => parse all *.nmon found in input_dir => NDJSON dans des sous-dossiers
################################################################################

def main():
    parser = argparse.ArgumentParser(
        description="Parse .nmon => NDJSON, subfolders: all, top, fc, vg, net, jfs, disk, uargs."
    )
    parser.add_argument("--input_dir", type=str, required=True, help="Folder with .nmon files")
    parser.add_argument("--output_dir", type=str, required=True, help="NDJSON output folder")
    parser.add_argument("--processes", type=int, default=cpu_count(), help="Number of processes.")
    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    nmon_files = glob.glob(os.path.join(args.input_dir, "*.nmon"))
    if not nmon_files:
        print(f"No .nmon files found in {args.input_dir}")
        return

    tasks = [(fp, args.output_dir) for fp in nmon_files]

    with Pool(processes=args.processes) as p:
        p.starmap(process_file, tasks)

    print("Terminé.")

if __name__ == "__main__":
    main()