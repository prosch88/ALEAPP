__artifacts_v2__ = {
    "alex_live_appops": {
        "name": "App Ops",
        "description": "Reads App Ops Data \
            from a PRFS backup created by ALEX.",
        "author": "@C_Peter",
        "creation_date": "2026-01-30",
        "last_update_date": "2026-01-30",
        "requirements": "none",
        "category": "ALEX Live Data",
        "notes": "",
        "paths": ('*/extra/app_ops.json'),
        "output_types": ["html", "lava", "tsv"],
        "artifact_icon": "package"
    },
    "alex_live_wifi_conf_net": {
        "name": "Dumpsys - Configured Networks",
        "description": "Outputs the configured \
            (known) networks from the Dumpsys \
                log of an ALEX PRFS backup.",
        "author": "@C_Peter",
        "creation_date": "2026-02-02",
        "last_update_date": "2026-02-02",
        "requirements": "none",
        "category": "ALEX Live Data",
        "notes": "",
        "paths": ('*/extra/dumpsys_*.txt'),
        "output_types": ["html", "lava", "tsv"],
        "artifact_icon": "wifi"
    },
    "alex_live_usagestats_events": {
        "name": "Dumpsys - Usagestats Events",
        "description": "Outputs the Usagestats \
            Event entries from the Dumpsys \
                log of an ALEX PRFS backup.",
        "author": "@C_Peter",
        "creation_date": "2026-02-03",
        "last_update_date": "2026-02-03",
        "requirements": "none",
        "category": "ALEX Live Data",
        "notes": "",
        "paths": ('*/extra/dumpsys_*.txt'),
        "output_types": ["html", "lava", "tsv"],
        "artifact_icon": "activity"
    }
}

import json
import re
import os
import datetime
from scripts.ilapfuncs import artifact_processor, \
    get_file_path, logfunc

_PARSED_DUMPSYS = False
_DUMPSYS_DICT = {}
_DEVICE_TIME = 0

# Timestamp Helper - Converts to UNIX Timestamp
def parse_timestamp(s, device_ts):
    if not s or not isinstance(s, str):
        return None
    # ISO format: 2026-02-02T05:37:49.732
    try:
        dt = datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    except (ValueError, IndexError):
        pass
    # Short format: 07-21 03:37:00.040
    if device_ts is None:
        return None
    try:
        device_dt = datetime.datetime.fromtimestamp(device_ts, tz=datetime.timezone.utc)
        if len(s) < 5 or s[2] != '-' or s[5] != ' ':
            return None
        month = int(s[0:2])
        day = int(s[3:5])
        year = device_dt.year
        if (month, day) > (device_dt.month, device_dt.day):
            year -= 1
        full_ts = f"{year}-{s}"
        dt = datetime.datetime.strptime(full_ts, "%Y-%m-%d %H:%M:%S.%f")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    except (ValueError, IndexError, TypeError):
        return None

# Helper to split the Dumpsys Output
def split_dumpsys_log(dumpsys_file) -> dict:
    global _PARSED_DUMPSYS, _DUMPSYS_DICT, _DEVICE_TIME
    if _PARSED_DUMPSYS:
        return
    if not dumpsys_file:
        return

    ds_filename = os.path.basename(dumpsys_file)
    try:
        _DEVICE_TIME = int(ds_filename.split('_', 1)[1].split('.', 1)[0])
    except (ValueError, IndexError):
        logfunc("Dumpsys File does not contain a unix timestamp")

    with open(dumpsys_file, "r", encoding="utf-8", errors="ignore") as f:
        log_txt = f.read()

    dumpdict = {}
    start_re = re.compile(r"DUMP OF SERVICE\s+(\S+):")
    duration_re = re.compile(
        r"([\d.]+)s\s+was the duration of dumpsys.*ending at:\s+(.+)$"
    )

    current_service = None
    current_lines = []
    current_start_ts = None

    def flush():
        if current_service:
            dumpdict[current_service] = (
                "\n".join(current_lines),
                current_start_ts
            )

    for line in log_txt.splitlines():
        start_match = start_re.search(line)
        if start_match:
            flush()
            current_service = start_match.group(1)
            current_lines = []
            current_start_ts = None
            continue

        if not current_service:
            continue

        current_lines.append(line)

        dur_match = duration_re.search(line)
        if dur_match:
            duration_s = float(dur_match.group(1))
            end_time = datetime.datetime.strptime(
                dur_match.group(2).strip(),
                "%Y-%m-%d %H:%M:%S"
            )
            current_start_ts = (
                end_time - datetime.timedelta(seconds=duration_s)
            ).timestamp()

    flush()
    _DUMPSYS_DICT = dumpdict
    _PARSED_DUMPSYS = True

# Dumpsys - Wifi - Configured Networks
@artifact_processor
def alex_live_wifi_conf_net(files_found, _report_folder, _seeker, _wrap_text):
    global _PARSED_DUMPSYS, _DUMPSYS_DICT, _DEVICE_TIME
    source_path = files_found[0]
    data_list = []
    split_dumpsys_log(source_path)
    wifi_dump, wifi_ts = _DUMPSYS_DICT.get("wifi", (None, None))
    if wifi_dump == None:
        logfunc('Dumpsys does not include a \"wifi\" part.')
    else:
        ID_RE = re.compile(r'^\s*[*-]?\s*(DSBLE ID|ID):\s*(\d+)')
        SECTION_BREAK_RE = re.compile(r'^(Dump of|DUMP OF SERVICE|WifiConfigManager|WifiConfigStore)')
        FIELD_PATTERNS = {
            "ssid": re.compile(r'SSID:\s*"([^"]*)"'),
            "bssid": re.compile(r'BSSID:\s*(\S+)'),
            "hidden": re.compile(r'HIDDEN:\s*(\S+)'),
            "creation_millis": re.compile(r'creation millis:\s*(\d+)'),
            "creation_time": re.compile(r'creationtime=([0-9\-:\.\s]+)|creation time=([0-9\-:\.\s]+)'),
            "randomized_mac": re.compile(r'^\s*[*-]?\s*mRandomizedMacAddress:\s*([0-9a-fA-F:]{17})', re.IGNORECASE),
            "last_connected": re.compile(r'lastConnected:\s*([^\s]+)'),
            "autojoin": re.compile(r'autojoin\s*:\s*(\d+)|allowAutojoin=(true|false)', re.IGNORECASE),
        }

        in_section = False
        current = None
        current_key = None
        blank_count = 0

        for line in wifi_dump.splitlines():
            stripped = line.strip()

            if "Configured networks" in line:
                in_section = True
                continue
            if not in_section:
                continue

            if SECTION_BREAK_RE.match(stripped):
                if current_key is not None:
                    data_list.append((net_id, create_time, last_connected_time, ssid,
                                    bssid, dsble, hidden, randomized_mac, autojoin))
                current_key = None
                in_section = False
                continue

            m_id = ID_RE.match(line)
            if m_id:
                if current_key is not None:
                    data_list.append((net_id, create_time, last_connected_time, ssid,
                                    bssid, dsble, hidden, randomized_mac, autojoin))


                id_type, id_value = m_id.groups()
                net_id = int(id_value)
                dsble = (id_type == "DSBLE ID")
                current_key = net_id

                ssid = bssid = hidden = None
                creation_millis = creation_time = None
                randomized_mac = last_connected = autojoin = None
                create_time = last_connected_time = None

            if current_key is not None:
                for key, pattern in FIELD_PATTERNS.items():
                    m = pattern.search(line)
                    if m:
                        if key == "autojoin":
                            if m.group(1) is not None:
                                autojoin = int(m.group(1))
                            elif m.group(2) is not None:
                                autojoin = 1 if m.group(2).lower() == "true" else 0
                        elif key == "creation_time":
                            creation_time = m.group(1) or m.group(2)
                        else:
                            value = m.group(1)
                            if key == "ssid":
                                ssid = value
                            elif key == "bssid":
                                bssid = value
                            elif key == "hidden":
                                hidden = value
                            elif key == "creation_millis":
                                creation_millis = value
                            elif key == "creation_time":
                                creation_time = value
                            elif key == "randomized_mac":
                                randomized_mac = value
                            elif key == "last_connected":
                                last_connected = value
                            elif key == "autojoin":
                                autojoin = value

                if creation_millis:
                    create_time = datetime.datetime.fromtimestamp(int(creation_millis)//1000, tz=datetime.timezone.utc)
                elif creation_time and creation_time != None:
                    create_time = datetime.datetime.fromtimestamp(parse_timestamp(creation_time, _DEVICE_TIME), tz=datetime.timezone.utc)
                if last_connected:
                    last_connected_time = datetime.datetime.fromtimestamp(parse_timestamp(last_connected, _DEVICE_TIME), tz=datetime.timezone.utc)

        if current_key is not None:
            data_list.append((net_id, create_time, last_connected_time, ssid,
                            bssid, dsble, hidden, randomized_mac, autojoin))
            
    data_headers = ('ID', ('Creation Time', 'datetime'), ('Last Connected', 'datetime'), 'SSID', 'BSSID', 'DSBLE', 'Hidden', 'Random MAC', 'Autojoin')

    return data_headers, data_list, source_path

# Dumpsys - Usagestats - Events
@artifact_processor
def alex_live_usagestats_events(files_found, _report_folder, _seeker, _wrap_text):
    global _PARSED_DUMPSYS, _DUMPSYS_DICT, _DEVICE_TIME
    source_path = files_found[0]
    data_list = []
    split_dumpsys_log(source_path)
    us_dump, us_ts = _DUMPSYS_DICT.get("usagestats", (None, None))
    if us_dump == None:
        logfunc('Dumpsys does not include a \"usagestats\" part.')
    else:
        PAIR_RE = re.compile(r'(\w+)=(".*?"|\S+)')
        data_list = []

        for line in us_dump.splitlines():
            stripped = line.strip()

            if not stripped.startswith("time=") or "type=" not in stripped or "package=" not in stripped:
                continue

            pairs = dict(
                (k, v.strip('"'))
                for k, v in PAIR_RE.findall(stripped))
            time = pairs.pop("time", None)
            event_type = pairs.pop("type", None)
            package = pairs.pop("package", None)
            reason = pairs.pop("reason", None)
            extra_data = pairs

            data_list.append((time, event_type, package, extra_data, reason))
    data_headers = (('Time', 'datetime'), 'Event Type', 'Package', 'Event', 'Reason')

    return data_headers, data_list, source_path

# App Ops
@artifact_processor
def alex_live_appops(files_found, _report_folder, _seeker, _wrap_text):
    source_path = get_file_path(files_found, "app_ops.json")
    data_list = []
    
    try:
        with open(source_path, "r", encoding="utf-8") as app_ops_file:
            app_ops_data = json.load(app_ops_file)
        for package, permissions in app_ops_data.items():
            for permission, value in permissions.items():
                state = None
                allowtime = None
                rejecttime = None
                if isinstance(value, str):
                    if value == "ignore":
                        continue
                    state = value
                elif isinstance(value, list):
                    state = value[0]
                    if state == "ignore":
                        continue
                    for entry in value[1:]:
                        if not isinstance(entry, dict):
                            continue
                        if "time" in entry:
                            try:
                                if isinstance(entry["time"], int):
                                    atime = entry["time"]
                                else:
                                    atime = int(entry["time"].split()[0])
                                allowtime = datetime.datetime.fromtimestamp(atime, tz=datetime.timezone.utc)
                            except ValueError:
                                pass
                        if "rejectTime" in entry:
                            try:
                                if isinstance(entry["rejectTime"], int):
                                    rtime = entry["rejectTime"]
                                else:
                                    rtime = int(entry["rejectTime"].split()[0])
                                rejecttime = datetime.datetime.fromtimestamp(rtime, tz=datetime.timezone.utc)
                            except ValueError:
                                pass
                data_list.append((allowtime, rejecttime, package, permission, state))  
    except (OSError, UnicodeDecodeError):
        pass

    data_headers = (('Access Timestamp', 'datetime'), ('Reject Timestamp', 'datetime'), 'Package Name', 'Permission', 'Value')

    return data_headers, data_list, source_path

