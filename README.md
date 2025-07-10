# AmCache-EvilHunter

`AmCache-EvilHunter` is a command-line tool to parse and analyze Windows `Amcache.hve` registry hives, identify evidence of execution, suspicious executables, and integrate VirusTotal lookups for enhanced threat intelligence.

https://github.com/user-attachments/assets/e23fb99b-48ad-4260-b372-2f15e5320c74

## Features

* Parse offline `Amcache.hve` registry hives.
* Filter records by date range (`--start`, `--end`).
* Search records using keywords (`--search`).
* Identify known suspicious executables (`--find-suspicious`).
* Identify executables without a publisher (`--missing-publisher`).
* VirusTotal integration for hash lookups (`--vt`, `--only-detections`).
* Export results to JSON (`--json`) or CSV (`--csv`).

## Requirements

* Python 3.7 or higher
* [requests](https://pypi.org/project/requests/)
* [python-registry](https://pypi.org/project/python-registry/)
* [rich](https://pypi.org/project/rich/)

Install dependencies via `pip`:

```bash
pip3 install -r requirements.txt
```

## Installation

```bash
git clone https://github.com/cristianzsh/amcache-evilhunter.git
cd amcache-evilhunter
pip3 install -r requirements.txt
```

## Usage

```bash
python3 amcache_evilhunter.py -i path/to/Amcache.hve [OPTIONS]
```

### Options

| Flag                 | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `-i`, `--input PATH` | Path to `Amcache.hve` (required)                               |
| `--start YYYY-MM-DD` | Only include records on or after this date                     |
| `--end YYYY-MM-DD`   | Only include records on or before this date                    |
| `--search TERMS`     | Comma-separated, case-insensitive search terms                 |
| `--find-suspicious`  | Filter only records matching known suspicious patterns         |
| `--missing-publisher`| Filter only records with missing Publisher                     |
| `-v`, `--vt`         | Enable VirusTotal lookups (requires `VT_API_KEY` env variable) |
| `--only-detections`  | Show/save only files with ≥1 VT detection                      |
| `--json PATH`        | Path to write full JSON output                                 |
| `--csv PATH`         | Path to write full CSV output                                  |
| `-V`, `--version`    | Show version information                                       |

## Examples

* **Parse and display all records**:

  ```bash
  python3 amcache_evilhunter.py -i Amcache.hve
  ```

* **Filter by date range and search for "notepad"**:

  ```bash
  python3 amcache_evilhunter.py -i Amcache.hve --start 2021-01-01 --end 2021-12-31 --search notepad
  ```

* **Identify suspicious executables and query VirusTotal**:

  ```bash
  python3 amcache_evilhunter.py -i Amcache.hve --find-suspicious -v
  ```

* **Export VirusTotal detections to JSON**:

  ```bash
  export VT_API_KEY=YOUR_API_KEY
  python3 amcache_evilhunter.py -i Amcache.hve -v --only-detections --json detections.json
  ```

## Environment variables

* `VT_API_KEY`: Your VirusTotal API key used for file hash lookups.

## Building executables

A `build.sh` script is provided to generate standalone binaries for both Linux and Windows (via Wine).

```bash
chmod +x build.sh
./build.sh
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
