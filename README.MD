
# Packet Sniffer

A simple command line sniffer/PCAP parser for an Anime game.

## Setup Python

[Py 3.10](https://www.python.org/downloads/release/python-3100/)
Scroll to Files near the bottom, grab the Windows installer (64-bit)

For the install, make sure to add py 3.10 to PATH (can be done in last step as well)
Select Custom Install, Can Deselect tcl/tk, Python Test Suit.

Once Python 3.10 is installed and in the Path, we can open a Terminal.


## Setup Pipenv (highly recommended)
Use the Python package Manager, PIP to install pipenv. Not using a virtual env could make this impossible to use.

```
pip install pipenv
```


## Usage

Before use, set up the environment and install the necessary dependencies:

```
pipenv install
-OR-
pip install -r requirements.txt
```

To start using the script, run:
```
pipenv run python sniffer.py --output <OUTPUT_PATH>
-OR-
py sniffer.py --output <OUTPUT_PATH>
```

If you want to exclude certain packets from being logged to the console, you can use `--exclude`, for example

```
pipenv run python sniffer.py --exclude SyncTimeReq SyncTimeRsp --output <OUTPUT_PATH>
```

If you want to include certain packets from being logged to the console, you can use `--include`, for example

```
pipenv run python sniffer.py --include UltraEndlessGetMainDataRsp UltraEndlessGetTopRankRsp GetExBossRankRsp
```

Make sure to end the script with `CTRL+C` to get the output.json

Reading .pcap files to .json seems broken. Will Fix soon TM.