import struct
import time
import re
import sys
import csv
import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# Constants
event_type_enum = {0: 'Success', 1: 'Error', 2: 'Warning', 4: 'Information', 8: 'SuccessAudit', 16: 'FailureAudit'}
source_encoding = 'utf-16le'
header_log_magic = b"\x4c\x66\x4c\x65"
header_size = 0x30

# Function to convert binary SID to ASCII
def bin_sid_to_ascii(sid_str):
    rest = sid_str[8:]
    first = struct.unpack('BBBBBBBB', sid_str[0:8])
    auth = ((first[2] << 40) | (first[3] << 32) | (first[4] << 24) | (first[5] << 16) | (first[6] << 8) | first[7])
    result = "S-%d-%d" % (first[0], auth)
    for i in range(0, first[1]):
        if len(rest) >= 4:
            next_int = struct.unpack('<I', rest[:4])[0]
            rest = rest[4:]
            result = "%s-%d" % (result, next_int)
    return result

# Function to read CSV file
def read_csv(filename):
    data = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data.append(row)
    return data

# Function to format message
def format_message(fmt, vars):
    state = 0
    ret_val = ''
    arg_num = ''
    arg_index = None
    extended_fmt = ''
    for c in fmt:
        if state == 0:
            arg_index = None
            arg_num = ''
            if c == '%':
                state = 1
            else:
                ret_val += c
        elif state == 1:
            if len(arg_num) == 0:
                if 0x30 < ord(c) < 0x3a:
                    arg_num = c
                elif c in ('0', 'b', 't', 'r', '\\', 'n'):
                    ret_val += {'0': '\x00', 'b': ' ', 't': '\x09', 'r': '\x0d', '\\': '\x0a', 'n': '\x0d\x0a'}[c]
                    state = 0
                else:
                    ret_val += c
                    state = 0
            elif len(arg_num) == 1:
                if 0x2f < ord(c) < 0x3a:
                    arg_index = int(arg_num + c) - 1
                else:
                    if arg_index is None:
                        arg_index = int(arg_num) - 1
                    if c == '!':
                        state = 3
                        extended_fmt = '%'
                    else:
                        if arg_index < len(vars):
                            if c == '%':
                                ret_val += "%s" % vars[arg_index]
                                state = 1
                                arg_num = ''
                                arg_index = None
                            else:
                                ret_val += "%s%s" % (vars[arg_index], c)
                                state = 0
                        else:
                            if c == '%':
                                ret_val += "%%%s" % arg_num
                                state = 1
                                arg_num = ''
                                arg_index = None
                            else:
                                ret_val += "%%%s%s" % (arg_num, c)
                                state = 0
        elif state == 3:
            if c == '!':
                state = 0
                ret_val += wsprintf(extended_fmt, vars[arg_index])
            else:
                extended_fmt += c
    return ret_val

# Function to guess record type
def guess_record_type(record, wrapped=False):
    ret_val = 'unknown'
    if len(record) == header_size:
        magic = record[4:4 + len(header_log_magic)]
        if magic == header_log_magic:
            ret_val = 'header'
    return ret_val

# Class to handle Event Log files
class EventFile:
    def __init__(self, filename, message_repository, parse_meta=1):
        self.f = open(filename, "rb")
        self.mr = message_repository

        if parse_meta:
            if self.guess_record_type() != 'header':
                sys.stderr.write("WARNING: Could not find header record.\n")
                self.f.seek(0)
                return
            self.header = self.get_header_record()
            self.f.seek(self.header['next_off'])

    def tell(self):
        return self.f.tell()

    def seek(self, off, whence=0):
        self.f.seek(off, whence)

    # Function to guess record type
    def guess_record_type(self):
        if not self.f:
            raise IOError("Log file not open.")
        wrapped_log = False
        ret_val = 'unknown'
        cur_pos = self.f.tell()
        raw_str = self.f.read(4)
        if len(raw_str) == 4:
            (size1,) = struct.unpack('<I', raw_str)
            if size1 >= header_size:
                raw_str = self.f.read(4)
                if len(raw_str) == 4:
                    (size2,) = struct.unpack('<I', raw_str)
                    if size1 == size2:
                        self.f.seek(cur_pos)
                        raw_str = self.f.read(size1)
                        if len(raw_str) == size1:
                            ret_val = guess_record_type(raw_str, wrapped_log)
        self.f.seek(cur_pos)
        return ret_val

    # Function to get header record
    def get_header_record(self):
        fmt = '<IIIIIIIIIIII'
        fmt_len = struct.calcsize(fmt)
        raw_rec = self.f.read(fmt_len)
        if len(raw_rec) < fmt_len:
            raise EOFError("Record read is too short for format.")
        (size1, lfle, unknown1, unknown2,
         first_off, next_off, next_num, first_num,
         file_size, flags, retention, size2) = struct.unpack(fmt, raw_rec)
        flag_dirty = flags & 0x1
        flag_wrapped = (flags & 0x2) >> 1
        flag_logfull = (flags & 0x4) >> 2
        flag_primary = (flags & 0x8) >> 3
        ret_val = {'first_off': first_off, 'first_num': first_num,
                   'next_off': next_off, 'next_num': next_num,
                   'file_size': file_size, 'retention': retention,
                   'flag_dirty': flag_dirty, 'flag_wrapped': flag_wrapped,
                   'flag_logfull': flag_logfull, 'flag_primary': flag_primary}
        return ret_val

    # Function to get log record
    def get_log_record(self):
        # Implementation of getLogRecord method from original code
        pass

#Implementation
if __name__ == "__main__":
    filename = filename = "D:\GIt\log_analyzer\Booksss.csv"  # Provide the filename here
    data = read_csv(filename)
    print(data)  # Or do whatever processing you need with the 'data' list

# Further thinking of implementing
#if __name__ == "__main__":
 #   filename = "example.evtx"  # Provide the filename here
  #  message_repository = None  # You need to define this or import it from somewhere
   # evt_file = EventFile(filename, message_repository)
    # Now you can use evt_file to work with the event log file




# Function to read CSV file
def read_csv(filename):
    data = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data.append(row)
    return data

# Function to visualize data
def visualize_data(data):
    entry_types = [row['EntryType'] for row in data]
    entry_type_counts = {entry_type: entry_types.count(entry_type) for entry_type in set(entry_types)}

    labels = list(entry_type_counts.keys())
    values = list(entry_type_counts.values())

    # Create bar chart
    fig, ax = plt.subplots()
    ax.bar(labels, values)
    ax.set_xlabel('Entry Type')
    ax.set_ylabel('Count')
    ax.set_title('Entry Type Counts')

    return fig

# Function to display visualization in GUI
def display_visualization_in_gui(fig):
    root = tk.Tk()
    root.title("Entry Type Counts")

    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.draw()
    canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    tk.mainloop()

if __name__ == "__main__":
    filename = "D:/GIt/log_analyzer/Booksss.csv"  # Provide the filename here
    data = read_csv(filename)
    fig = visualize_data(data)
    display_visualization_in_gui(fig)
