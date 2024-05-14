import struct
import time
import csv
import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import win32evtlog
import xlsxwriter

# Constants
event_type_enum = {0: 'Success', 1: 'Error', 2: 'Warning', 4: 'Information', 8: 'SuccessAudit', 16: 'FailureAudit'}

# Function to read Windows Event Logs
def read_event_logs(log_type='System', max_records=1000):
    logs = []
    computer = None  # Use None for the local computer
    log_handle = win32evtlog.OpenEventLog(computer, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)
    num_records = min(total_records, max_records)

    events = win32evtlog.ReadEventLog(log_handle, flags, 0)
    evt_dict = {win32evtlog.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
                win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
                win32evtlog.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
                win32evtlog.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
                win32evtlog.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'}

    for event in events:
        timestamp = event.TimeGenerated.Format()
        event_type = event.EventType
        event_category = evt_dict.get(event_type, 'Unknown')
        event_message = event.StringInserts

        # Convert tuple to string if event_message is a tuple
        if isinstance(event_message, tuple):
            event_message = ', '.join(event_message)

        logs.append({'Timestamp': timestamp, 'Event Type': event_type_enum.get(event_type, 'Unknown'),
                     'Event Category': event_category, 'Event Message': event_message})

    win32evtlog.CloseEventLog(log_handle)
    return logs

# Function to visualize event logs
def visualize_logs(logs, log_type):
    entry_types = [log['Event Type'] for log in logs]
    entry_type_counts = {entry_type: entry_types.count(entry_type) for entry_type in set(entry_types)}

    labels = list(entry_type_counts.keys())
    values = list(entry_type_counts.values())

    # Create bar chart
    fig, ax = plt.subplots()
    ax.bar(labels, values)
    ax.set_xlabel('Entry Type')
    ax.set_ylabel('Count')
    ax.set_title(f'{log_type} Entry Type Counts')

    return fig

# Function to display visualization in GUI
def display_visualization_in_gui(fig):
    root = tk.Tk()
    root.title("Event Log Entry Type Counts")

    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.draw()
    canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    tk.mainloop()

# Function to write logs to Excel file
def write_logs_to_excel(system_logs, app_logs):
    # Create a new Excel workbook
    workbook = xlsxwriter.Workbook('event_logs.xlsx')
    
    # Add a worksheet for system logs
    system_sheet = workbook.add_worksheet('System Logs')
    system_sheet.write_row(0, 0, ['Timestamp', 'Event Type', 'Event Category', 'Event Message'])
    for i, log in enumerate(system_logs, start=1):
        system_sheet.write_row(i, 0, [log['Timestamp'], log['Event Type'], log['Event Category'], log['Event Message']])
    
    # Add a worksheet for application logs
    app_sheet = workbook.add_worksheet('Application Logs')
    app_sheet.write_row(0, 0, ['Timestamp', 'Event Type', 'Event Category', 'Event Message'])
    for i, log in enumerate(app_logs, start=1):
        app_sheet.write_row(i, 0, [log['Timestamp'], log['Event Type'], log['Event Category'], log['Event Message']])
    
    workbook.close()

if __name__ == "__main__":
    system_logs = read_event_logs(log_type='System', max_records=1000)
    app_logs = read_event_logs(log_type='Application', max_records=1000)
    
    system_fig = visualize_logs(system_logs, 'System')
    app_fig = visualize_logs(app_logs, 'Application')
    
    display_visualization_in_gui(system_fig)
    display_visualization_in_gui(app_fig)
    
    # Write logs to Excel file
    write_logs_to_excel(system_logs, app_logs)
