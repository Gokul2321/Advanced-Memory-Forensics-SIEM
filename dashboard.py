import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, scrolledtext
import threading, time, os, subprocess
from datetime import datetime
import matplotlib.pyplot as plt

MEMORY_FILE = "/home/kali/memory_dump.lime"
STRINGS_FILE = "/home/kali/raw_strings.txt"
VOL_FILE = "/home/kali/vol_output.txt"
LOG_FILE = "/home/kali/analysis_log.txt"
VOL_PATH = "/home/kali/volatility3/vol.py"

alerts_global = []
MONITORING = False

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def update_status(msg, color="cyan"):
    status_label.config(text=msg, fg=color)
    root.update()

def extract_data():
    def task():
        update_status("Extracting memory...", "cyan")
        os.system(f"strings {MEMORY_FILE} > {STRINGS_FILE}")
        update_status("Extraction complete", "green")
    threading.Thread(target=task).start()

def run_volatility():
    def task():
        update_status("Running Volatility...", "cyan")
        plugins = ["linux.pslist","linux.netscan","linux.malfind"]
        output = ""
        for p in plugins:
            try:
                out = subprocess.getoutput(f"python3 {VOL_PATH} -f {MEMORY_FILE} {p}")
                output += out + "\n"
            except:
                pass
        open(VOL_FILE,"w").write(output)
        update_status("Volatility complete", "green")
    threading.Thread(target=task).start()

def attack_mode():
    def task():
        update_status("Launching real attacks...", "red")

        subprocess.Popen("nc -lvp 4444", shell=True)

        os.system("echo 'malicious code' > /tmp/malware.sh")
        os.system("chmod +x /tmp/malware.sh")

        subprocess.Popen("nmap -sS 127.0.0.1", shell=True)

        os.system(f"echo 'mimikatz rootkit trojan keylogger' >> {STRINGS_FILE}")

        update_status("Attack Mode Active", "red")
        messagebox.showwarning("Attack Mode","Real attack simulation running")

    threading.Thread(target=task).start()

def get_live():
    ps = subprocess.getoutput("ps aux")
    net = subprocess.getoutput("ss -tulnp")
    tmp = " ".join(os.listdir("/tmp"))
    return (ps + net + tmp).lower()

def detect():
    def task():
        global alerts_global
        update_status("Analyzing...", "yellow")

        alerts = []

        try:
            data = open(STRINGS_FILE).read().lower()
        except:
            data = ""

        try:
            vol = open(VOL_FILE).read().lower()
        except:
            vol = ""

        live = get_live()

        def add(level, msg):
            if not any((msg == a[1] and level == a[0]) for a in alerts):
                alerts.append((level, msg, now()))

        def clean(keyword):
            return (
                keyword in data and
                "/usr/share" not in data and
                ".desktop" not in data and
                "kali-" not in data
            )


        if "nc" in live and "4444" in live and ("bash -i" in data or "sh -i" in data):
            add("HIGH", "Reverse shell confirmed")

        elif "4444" in live and ("nc" in live or "python" in live):
            add("HIGH", "Backdoor port active")

        if clean("mimikatz") and ("invoke" in data or "password" in data):
            add("HIGH", "Credential dumping activity")

        if "rootkit" in data and "hidden module" in data:
            add("HIGH", "Rootkit behavior detected")

        if "trojan" in data and "/tmp" in data:
            add("HIGH", "Trojan execution detected")

        if ("sudo su" in data or "sudo -i" in data) and "pts/" in live:
            add("HIGH", "Privilege escalation activity")

        if ("wget http" in data or "curl http" in data) and "/tmp" in data:
            add("MEDIUM", "Suspicious payload download")

        if "injected" in vol or "shellcode" in vol:
            add("MEDIUM", "Memory injection detected")

        if "unknown" in data and "/tmp" in data:
            add("MEDIUM", "Unknown binary execution")

        if "keylogger" in data and ("capture keystrokes" in data or "log keys" in data):
            add("LOW", "Keylogger behavior")

        if "bash -i" in data and "tcp" in data:
            add("LOW", "Interactive shell activity")

        alerts_global = alerts
        score = min(100, len(alerts) * 10)

        box_all.delete(1.0, tk.END)
        box_high.delete(1.0, tk.END)
        box_medium.delete(1.0, tk.END)
        box_low.delete(1.0, tk.END)

        box_all.insert(tk.END, f"\n=== THREAT SCORE: {score}% ===\n\n")

        for l, m, t in alerts:
            line = f"[{t}] [{l}] {m}\n"
            box_all.insert(tk.END, line)

            if l == "HIGH":
                box_high.insert(tk.END, line)
            elif l == "MEDIUM":
                box_medium.insert(tk.END, line)
            else:
                box_low.insert(tk.END, line)

        with open(LOG_FILE, "a") as f:
            for l, m, t in alerts:
                f.write(f"{t} [{l}]: {m}\n")

        update_status("Analysis complete", "green")

        if any(l == "HIGH" for l, _, _ in alerts):
            tab_control.select(tab_high)

    threading.Thread(target=task).start()
def mitigate():
    def task():
        update_status("Mitigating threats...", "orange")

        subprocess.run(["sudo","pkill","-9","-f","nc"])
        subprocess.run(["sudo","pkill","-9","-f","bash"])
        subprocess.run(["sudo","pkill","-9","-f","nmap"])

        subprocess.run(["sudo","fuser","-k","4444/tcp"])

        for f in os.listdir("/tmp"):
            if "mal" in f:
                os.remove(f"/tmp/{f}")

        subprocess.run(["sudo","iptables","-F"])

        update_status("System secured","green")
        messagebox.showinfo("Mitigation","Threats stopped successfully")

    threading.Thread(target=task).start()

def show_level(level):
    win = tk.Toplevel(root)
    win.title(level+" Threats")

    txt = scrolledtext.ScrolledText(win,width=80,height=20)
    txt.pack()

    for l,m,t in alerts_global:
        if l==level:
            txt.insert(tk.END,f"[{t}] {m}\n")

def show_graph():
    try:
        data = open(LOG_FILE).read()
    except:
        return

    h = data.count("HIGH")
    m = data.count("MEDIUM")
    l = data.count("LOW")

    plt.pie([h,m,l],labels=["High","Medium","Low"],autopct="%1.1f%%")
    plt.title("Threat Distribution")
    plt.show()

def start_monitor():
    global MONITORING
    MONITORING = True

    def loop():
        while MONITORING:
            extract_data()
            run_volatility()
            detect()
            time.sleep(10)

    threading.Thread(target=loop).start()

def stop_monitor():
    global MONITORING
    MONITORING = False

root = tk.Tk()
root.title("Advanced Memory Forensics SIEM")
root.geometry("1100x700")
root.configure(bg="#0f172a")

title = tk.Label(root,text="Advanced Memory Forensics Dashboard",
                 fg="white",bg="#0f172a",font=("Arial",18,"bold"))
title.pack()

status_label = tk.Label(root,text="STATUS: READY",fg="cyan",bg="#0f172a")
status_label.pack()

frame = tk.Frame(root,bg="#0f172a")
frame.pack(pady=10)

def btn(t,c,col):
    return tk.Button(frame,text=t,command=c,bg=col,fg="white",width=18,height=2)

buttons = [
("Extract Data",extract_data,"#3b82f6"),
("Run Volatility",run_volatility,"#06b6d4"),
("Detect Threats",detect,"#ef4444"),
("Attack Mode",attack_mode,"#8b5cf6"),

("Mitigate",mitigate,"#f59e0b"),
("Start Monitoring",start_monitor,"#10b981"),
("Stop Monitoring",stop_monitor,"#64748b"),
("High Threats",lambda:show_level("HIGH"),"#dc2626"),

("Medium Threats",lambda:show_level("MEDIUM"),"#f97316"),
("Low Threats",lambda:show_level("LOW"),"#22c55e"),
("Show Graph",show_graph,"#14b8a6")
]

for i,(t,c,col) in enumerate(buttons):
    btn(t,c,col).grid(row=i//4,column=i%4,padx=5,pady=5)

tab_control = ttk.Notebook(root)

tab_all = tk.Frame(tab_control)
tab_high = tk.Frame(tab_control)
tab_medium = tk.Frame(tab_control)
tab_low = tk.Frame(tab_control)

tab_control.add(tab_all, text="All")
tab_control.add(tab_high, text="High")
tab_control.add(tab_medium, text="Medium")
tab_control.add(tab_low, text="Low")

tab_control.pack(expand=1, fill="both")

box_all = scrolledtext.ScrolledText(tab_all,width=120,height=25,bg="#020617",fg="white")
box_high = scrolledtext.ScrolledText(tab_high,width=120,height=25,bg="#020617",fg="white")
box_medium = scrolledtext.ScrolledText(tab_medium,width=120,height=25,bg="#020617",fg="white")
box_low = scrolledtext.ScrolledText(tab_low,width=120,height=25,bg="#020617",fg="white")

box_all.pack()
box_high.pack()
box_medium.pack()
box_low.pack()

root.mainloop()
