from scapy.all import *
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import ctypes
import subprocess
import sys
import os

# Windows 权限检查
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# 关闭系统默认 ICMP 回应
def block_icmp():
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                        "name=Block ICMP", "protocol=icmpv4", "dir=in", "action=block"],
                       check=True)
    except Exception as e:
        print("无法阻止系统 ICMP 响应:", str(e))

# 恢复系统 ICMP 回应
def unblock_icmp():
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        "name=Block ICMP"], check=True)
    except:
        pass


class PingSpooferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ICMP Ping伪造工具 --Dysprosium[safe049]")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        self.running = False
        self.sniff_thread = None
        self.interface = None

        self.create_widgets()

        # 检查管理员权限
        if not is_admin():
            messagebox.showerror("权限错误", "请以管理员身份运行此程序!")
            self.root.after(100, self.root.destroy)

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        settings_frame = ttk.LabelFrame(main_frame, text="设置", padding="10")
        settings_frame.pack(fill=tk.X, pady=5)

        # Ping延迟设置
        ttk.Label(settings_frame, text="[±30波动]伪造的Ping延迟(ms):").grid(row=0, column=0, sticky=tk.W)
        self.ping_delay = tk.IntVar(value=10)
        ttk.Entry(settings_frame, textvariable=self.ping_delay, width=10).grid(row=0, column=1, sticky=tk.W)

        # 网络接口选择
        ttk.Label(settings_frame, text="网络接口:").grid(row=1, column=0, sticky=tk.W)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(settings_frame, textvariable=self.interface_var)
        self.interface_combo.grid(row=1, column=1, sticky=tk.EW)
        self.interface_combo['values'] = self.get_network_interfaces()
        if self.interface_combo['values']:
            self.interface_combo.current(0)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        self.start_button = ttk.Button(button_frame, text="启动", command=self.start_spoofing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="停止", command=self.stop_spoofing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        log_frame = ttk.LabelFrame(main_frame, text="日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, height=8, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text['yscrollcommand'] = scrollbar.set

    def get_network_interfaces(self):
        """获取可用的网络接口"""
        try:
            return [iface.name for iface in ifaces.values()]
        except:
            return ["以太网", "WLAN", "本地连接", "Loopback", "TAP-Windows Adapter V9"]

    def log_message(self, message):
        """在日志区域添加消息"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def fake_ping_response(self, pkt):
        """处理ICMP请求并发送伪造响应"""
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # ICMP请求(ping)
            src_ip = pkt[IP].dst
            dst_ip = pkt[IP].src
            id = pkt[ICMP].id
            seq = pkt[ICMP].seq

            reply = IP(src=src_ip, dst=dst_ip)/ICMP(type=0, id=id, seq=seq)/pkt[ICMP].payload

            current_time = time.time()
            request_time = pkt.time
            elapsed = (current_time - request_time) * 1000  # 实际耗时(ms)

            target_delay = self.ping_delay.get()
            if elapsed < target_delay:
                time.sleep((target_delay - elapsed) / 1000.0)

            send(reply, verbose=0, iface=self.interface)

            self.root.after(0, self.log_message,
                          f"伪造Ping响应: {dst_ip} -> {src_ip} (延迟: {target_delay}ms)")

    def start_spoofing(self):
        if self.running:
            return

        block_icmp()  # 关闭系统默认 ICMP 响应

        self.interface = self.interface_var.get()
        target_delay = self.ping_delay.get()

        if target_delay <= 0:
            messagebox.showerror("错误", "延迟时间必须大于0")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

        self.log_message(f"启动ICMP Ping伪造服务，所有Ping将显示为{target_delay}ms延迟")
        self.log_message(f"监听接口: {self.interface}")

    def stop_spoofing(self):
        if not self.running:
            return

        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        unblock_icmp()  # 恢复系统 ICMP 响应

        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)

        self.log_message("已停止ICMP Ping伪造服务")

    def sniff_packets(self):
        filter_str = "icmp and icmp[0] == 8"  # 只捕获ICMP请求

        try:
            sniff(
                filter=filter_str,
                prn=self.fake_ping_response,
                store=0,
                iface=self.interface,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.root.after(0, self.log_message, f"错误: {str(e)}")
            self.root.after(0, self.stop_spoofing)

    def on_closing(self):
        if self.running:
            self.stop_spoofing()
        self.root.destroy()


if __name__ == "__main__":
    # 检查 Scapy 是否安装
    try:
        from scapy.all import *
    except ImportError:
        print("错误: 需要安装scapy库 (pip install scapy)")
        sys.exit(1)

    # 重新启动自身为管理员（如果需要）
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, os.path.abspath(sys.argv[0]), None, 1)
        sys.exit()

    root = tk.Tk()
    app = PingSpooferApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
