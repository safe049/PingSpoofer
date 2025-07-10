from scapy.all import *
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os
import sys

class PingSpooferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ICMP Ping伪造工具 --Dysprosium[safe049]")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        # 运行状态
        self.running = False
        self.sniff_thread = None
        self.interface = None
        
        # 创建UI
        self.create_widgets()
        
        # 检查权限
        if os.name == 'posix' and os.geteuid() != 0:
            messagebox.showerror("权限错误", "此程序需要root权限!")
            self.root.after(100, self.root.destroy)
        
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 设置区域
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
        
        # 控制按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="启动", command=self.start_spoofing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="停止", command=self.stop_spoofing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # 日志区域
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
            return sorted(ifaces.dev_from_index(i).name for i in ifaces.data.keys())
        except:
            return ["自动选择"]
    
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
            
            # 构造伪造的ICMP响应包
            reply = IP(src=src_ip, dst=dst_ip)/ICMP(type=0, id=id, seq=seq)/pkt[ICMP].payload
            
            # 计算延迟
            current_time = time.time()
            request_time = pkt.time
            elapsed = (current_time - request_time) * 1000  # 实际耗时(ms)
            
            # 如果需要固定延迟，就等待足够的时间
            target_delay = self.ping_delay.get()
            if elapsed < target_delay:
                time.sleep((target_delay - elapsed) / 1000.0)
            
            # 发送伪造的响应
            send(reply, verbose=0, iface=self.interface)
            
            # 在UI线程中更新日志
            self.root.after(0, self.log_message, 
                          f"伪造Ping响应: {dst_ip} -> {src_ip} (延迟: {target_delay}ms)")
    
    def start_spoofing(self):
        """启动伪造服务"""
        if self.running:
            return
            
        self.interface = self.interface_var.get() if self.interface_var.get() != "自动选择" else None
        target_delay = self.ping_delay.get()
        
        if target_delay <= 0:
            messagebox.showerror("错误", "延迟时间必须大于0")
            return
        
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # 启动嗅探线程
        self.sniff_thread = threading.Thread(
            target=self.sniff_packets, 
            daemon=True
        )
        self.sniff_thread.start()
        
        self.log_message(f"启动ICMP Ping伪造服务，所有Ping将显示为{target_delay}ms延迟")
        self.log_message(f"监听接口: {self.interface if self.interface else '自动选择'}")
    
    def stop_spoofing(self):
        """停止伪造服务"""
        if not self.running:
            return
            
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # 停止嗅探线程
        if self.sniff_thread and self.sniff_thread.is_alive():
            # Scapy的sniff函数没有直接的停止方法，这里使用一个不太优雅的方式
            os.kill(os.getpid(), signal.SIGINT)
            self.sniff_thread.join(timeout=1)
        
        self.log_message("已停止ICMP Ping伪造服务")
    
    def sniff_packets(self):
        """嗅探网络包"""
        filter = "icmp and icmp[0] == 8"  # 只捕获ICMP请求(ping)
        
        try:
            sniff(
                filter=filter, 
                prn=self.fake_ping_response, 
                store=0, 
                iface=self.interface,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.root.after(0, self.log_message, f"错误: {str(e)}")
            self.root.after(0, self.stop_spoofing)
    
    def on_closing(self):
        """窗口关闭事件处理"""
        if self.running:
            self.stop_spoofing()
        self.root.destroy()

if __name__ == "__main__":
    # 检查是否安装了scapy
    try:
        from scapy.all import *
        import signal
    except ImportError:
        print("错误: 需要安装scapy库 (pip install scapy)")
        sys.exit(1)
    
    root = tk.Tk()
    app = PingSpooferApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
