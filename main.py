import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from rssi_core import run_test, VERSION


def resource_path(name):
    return os.path.join(os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__), name)

class App:
    def __init__(self, root):
        self.root=root
        root.title('VG-8043u RSSI Test V'+VERSION)
        root.geometry('900x650')
        box=ttk.Frame(root,padding=18); box.pack(fill='both',expand=True)
        ttk.Label(box,text='VG-8043u RSSI 自動測試',font=('Microsoft JhengHei',19,'bold')).pack(anchor='w',pady=(0,14))
        fields=[('DUT IP','192.168.1.1'),('Telnet Port','23'),('Login','root'),('Password','12345'),('SN / DUT ID',''),('Operator',''),('RSSI 門檻','50'),('擷取秒數','6')]
        self.vars={}
        grid=ttk.Frame(box);grid.pack(fill='x')
        for i,(title,default) in enumerate(fields):
            row,col=divmod(i,2)
            ttk.Label(grid,text=title).grid(row=row,column=col*2,sticky='w',padx=(0,10),pady=7)
            v=tk.StringVar(value=default);self.vars[title]=v
            ttk.Entry(grid,textvariable=v,show='*' if title=='Password' else '',width=27).grid(row=row,column=col*2+1,sticky='ew',padx=(0,32),pady=7)
        self.status=tk.StringVar(value='READY')
        bar=ttk.Frame(box);bar.pack(fill='x',pady=15)
        self.btn=ttk.Button(bar,text='開始 RSSI 測試',command=self.start);self.btn.pack(side='left')
        ttk.Button(bar,text='開啟測試紀錄',command=self.open_dir).pack(side='left',padx=14)
        ttk.Label(bar,textvariable=self.status,font=('Arial',18,'bold')).pack(side='right')
        ttk.Label(box,text='詳細紀錄（包括指令進度及結果）：').pack(anchor='w')
        self.console=tk.Text(box,height=17,wrap='word',font=('Consolas',11));self.console.pack(fill='both',expand=True,pady=8)
        self.output=os.path.join(os.path.dirname(sys.executable) if getattr(sys,'frozen',False) else os.path.dirname(__file__),'records')
        root.protocol('WM_DELETE_WINDOW',root.destroy)

    def open_dir(self):
        os.makedirs(self.output,exist_ok=True)
        if sys.platform=='win32':os.startfile(self.output)
        else: messagebox.showinfo('Record Path',self.output)

    def write(self,msg):
        self.root.after(0,lambda:(self.console.insert('end',str(msg)+'\n'),self.console.see('end')))

    def start(self):
        v={k:x.get().strip() for k,x in self.vars.items()}
        if not v['SN / DUT ID']:
            messagebox.showwarning('SN', '請輸入 SN / DUT ID');return
        self.btn.configure(state='disabled');self.status.set('TESTING')
        self.console.delete('1.0','end')
        def task():
            try:
                summary,base=run_test(v['DUT IP'],v['Login'],v['Password'],v['SN / DUT ID'],v['Operator'],int(v['RSSI 門檻']),float(v['擷取秒數']),self.output,int(v['Telnet Port']),self.write)
                status=summary['result']
                self.write('DUT SN: '+str(summary['device_sn'])+' | SN Check: '+summary['sn_result'])
                self.write('RSSI Check: '+summary['rssi_result']+' | Min RSSI: '+str(summary['min_rssi']))
                self.write('Overall Result: '+status)
                self.write('Reason: '+summary['reason'])
                self.write('Evidence: '+str(base)+'.log')
                self.write('Debug: '+str(base)+'.debug.log')
                self.write('Failure phase: '+str(summary.get('failure_phase','')))
                self.write('Build version: '+VERSION)
                self.root.after(0,lambda:self.status.set(status))
            except Exception as exc:
                self.write('Program error: '+str(exc));self.root.after(0,lambda:self.status.set('ERROR'))
            finally:self.root.after(0,lambda:self.btn.configure(state='normal'))
        threading.Thread(target=task,daemon=True).start()

if __name__=='__main__':
    root=tk.Tk();App(root);root.mainloop()
