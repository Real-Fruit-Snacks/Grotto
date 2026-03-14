#!/usr/bin/env python3
"""Upload grotto.exe to remote target."""
import paramiko, time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.123.147', username='Eric.Wallows', password='EricLikesRunning800', timeout=10)
print('[+] Connected')
ssh.exec_command('taskkill /IM grotto.exe /F 2>nul', timeout=5)
ssh.exec_command('taskkill /IM ncat.exe /F 2>nul', timeout=5)
time.sleep(2)

sftp = ssh.open_sftp()
local = r"C:\Users\Matt\Notes\Projects\netcat\build\grotto.exe"
remote = "C:/Users/Eric.Wallows/Desktop/grotto.exe"
try:
    sftp.put(local, remote)
    print('[+] Uploaded grotto.exe')
except OSError:
    tmp = "C:/Users/Eric.Wallows/Desktop/grotto_tmp.exe"
    sftp.put(local, tmp)
    ssh.exec_command("del C:\\Users\\Eric.Wallows\\Desktop\\grotto.exe 2>nul", timeout=5)
    time.sleep(1)
    ssh.exec_command("move /Y C:\\Users\\Eric.Wallows\\Desktop\\grotto_tmp.exe C:\\Users\\Eric.Wallows\\Desktop\\grotto.exe", timeout=5)
    print('[+] Uploaded grotto.exe (via rename)')
sftp.close()
ssh.close()
