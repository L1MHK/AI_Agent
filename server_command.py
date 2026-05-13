import paramiko

def commandInput(ssh_client, cmd):
    """
    보안 정책이 적용된 일반 점검용 명령어 실행 함수
    """
    forbidden_keywords = [
        "rm ", "mv ", "dd ", "mkfs", "reboot", "shutdown", 
        "systemctl stop", "systemctl disable", ">", "wget ", "curl "
    ]
    
    clean_cmd = cmd.lower().strip()
    if any(forbidden in clean_cmd for forbidden in forbidden_keywords):
        return f"Error: 보안 정책상 허용되지 않는 명령어입니다. ({cmd})"

    try:
        stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=5)
        result = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        return result if result else (f"Error: {error}" if error else "No Output")
    except Exception as e:
        return f"Error: 예외 발생 ({str(e)})"

def adminCommandExporter(ssh_client, commands_text):
    """
    관리자 승인을 받은 명령어를 SFTP로 서버에 저장하는 함수
    """
    remote_path = "./remediation_commands.txt"
    try:
        sftp = ssh_client.open_sftp()
        with sftp.file(remote_path, 'w') as f:
            f.write(commands_text)
        sftp.close()
        return f"✅ 서버 파일 저장 완료: {remote_path}"
    except Exception as e:
        return f"❌ 파일 저장 실패: {str(e)}"
    

# server_command.py

def adminCommandRunner(ssh_client, commands_text):
    """
    관리자 승인을 받은 명령어들을 서버에서 직접 순차 실행합니다.
    """
    results = []
    lines = commands_text.split('\n')
    
    for line in lines:
        cmd = line.strip()
        # 빈 줄이나 주석(#)은 실행하지 않고 건너뜁니다.
        if not cmd or cmd.startswith('#'):
            continue
            
        try:
            print(f"🚀 실행 중: {cmd}")
            stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=10)
            
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error:
                results.append(f"❌ <b>FAIL:</b> <code>{cmd}</code>\n<pre>{error}</pre>")
            else:
                results.append(f"✅ <b>SUCCESS:</b> <code>{cmd}</code>\n<pre>{output if output else 'Done'}</pre>")
                
        except Exception as e:
            results.append(f"⚠️ <b>ERROR:</b> <code>{cmd}</code>\n({str(e)})")

    return "\n\n".join(results)