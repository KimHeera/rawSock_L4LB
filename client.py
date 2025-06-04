import socket
import time

def create_tcp_connection(host, port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)  # 타임아웃 설정

        print(f"Connecting to {host}:{port}")
        client_socket.connect((host, port))
        print(f"Successfully connected to {host}:{port}")

    except socket.timeout:
        print("Connection timed out. The server may be unreachable or not responding.")
    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        client_socket.close()
        print("Socket closed.")

# 실행 시 IP와 Port 변경 필수!!
host = '192.168.0.33'
port = 7890

create_tcp_connection(host, port)