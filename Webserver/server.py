from flask import Flask, request, render_template
import socket
import threading

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def flask_thread():
    app.run(host='0.0.0.0', port=5000)

def handle_tcp_connections():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 6000))
    server_socket.listen(5)
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f'Connection from {addr}')
        
        data = client_socket.recv(1024)
        print(data)
        if data == b'\x00':
            print("First")
            response = '100'
            client_socket.send(response.encode('utf-8'))
        else:
            # 다른 경우에 대한 처리
            print("second")
            pass
        
        client_socket.close()

if __name__ == '__main__':
    # Flask 서버를 다른 스레드에서 실행
    threading.Thread(target=flask_thread).start()
    
    # TCP 소켓 연결을 처리하는 함수 실행
    handle_tcp_connections()

