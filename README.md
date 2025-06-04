[진행상황]
client와 server가 LB를 통한 3-way handshake까지 완료했다.
또, client로부터 데이터 요청 패킷[PSH, ACK]을 받지만, LB가 해당 패킷을 server에게 전달하지 못하는 상태이다.

--------

실행 방법

1. client.py에 LB의 IP와 Port 수정하기.
1-2. serverInfo.txt 파일에서 
    server의 IP와 LB 소통용 Port, 웹서버용 Port 수정하기.
2. 아래의 방법을 따라 server, LB, client 순서로 실행하기.

[Server]
WebServer 폴더 안에 있음.
컴파일 필요 없음.

실행 명령어
--> python3 server.py
--> 웹서버 접속

[LB]
컴파일
--> gcc -o lb tcp_lb.c

실행 명령어
--> sudo ./lb [LB IP] [LB Port] [algorithm name]
    e.g., sudo ./lb 192.168.10.105 7890 rr
        algorithm name: rr, lc, rb

[Client]
컴파일 필요 없음.

실행 명령어
--> python3 client.py
