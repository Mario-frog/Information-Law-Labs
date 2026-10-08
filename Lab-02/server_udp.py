import socket
from datetime import datetime

HOST, PORT = '127.0.0.1', 5001
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind((HOST, PORT))
    print(f'UDP server: {HOST}:{PORT}')
    while True:
        data, address = server.recvfrom(65535)
        message = data.decode('utf-8')
        if message == '__DROP__':
            print(f'{datetime.now()}: simulated packet loss for {address}')
            continue
        reply = message.upper().encode('utf-8')
        server.sendto(reply, address)
        print(f'{address}: {message!r} -> {reply.decode()!r}')
