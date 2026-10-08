import socket
HOST, PORT = '127.0.0.1', 5002
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f'TCP server: {HOST}:{PORT}')
    while True:
        conn, addr = server.accept()
        with conn:
            data = conn.recv(65535)
            if data:
                conn.sendall(data.decode('utf-8').upper().encode('utf-8'))
                print(f'{addr}: {data.decode()!r}')
