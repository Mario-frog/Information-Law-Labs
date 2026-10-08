import socket

HOST = '127.0.0.1'
PORT = 65432


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        print(f'TCP server listening on {HOST}:{PORT}')
        while True:
            connection, address = server.accept()
            with connection:
                print(f'Connected: {address}')
                data = connection.recv(4096)
                if not data:
                    continue
                message = data.decode('utf-8')
                response = message.upper()
                connection.sendall(response.encode('utf-8'))
                print(f'{message!r} -> {response!r}')


if __name__ == '__main__':
    main()
