import socket

server_ip = "127.0.0.1"
server_port = 80


def start_server():
    # create server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # bind the socket to server host and port
    server_sock.bind((server_ip, server_port))
    print("[+]server socket created")
    # start listening for new connection only one client at a time
    server_sock.listen(1)
    print("[+]listening for connection")

    while True:
        # accept new connection
        client_sock, client_add = server_sock.accept()
        print(f'connection made with :{client_add}')

        # receive the client's packet and decode it to string
        request = client_sock.recv(1024).decode('utf-8')

        # check if its a get http request
        if 'GET' in request:
            print("received GET request")
            filename = request.split()[1][1:]
            if filename == 'img1.jpg':
                # proxy_req = "GET /img1.jpg HTTP/1.1\r\nHost: 10.0.0.53:8000\r\n\r\n"
                with open('img1.jpg', 'rb') as file:
                    img_data = file.read()
                    response = b'HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n' + img_data
                    client_sock.sendall(response)
                    print("response sent successfully.")
                    client_sock.close()
                    break
            else:
                print("received other type of request")
    server_sock.close()


if __name__ == '__main__':
    start_server()
