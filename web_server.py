import socket
import requests

web_server_ip = "127.0.0.2"
web_server_port = 80
storage_server_ip = "127.0.0.3"
storage_server_port = 80


def start_proxy():
    # create server socket
    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # bind the socket to server host and port
    proxy_sock.bind((web_server_ip, web_server_port))
    print("[+]server socket created")
    # start listening for new connection only one client at a time
    proxy_sock.listen(1)
    print("[+]listening for connection")

    while True:
        # accept new connection
        client_sock, client_add = proxy_sock.accept()
        print(f'connection made with :{client_add}')

        # receive the client's packet and decode it to string
        request = client_sock.recv(1024).decode('utf-8')

        # check if it's a GET http request
        if 'GET' in request:
            print("received GET request")
            # check if is it request for img1
            filename = request.split()[1][1:]
            # make a request from server for the image
            new_url = f'http://{storage_server_ip}:{storage_server_port}/{filename}'
            response = requests.get(new_url)
            # check if we received the correct response
            if response.status_code == 200:
                # create a response to send to the client
                reply = b'HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n' + response.content
                client_sock.sendall(reply)
                print("response sent successfully.")
            else:
                print("didnt get the image successfully")
            # close socket
            client_sock.close()
            print("[+]client_socket closed")
            break
    # close socket
    proxy_sock.close()
    print("[+]proxy_sock closed")


if __name__ == '__main__':
    start_proxy()
