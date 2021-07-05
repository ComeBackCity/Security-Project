import socket
import cv2
import pickle
import struct
import threading
import time

# Socket Create
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
print('HOST IP:', host_ip)
port = 9999
socket_address = (host_ip, port)
dim = (800, 600)

# Socket Bind
server_socket.bind(socket_address)

# Socket Listen
server_socket.listen(5)
print("LISTENING AT:", socket_address)


def client_handler(client_socket):
    if client_socket is None:
        return
    vid = cv2.VideoCapture("video.mp4")
    try:
        while vid.isOpened():
            ret, frame = vid.read()
            frame = cv2.resize(frame, dim, fx=0, fy=0,
                               interpolation=cv2.INTER_CUBIC)
            a = pickle.dumps(frame)
            message = struct.pack("Q", len(a)) + a
            client_socket.sendall(message)
    except:
        None


# Socket Accept
while True:
    client_socket, addr = server_socket.accept()
    print('GOT CONNECTION FROM:', addr)
    th = threading.Thread(target=client_handler, args=(client_socket, ))
    th.start()