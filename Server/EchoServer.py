# Echo server program
# http header expected by client as print 'ICSI-Client-Addr:', addr[0], addr[1]
import socket

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 1947               # Arbitrary non-privileged port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))


count = 0
while count < 100:
  s.listen(1)
  conn, addr = s.accept()
  print 'Connected by', addr
  resp = addr[0] + ":" + str(addr[1])
  conn.sendall(resp)
  while 1:
    data = conn.recv(1024)
    if not data: break
    conn.sendall(data)
  conn.close()
count+=1
