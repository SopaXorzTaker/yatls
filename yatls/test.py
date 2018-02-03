from yatls.simple_client import *

request = b"GET / HTTP/1.0\r\nHost: www.ietf.org\r\n\r\n"

client = SimpleClient(("ietf.org", 443))

client.connect()
client.send(request)

print(client.recv().decode("utf-8", errors="ignore"))
