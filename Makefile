all : ssl_client ssl_server

ssl_client: ssl_client.cpp
	g++ -Wall -o ssl_client ssl_client.cpp -L/usr/lib -lssl -lcrypto -std=c++11 -fpermissive -Wwrite-strings -pthread

ssl_server: ssl_server.cpp
	g++ -Wall -o ssl_server ssl_server.cpp -L/usr/lib -lssl -lcrypto -std=c++11 -fpermissive -Wwrite-strings -pthread

clean:
	rm -f ssl_client
	rm -f ssl_server

