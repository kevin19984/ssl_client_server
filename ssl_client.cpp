#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#define FAIL	-1
using namespace std;
int OpenConnection(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;
	if ( (host = gethostbyname(hostname)) == NULL )
	{
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}
SSL_CTX* InitCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = TLSv1_2_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}
void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);	   /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);	   /* free the malloc'ed string */
		X509_free(cert);	 /* free the malloc'ed certificate copy */
	}
	else
		printf("Info: No client certificates configured.\n");
}
void recvfun(SSL *ssl)
{
	char buf[1024];
	while(true) {
		int bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		buf[bytes] = 0;
		if(strcmp(buf, "quit") == 0) break;
		printf("Received: %s\n", buf);
	}
}
void usage() {
	printf("syntax: ssl_client <host> <port>\n");
	printf("sample: ssl_client 127.0.0.1 1234\n");
}
int main(int count, char *strings[])
{
	if (count < 3) {
		usage();
		return -1;
	}
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
	char *hostname, *portnum;
	SSL_library_init();
	hostname=strings[1];
	portnum=strings[2];
	ctx = InitCTX();
	server = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);	  /* create new SSL connection state */
	SSL_set_fd(ssl, server);	/* attach the socket descriptor */
	int err = SSL_connect(ssl);   /* perform the connection */
	if (err == FAIL) 
	{
		SSL_free(ssl);
		ERR_print_errors_fp(stderr);
		close(server);	
		SSL_CTX_free(ctx);
		return 0;
	}
	printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
	ShowCerts(ssl);		/* get any certs */
	thread t1(recvfun, ssl);
	while(true)
	{
		fgets(buf, 1024, stdin);
		buf[strlen(buf)-1] = '\0';
		SSL_write(ssl,buf, strlen(buf));   /* encrypt & send message */
		if (strcmp(buf, "quit") == 0) break;
	}
	t1.join();
	SSL_free(ssl);		/* release connection state */	
	close(server);		 /* close socket */
	SSL_CTX_free(ctx);		/* release context */
	return 0;
}
