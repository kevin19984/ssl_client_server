#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <thread>
#include <mutex>
#include <list>
#include <vector>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL	-1
using namespace std;

list<SSL*> ssllist;
mutex mtx_lock;

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
	int sd;
	struct sockaddr_in addr;
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}
int isRoot()
{
	if (getuid() != 0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}
SSL_CTX* InitServerCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD*)TLSv1_2_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	/*
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
	*/
}
void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	/*
	else
		printf("No certificates.\n");
	*/
}
void usage() {
	printf("syntax: ssl_server <port> [-b]\n");
	printf("sample: ssl_server 1234 -b\n");
}
void fun(SSL* ssl) {
	char buf[1024] = {0};
	int sd, bytes;

	if ( SSL_accept(ssl) == FAIL )	 /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);		/* get any certificates */
		while(1)
		{
			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
			if ( bytes <= 0 )
			{
				ERR_print_errors_fp(stderr);
				printf("Connection closed\n");
				break;
			}
			buf[bytes] = '\0';
			if(strcmp(buf, "quit") == 0)
			{
				SSL_write(ssl, buf, strlen(buf));
				continue;
			}
			printf("Client msg: %s\n", buf);
			SSL_write(ssl, buf, strlen(buf)); /* send reply */
		}
	}
	sd = SSL_get_fd(ssl);	   /* get socket connection */
	SSL_free(ssl);		 /* release SSL state */
	close(sd);		  /* close connection */
}
void bfun(SSL* ssl) {
	mtx_lock.lock();
	ssllist.push_back(ssl);
	mtx_lock.unlock();
	char buf[1024] = {0};
	int sd, bytes;

	if ( SSL_accept(ssl) == FAIL )	 /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);		/* get any certificates */
		while(1)
		{
			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
			if ( bytes <= 0 )
			{
				mtx_lock.lock();
				ssllist.remove(ssl);
				mtx_lock.unlock();
				printf("Connection closed\n");
				ERR_print_errors_fp(stderr);
				break;
			}
			buf[bytes] = '\0';
			if(strcmp(buf, "quit") == 0)
			{
				SSL_write(ssl, buf, strlen(buf));
				continue;
			}
			printf("Client msg: %s\n", buf);
			mtx_lock.lock();
			for(list<SSL*>::iterator iter = ssllist.begin(); iter != ssllist.end(); iter++){
				SSL_write(*iter, buf, strlen(buf));
			}
			mtx_lock.unlock();
		}

	}
	sd = SSL_get_fd(ssl);	   /* get socket connection */
	SSL_free(ssl);		 /* release SSL state */
	close(sd);		  /* close connection */	
}
int main(int count, char *Argc[])
{
	if (count < 2) {
		usage();
		return -1;
	}
	int chk = 0;
	if (count == 3 && strncmp(Argc[2], "-b", 2) == 0)
		chk = 1;

	SSL_CTX *ctx;
	int server;
	char *portnum;
//Only root user have the permsion to run the server
	if(!isRoot())
	{
		printf("This program must be run as root/sudo user!!\n");
		exit(0);
	}
	// Initialize the SSL library
	SSL_library_init();
	portnum = Argc[1];
	ctx = InitServerCTX();		/* initialize SSL */
	LoadCertificates(ctx, "test.com.crt", "test.com.pem"); /* load certs */
	server = OpenListener(atoi(portnum));	/* create server socket */
	vector<thread> workers;
	while (1)
	{
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;
		int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);			  /* get new SSL state with context */
		SSL_set_fd(ssl, client);	  /* set connection socket to SSL state */
		if(chk)
			workers.push_back(thread(bfun, ssl));
		else
			workers.push_back(thread(fun, ssl));
	}
	int len = workers.size();
	for(int i=0; i<len; i++)
		workers[i].join();
	close(server);		  /* close server socket */
	SSL_CTX_free(ctx);		 /* release context */
}
