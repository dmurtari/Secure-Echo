#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define	QLEN		  32	/* maximum connection queue length	*/
#define	BUFSIZE		4096

/*Password for the key file*/
#define KEY_PASSWD "netsys_2014"

/* Make these what you want for certificate & key files */
#define CERT_FILE  "server.cert"
#define KEY_FILE  "server_priv.key"

extern int	errno;
int		errexit(const char *format, ...);
int		passivesock(const char *portnum, int qlen);
int		echo(SSL *myssl);

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char	*portnum = "5004";	/* Standard server port number	*/
	struct sockaddr_in fsin;	/* the from address of a client	*/
	int	msock;			          /* master server socket		*/
	fd_set	rfds;			        /* read file descriptor set	*/
	fd_set	afds;			        /* active file descriptor set	*/
	unsigned int	alen;		    /* from-address length		*/
	int	fd, nfds;

  /* SSL Stuff */
  const SSL_METHOD *meth;
  SSL_CTX *ctx;
  SSL *myssl;
  int err;
  SSL *client_connections[QLEN];

	switch (argc) {
	case	1:
		break;
	case	2:
		portnum = argv[1];
		break;
	default:
		errexit("usage: TCPmethod [port]\n");
	}

  SSL_library_init(); /* load encryption & hash algorithms for SSL */                
  SSL_load_error_strings(); /* load the error strings for good error reporting */

  meth = SSLv3_server_method();
  ctx = SSL_CTX_new(meth);

  if (!ctx) {
    printf("Error creating the context.\n");
    exit(0);
  }

  /* Set the certificate to be used. */
  if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the certificate file.\n");
    exit(0);
  }

  /* Load the password for the Private Key */
  SSL_CTX_set_default_passwd_cb_userdata(ctx, KEY_PASSWD);

  /* Indicate the key file to be used */
  if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the key file.\n");
    exit(0);
  }

  /* Make sure the key and certificate file match */
  if (SSL_CTX_check_private_key(ctx) == 0) {
    printf("Private key does not match the certificate public key\n");
    exit(0);
  }

	msock = passivesock(portnum, QLEN);

	nfds = getdtablesize();
	FD_ZERO(&afds);
	FD_SET(msock, &afds);

	while (1) {
		memcpy(&rfds, &afds, sizeof(rfds));

		if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0) < 0)
			errexit("select: %s\n", strerror(errno));
		if (FD_ISSET(msock, &rfds)) {
			int	ssock;

			alen = sizeof(fsin);
			ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
			if (ssock < 0)
				errexit("accept: %s\n", strerror(errno));
			FD_SET(ssock, &afds);

      /* Create new ssl object*/
      myssl=SSL_new(ctx);

      /* Set socket into SSL structure */
      SSL_set_fd(myssl, ssock);

      /* Do the SSL Handshake */
      err = SSL_accept(myssl);

      /* Check for error in handshake */
      if (err < 1) {
        err = SSL_get_error(myssl, err);
        printf("SSL error #%d in SSL_accept, program terminated\n", err);
        close(msock);
        SSL_CTX_free(ctx);
        exit(0);
      }

      client_connections[ssock] = myssl;
		}
    
		for (fd=0; fd<nfds; ++fd)
			if (fd != msock && FD_ISSET(fd, &rfds))
				if (echo(client_connections[fd]) == 0) {
          SSL *myssl = client_connections[fd];
          client_connections[fd] = NULL;

          SSL_shutdown(myssl);
          SSL_free(myssl);
					(void) close(fd);
					FD_CLR(fd, &afds);
				}
	}
}

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int echo(SSL *myssl) {
	char	buf[BUFSIZ];
	int	cc;

	cc = SSL_read(myssl, buf, sizeof(buf));
	if (cc < 0)
		errexit("echo read: %s\n", strerror(errno));
	if (cc && SSL_write(myssl, buf, cc) < 0)
		errexit("echo write: %s\n", strerror(errno));
	return cc;
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int
errexit(const char *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  exit(1);
}

/*------------------------------------------------------------------------
 * passivesock - allocate & bind a server socket using TCP
 *------------------------------------------------------------------------
 */
int
passivesock(const char *portnum, int qlen)
/*
 * Arguments:
 *      portnum   - port number of the server
 *      qlen      - maximum server request queue length
 */
{
  struct sockaddr_in sin; /* an Internet endpoint address  */
  int     s;              /* socket descriptor             */

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;

  /* Map port number (char string) to port number (int) */
  if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
    errexit("can't get \"%s\" port number\n", portnum);

  /* Allocate a socket */
  s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s < 0)
    errexit("can't create socket: %s\n", strerror(errno));

  /* Bind the socket */
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    fprintf(stderr, "can't bind to %s port: %s; Trying other port\n",
    portnum, strerror(errno));
    sin.sin_port=htons(0); /* request a port number to be allocated
                       by bind */
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
      errexit("can't bind: %s\n", strerror(errno));
    else {
      int socklen = sizeof(sin);

      if (getsockname(s, (struct sockaddr *)&sin, &socklen) < 0)
        errexit("getsockname: %s\n", strerror(errno));
 
      printf("New server port number is %d\n", ntohs(sin.sin_port));
    }
  }

  if (listen(s, qlen) < 0)
    errexit("can't listen on %s port: %s\n", portnum, strerror(errno));
  return s;
}

