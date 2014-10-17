#include <sys/types.h>
#include <sys/socket.h>

#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif  /* INADDR_NONE */

extern int	errno;

int	TCPecho(const char *host, const char *portnum);
int	errexit(const char *format, ...);
int	connectsock(const char *host, const char *portnum);

#define	LINELEN		128

#define CERT_FILE  "cacert.pem"
#define KEY_FILE  "cakey.pem"

/*Trusted CAs location*/
#define CA_FILE "./cacert.pem"
#define CA_DIR  NULL

/*Password for the key file*/
#define KEY_PASSWD "netsys_2014"

/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char	*host = "localhost";	/* host to use if none supplied	*/
	char	*portnum = "5004";	/* default server port number	*/

	switch (argc) {
	case 1:
		host = "localhost";
		break;
	case 3:
		host = argv[2];
		/* FALL THROUGH */
	case 2:
		portnum = argv[1];
		break;
	default:
		fprintf(stderr, "usage: TCPecho [host [port]]\n");
		exit(1);
	}

	TCPecho(host, portnum);
	exit(0);
}

/*------------------------------------------------------------------------
 * TCPecho - send input to ECHO service on specified host and print reply
 *------------------------------------------------------------------------
 */
int
TCPecho(const char *host, const char *portnum)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	int	s, n;			/* socket descriptor, read count*/
	int	outchars, inchars;	/* characters sent and received	*/
  
  /* SSL Stuff */
  const SSL_METHOD *meth;
  SSL_CTX *ctx;
  SSL *myssl;
  int err;

  SSL_library_init(); /* load encryption & hash algorithms for SSL */                
  SSL_load_error_strings(); /* load the error strings for good error reporting */

  meth = SSLv3_client_method();
  ctx = SSL_CTX_new(meth);
  
  if (!ctx) {
     printf("Error creating the context.\n");
     exit(0);
  }

  /* Indicate the certificate file to be used */
  if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the certificate file.\n");
    ERR_print_errors_fp(stderr);
    exit(0);
  }

  /* Load the password for the Private Key */
  SSL_CTX_set_default_passwd_cb_userdata(ctx, KEY_PASSWD);

  /* Indicate the key file to be used */
  if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the key file.\n");
    ERR_print_errors_fp(stderr);
    exit(0);
  }

  /* Make sure the key and certificate file match */
  if (SSL_CTX_check_private_key(ctx) == 0) {
    printf("Private key does not match the certificate public key\n");
    ERR_print_errors_fp(stderr);
    exit(0);
  }

  /*  Set the list of trusted CAs based on the file and/or directory provided */
  if(SSL_CTX_load_verify_locations(ctx, CA_FILE ,CA_DIR)<1) {
    printf("Error setting verify location\n");
    ERR_print_errors_fp(stderr);
    exit(0);
  }

  /*  Set for server verification */
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

  /* Create new ssl object*/
  myssl = SSL_new(ctx);

  if(!myssl) {
     printf("Error creating SSL structure.\n");
     exit(0);
  }

	s = connectsock(host, portnum);

  /* Set socket into SSL structure */
  SSL_set_fd(myssl, s);

  /* Connect to the server, SSL layer */
  err = SSL_connect(myssl);

  /* Check for error in connect */
  if (err < 1) {
    err = SSL_get_error(myssl,err);
    printf("SSL error #%d in accept, program terminated\n", err);
    close(s);
    SSL_free(myssl);
    SSL_CTX_free(ctx);
    exit(0);
  }

	while (fgets(buf, sizeof(buf), stdin)) {
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		SSL_write(myssl, buf, outchars);

		/* read it back */
		for (inchars = 0; inchars < outchars; inchars+=n ) {
			n = SSL_read(myssl, &buf[inchars], outchars - inchars);
			if (n < 0)
				errexit("socket read failed: %s\n", strerror(errno));
		}
		fputs(buf, stdout);
	}
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
 * connectsock - allocate & connect a socket using TCP 
 *------------------------------------------------------------------------
 */
int
connectsock(const char *host, const char *portnum)
/*
 * Arguments:
 *      host      - name of host to which connection is desired
 *      portnum   - server port number
 */
{
        struct hostent  *phe;   /* pointer to host information entry    */
        struct sockaddr_in sin; /* an Internet endpoint address         */
        int     s;              /* socket descriptor                    */


        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Map host name to IP address, allowing for dotted decimal */
        if ( phe = gethostbyname(host) )
                memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
        else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE )
                errexit("can't get \"%s\" host entry\n", host);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
                errexit("can't create socket: %s\n", strerror(errno));

    /* Connect the socket */
        if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't connect to %s.%s: %s\n", host, portnum,
                        strerror(errno));


        return s;
}

