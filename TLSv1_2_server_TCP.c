#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

int server_init_sock(int port)
{   int snum;
    struct sockaddr_in addr;
    snum = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(snum, (struct sockaddr*)&addr, sizeof(addr)); //bind sock
    listen(snum, 10);//listen for connections
return snum;
}

SSL_CTX* ctx_server(void)
{   SSL_METHOD *methodcert;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  // All cryptos
    SSL_load_error_strings();   //errors
    methodcert = TLSv1_2_server_method();  //new method for reading cert
    ctx = SSL_CTX_new(methodcert);   //context for method
    return ctx;
}

void cert_key_file(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);
    
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // private key 
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key not much public certificate\n");
        abort();
    }

    //client have a certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

void recv_send(SSL* ssl) // Serve the connection 
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* responce="hi";

    if ( SSL_accept(ssl) == -1 )     //SSL accept
        ERR_print_errors_fp(stderr);
    else
    {
        bytes = SSL_read(ssl, buf, sizeof(buf)); //request
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Responce: \"%s\"\n", buf);
            sprintf(reply, responce, buf);   //replay
            SSL_write(ssl, reply, strlen(reply)); //send reply 
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

int main()
{   SSL_CTX *ctx;
    int server;
    char port[]="8080";

        char CertF[] = "cert.pem";
        char KeyF[] = "key.pem";

    SSL_library_init();

    ctx = ctx_server();        // initialize SSL
    cert_key_file(ctx, CertF, KeyF); //load certs 
    server = server_init_sock(atoi(port));    //create socket
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);  //accept connection
        printf("Client IP:PORT: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port)); //ip :port
        ssl = SSL_new(ctx);              //get  SSL state
        SSL_set_fd(ssl, client);      //socket to SSL state 
        recv_send(ssl);         // service connection 
    }
    close(server);          // close socket
    SSL_CTX_free(ctx);         //ctx
}
