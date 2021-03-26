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
void cert_key_files(SSL_CTX* ctx, char* CertF, char* KeyF)
{
 
    if ( SSL_CTX_use_certificate_file(ctx, CertF SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
  
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyF, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
  
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Key not match \n");
        abort();
    }
}
int client_init_sock(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    host = gethostbyname(hostname));
    
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    connect(sd, (struct sockaddr*)&addr, sizeof(addr));
    return sd;
}

SSL_CTX* ctx_server(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();   
    method = TLSv1_2_client_method(); 
    ctx = SSL_CTX_new(method);   
    return ctx;
}

int main()
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[2024];
    int bytes;
    char hostname[]="0.0.0.0";
    char port[]="8080";
    char CertF[] = "cert.pem";
    char KeyF[] = "key.pem";

    SSL_library_init();

    ctx = ctx_server();
    cert_key_files(ctx, CertF, KeyF);
    server = client_init_sock(hostname, atoi(port));
    ssl = SSL_new(ctx);      
    SSL_set_fd(ssl, server);    
    if ( SSL_connect(ssl) == -1 )  
        ERR_print_errors_fp(stderr);
    else
    {   char *msg = "Hello???";

        printf("Connection %s encrypted\n", SSL_get_cipher(ssl));
        
        SSL_write(ssl, msg, strlen(msg));   
        bytes = SSL_read(ssl, buf, sizeof(buf)); 
        buf[bytes] = 0;
        printf("Responce: \"%s\"\n", buf);
        SSL_free(ssl);       
    }
    close(server);         
    SSL_CTX_free(ctx);     
    return 0;
}



