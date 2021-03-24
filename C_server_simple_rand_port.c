#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
//#define INADDR_LOOPBACK     0x7f000001
//#define INADDR_ANY      0x00000000
void read_socket(int newsock, int pid);
void server_main();
void main(){
server_main();
}
void server_main(){
       int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sock_addr,port_addr;
        int pid;
        int newsock;
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_port = htons(0);
        sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        bind(sock,(struct sockaddr *)&sock_addr , sizeof(sock_addr));
        int len = sizeof(port_addr);
        getsockname(sock, (struct sockaddr *) &port_addr, &len);
        printf("%d",ntohs(port_addr.sin_port));
        listen(sock,5);
        int scli=sizeof(sock_addr);
while(newsock = accept(sock, (struct sockaddr *) &sock_addr, &scli)){
   int pid;
    if((pid = fork()) == 0) {
        read_socket(newsock,pid);
}}}
void read_socket(int newsock, int pid)
{
char buffer[256];
while(read(newsock,buffer,255)>0){
printf(buffer);
}
}
