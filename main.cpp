#include <stdio.h>
#include <winsock2.h>

void print_and_exit(int exit_code, char *format, ...){
  va_list args;
  va_start(args, format);
  printf("Socket Error :%d\n", WSAGetLastError());
  vprintf(format, args);
  va_end(args);
  exit(exit_code);
}

int main(){
  WSADATA wsadata;
  WSAStartup(MAKEWORD(2,2), &wsadata);
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sock == INVALID_SOCKET) print_and_exit(-1, "CANT CONNECT SOCKET");

  hostent*  localhost  =  gethostbyname("");                
  char*     localIP    =  inet_ntoa(*(struct  in_addr*  )*  localhost->h_addr_list);
  struct sockaddr_in server;
  server.sin_family       =  AF_INET;
  server.sin_addr.s_addr  =  inet_addr(localIP);
  server.sin_port         =  htons(6969);
  int bind_ret = bind(sock, (sockaddr *)&server, sizeof(server));
  if(bind_ret) print_and_exit(-1, "CANT BIND");

  int listen_ret = listen(sock, SOMAXCONN);
  if(listen_ret) print_and_exit(-1, "CANT LISTEN");

  int clientsock = accept(sock, NULL, NULL);
  if(clientsock == INVALID_SOCKET) print_and_exit(-1, "CANT CONNECT CLIENT");


  char client_request[256];
  client_request[255] = 0;

  int repeating = 1;
  while(repeating){
    int result_len = recv(clientsock, client_request, 256, 0);
    if(result_len == 0) repeating = 0;
    else if (result_len > 0) printf("%.*s", result_len, client_request);
    //result_len = send(clientsock, client_request, 256, 0);
  }

  repeating = 1;
  while(repeating){
    int result_len = send(clientsock, client_request, 256, 0);
    if(result_len == 0) repeating = 0 ;
    else printf("%d bytes send\n", result_len);
  }

  closesocket(clientsock);
  closesocket(sock);

}
