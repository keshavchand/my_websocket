#include <stdio.h>
#include <winsock2.h>
#include <string.h>
#include <assert.h>
#include "misc.h"
#include "sha.h"

void print_and_exit(int exit_code, char *format, ...){
  va_list args;
  va_start(args, format);
  printf("Socket Error :%d\n", WSAGetLastError());
  vprintf(format, args);
  va_end(args);
  exit(exit_code);
}

bool present_in_string(char *buffer, char *haystack, int buflen, int haylen){
  if (haylen > buflen) return false;
  for (int i = 0; i < buflen || buffer[i] == 0; i++){
    int matching = strncmp((const char*) buffer + i, (const char*) haystack, haylen); 
    if (matching == 0) return true;
    if ((buflen - i) < haylen) return false;
  }

  return false;
}

bool process_ws_data(char *buffer, int total_read, char* response, int* resp_len){
  int idx = 0;
  {
    // Porcess HTML Headers 
    // GET %path% HTML/1.1

    //Clear Whitespace (if any)
    for(idx = 0; idx < total_read; idx++) 
      if (!isspace(buffer[idx])) break;

    // Check its GET
    // JUST RETURN IF IT ISNT 
    char *GET = "GET";
    if(strncmp(buffer + idx, GET, strlen(GET))) return false;
    idx += strlen(GET);
  
    //Get the desired path
    //path = buffer[path_offset .. path_offset + path_len]
    int path_offset, path_len = 0;
    for(; idx < total_read; idx++) 
      if (!isspace(buffer[idx])) break;
    for(path_offset = idx;
        path_offset + path_len < total_read; 
        path_len++, idx++) 
      if (isspace(buffer[path_offset + path_len])) break;
#if VERBOSE
    printf("PATH :%.*s\n", path_len, buffer + path_offset);
#endif
    for(; idx < total_read; idx++) 
      if (!isspace(buffer[idx])) break;

    // Check its HTTP/1.1
    // JUST RETURN IF IT ISNT 
    char *HTTP = "HTTP/1.1";
    if(strncmp(buffer + idx, HTTP, strlen(HTTP))) return false;
    idx += strlen(HTTP);

    for(; idx < total_read; idx++) 
      if (!isspace(buffer[idx])) break;
  }
  
  //MUST HAVES
  bool avail_Upgrade;
  bool avail_Connection;
  bool avail_Sec_WebSocket_Key;
  bool avail_Sec_WebSocket_Version;

  char *ws_magic_value = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char ws_server_return[30];
  if (idx >= total_read) return false;
  {
    //Strtok changes the buffer 
    //so need to make extra copy
    while(idx < total_read){
      char * temp_buffer = buffer + idx;
      char * key  = strtok(temp_buffer, ":");
      idx += strlen(key) + 1;// NULL CHARACTER 

      //Delete white spaces
      for(; idx < total_read; idx++) 
        if (!isspace(buffer[idx])) break;
      temp_buffer = buffer + idx;
      char * value = strtok(temp_buffer, "\r\n");
      idx += strlen(value) + 1; // NULL CHARATER
#if VERBOSE
      printf("%s %s\n", key, value);
#endif
      for(; idx < total_read; idx++) 
        if (!isspace(buffer[idx])) break;

      // Check the headers
      char *Upgrade = "Upgrade";
      char *Connection = "Connection";
      char *Sec_WebSockey_Key = "Sec-WebSocket-Key";
      char *Sec_WebSockey_Version = "Sec-WebSocket-Version";
      if (strncmp(key, Connection, strlen(Connection)) == 0){
        avail_Connection = true;
        char *upgrade = "Upgrade";
        assert(strncmp(value, upgrade, strlen(upgrade)) == 0);
      }
      else if (strncmp(key, Upgrade, strlen(Upgrade)) == 0){
        avail_Upgrade = true;
        char *ws = "websocket";
        assert(strncmp(value, ws, strlen(ws)) == 0);
      }
      else if (strncmp(key, Sec_WebSockey_Key, strlen(Sec_WebSockey_Key)) == 0){
        avail_Sec_WebSocket_Key = true;
        ws_sha1_hash_base64(value, strlen(value), ws_magic_value, strlen(ws_magic_value), (char *) ws_server_return, 30);
      }
      else if (strncmp(key, Sec_WebSockey_Version, strlen(Sec_WebSockey_Version)) == 0){
        avail_Sec_WebSocket_Version = true;
        // IDK WHAT TO DO HERE
      }
    }
  }

  // Generate Server response 
  {
    *resp_len = snprintf(response, *resp_len, "HTTP/1.1 101 Switching Protocol\r\n" \
        "Upgrade: websocket\r\n"\
        "Connection: Upgrade\r\n"\
        "Sec-WebSocket-Accept: %s\r\n\r\n", ws_server_return);

    printf("%.*s", *resp_len, response);
  }
}

void read_and_process_ws_headers(int clientsock){
#define DEFAULT_SIZE 1024
  int size = DEFAULT_SIZE;
  int bytes_left = size;
  int total_read = 0;
  char *buffer = (char *)malloc(sizeof(*buffer) * size);
  //char buffer[sizeof(char) * DEFAULT_SIZE];
  int running = 1;
  while( running && (bytes_left > 0)){
    int read_amt = recv(clientsock, buffer + total_read, bytes_left, 0); 
    // Find \r\n\r\n in the string
    if(present_in_string(buffer + total_read, "\r\n\r\n", read_amt, 4)) running = 0;
    total_read += read_amt;
    bytes_left -= total_read;
  }
  
  char resp[1024];
  int resp_size = 1024;
  process_ws_data(buffer, total_read, (char *)resp, &resp_size);
  int send_amt = send(clientsock, resp, resp_size, 0);
  free(buffer);
}

int main(){
#if 0
  char *a = "Abcdefghijklmn";
  char *b = "ghij";
  bool s = present_in_string(a, b, strlen(a), strlen(b));
  char *a2 = "Abcdefghijklmn";
  char *b2 = "xyza";
  s = present_in_string(a2, b2, strlen(a2), strlen(b2));
#endif
#if 0
  char *a = "dGhlIHNhbXBsZSBub25jZQ==";
  char *b = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char c [1024];
  ws_sha1_hash_base64(a, strlen(a), b, strlen(b), c, 1024);
#endif
  WSADATA wsadata;
  WSAStartup(MAKEWORD(2,2), &wsadata);
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sock == INVALID_SOCKET) print_and_exit(-1, "CANT CONNECT SOCKET");

  hostent*  localhost  =  gethostbyname("localhost");                
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


#if 0
  char client_request[256];
  client_request[255] = 0;

  int repeating = 1;
  while(repeating){
    int result_len = recv(clientsock, client_request, 256, 0);
    if(result_len == 0) repeating = 0;
    else if (result_len > 0) printf("%.*s", result_len, client_request);
    //result_len = send(clientsock, client_request, 256, 0);
  }
#else
  read_and_process_ws_headers(clientsock);
#endif

#if VERBOSE
  puts("CONNECTED");
#endif

  int size = DEFAULT_SIZE;
  char *buffer = (char *)malloc(sizeof(*buffer) * size);
  int recv_size = recv(clientsock, buffer, size, 0);
  closesocket(clientsock);
  closesocket(sock);

}
