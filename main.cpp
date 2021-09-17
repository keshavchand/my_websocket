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
  bool avail_Upgrade = 0;
  bool avail_Connection = 0;
  bool avail_Sec_WebSocket_Key = 0;
  bool avail_Sec_WebSocket_Version = 0;

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

  if (avail_Connection && avail_Upgrade && avail_Sec_WebSocket_Key && avail_Sec_WebSocket_Version) {
    // Generate Server response 
    *resp_len = snprintf(response, *resp_len, 
        "HTTP/1.1 101 Switching Protocol\r\n" \
        "Upgrade: websocket\r\n"\
        "Connection: Upgrade\r\n"\
        "Sec-WebSocket-Accept: %s\r\n\r\n", ws_server_return);

    printf("%.*s", *resp_len, response);
  }else {
    // SEND 400
    *resp_len = snprintf(response, *resp_len, 
        "HTTP/1.1 400 Bad Request\r\n" \
        "Content-Type: text/html; charset=UTF-8\r\n"\
        "\r\n%s", "<HTML> BAD WEBSOCKET REQUEST </HTML>");
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

  { //RECV DATA
    int size = DEFAULT_SIZE;
    unsigned char *buffer = (unsigned char *)malloc(sizeof(*buffer) * size);
    int recv_size = recv(clientsock, (char *)buffer, size, 0);
    //if msb of first byte is 1 then it is full message
    int is_complete_msg = 0;
    int bytes_idx = 0;
    if ((buffer[bytes_idx] & 128) == 128) is_complete_msg = 1;

    bytes_idx += 1;
    //If first bit is masked then it will be from client
    //server wont mast the first bit
    assert((buffer[bytes_idx] & 128) == 128);
    //if reset of the bits are below 126 then it is length
    int msg_len = 0;
    if (((buffer[bytes_idx] & ~128) & 0xff) <= 125) {
      msg_len = (buffer[bytes_idx] & ~128) & 0xff ;
      bytes_idx += 1;
    }
    //if reset of the bits are 126 then length is next two bytes
    else if (((buffer[bytes_idx] & ~128) & 0xff) == 126){
      msg_len = ntohs(*(short *) (buffer + bytes_idx + 1));
      bytes_idx += 2;
      bytes_idx += 1;
    }
    //if reset of the bits are 127 then length is next eight bytes
    else if (((buffer[bytes_idx] & ~128) & 0xff) == 127){
      // THIS LARGE???
      msg_len = ntohll(*(unsigned __int64 *) (buffer + bytes_idx + 1));
      bytes_idx += 8;
      bytes_idx += 1;
    }

    assert(msg_len <= recv_size - bytes_idx + 4);

    // KEYS are 4 bytes that xor message for some reason
    unsigned char keys[4];
    for (int idx = 0 ; idx < 4; idx++) {
      keys[idx] = buffer[bytes_idx];
      bytes_idx += 1;
    }
  
    int remaining_len = recv_size - bytes_idx;
    unsigned char *msg = buffer + bytes_idx;
    for (int idx = 0; idx <= msg_len && idx <= remaining_len; idx++) {
      msg[idx] ^= keys[idx % 4];
    }

    free(buffer);
    printf("%.*s\n", msg_len, msg);
  }
 
  {//SEND DATA
    int size = DEFAULT_SIZE;
    unsigned char *buffer = (unsigned char*) malloc(sizeof(*buffer) * size);
    int bytes_idx = 0;
    //First bit set because its complete message
    //else its next
    buffer[bytes_idx] = 129;
    bytes_idx += 1;
    
    char * msg = "HELLO WORLD";
    int msg_size = strlen(msg);
    if (msg_size <= 125) {
      buffer[bytes_idx] = msg_size;
    } else if (msg_size == 126) {
      buffer[bytes_idx] = 126;
      *(short *)(buffer + bytes_idx + 1) = htons(msg_size);
      bytes_idx += 2;
    }else if (msg_size == 127) {
      buffer[bytes_idx] = 127;
      *(unsigned __int64 *)(buffer + bytes_idx + 1) = htonll(msg_size);
      bytes_idx += 8;
    }
    bytes_idx += 1;

    int remaining_size = size - bytes_idx;
    for (int i = 0 ; i < msg_size && i < remaining_size; i++) {
      buffer[bytes_idx] = msg[i];  
      bytes_idx += 1;
    }
    send(clientsock, (const char*) buffer, bytes_idx, 0);
  }
  closesocket(clientsock);
  closesocket(sock);

}
