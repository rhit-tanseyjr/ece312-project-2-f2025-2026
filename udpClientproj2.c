/************* UDP CLIENT CODE *******************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define SERVER "137.112.38.47"
#define MESSAGE "hello"
#define PORT 2526
#define BUFSIZE 1024

#define VERSION 12
#define DSTPORT 0x1874
#define TYPE 0
#define SRC_PORT 9438

#define RHMP_COMM_ID 0x312
#define RHMP_TYPE 4


#define RHP_DSTPORT_RHMP 0x0ECE

static size_t build_rhp_control(uint8_t *out, const char *msg,
                                uint16_t srcPort, uint16_t dstPort,
                                uint8_t version, uint8_t type);

static size_t build_rhmp(uint8_t **w,
                         uint16_t commID14, uint8_t rhmp_type6,
                         const uint8_t *pl, uint16_t pl_len);

static size_t build_rhp_with_rhmp(uint8_t *out,
                                  uint16_t srcPort, uint8_t version,
                                  uint16_t commID14, uint8_t rhmp_type6,
                                  const uint8_t *pl, uint16_t pl_len);

enum {
    RHMP_Reserved         = 0,
    RHMP_Message_Request  = 4,
    RHMP_Message_Response = 6,
    RHMP_ID_Request       = 16,
    RHMP_ID_Response      = 24
};


static void put_u8(uint8_t **p, uint8_t v){
    uint8_t* current = *p;
    *current = v;
    current = current+1;
    *p = current;
}

static void put_u16be(uint8_t **p, uint16_t v){
    uint8_t* current = *p;

    
    *current = (uint8_t)(v & 0xFF);
    current = current + 1;

    *current = (uint8_t)(v>>8);
    current = current + 1;


    *p = current;
}

static uint16_t internet_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint16_t)(((data[0] << 8)) | data[1]);
        data +=2;
        len -=2;
        if (sum & 0x10000) {
            sum = (sum & 0xFFFF) + 1;
        }
        }
        if (len == 1){
            sum += (uint16_t)(data[0] << 8);
        if (sum & 0x10000) {    
            sum = (sum & 0xFFFF) + 1;
        }
    }
    return (uint16_t)~(sum & 0xFFFF);
}

static void byte_to_bits(uint8_t b, char out[9]){
    for (int i =7; i>=0; i--) {
        out[7-i] = (char)('0' + ((b>>i) & 1));
        out[8] = '\0';
    }
}

static void dump_packet(const uint8_t* buf, size_t len, bool header) {
    if (header){
        printf("---- Sending packet (%zu bytes) ----\n", len);        
    } else {
        printf("---- Receiving packet (%zu bytes) ----\n", len);  
    }
    printf(" idx |  bits      | ascii \n");
    printf("--------------------------\n");

    for (size_t i = 0; i < len; i++) {
        char bits[9];
        for (int b = 7; b >= 0; --b)
            bits[7 - b] = ((buf[i] >> b) & 1) ? '1' : '0';
        bits[8] = '\0';

        char c = isprint(buf[i]) ? (char)buf[i] : '.';
        printf("%4zu | %s | %c\n", i, bits, c);
    }
    printf("------------------------------------\n");
}

static void print_message_recieved(const uint8_t* buffer, size_t nBytes) {
    uint8_t version = buffer[0];
    uint16_t srcPort = (buffer[2] << 8) | buffer[1];
    uint16_t dstPort = (buffer[4] << 8) | buffer[3];
    uint16_t len_type = (buffer[6] << 8) | buffer[5];

    
    uint16_t rhp_type = (len_type >> 12) & 0x0F;
    uint16_t payload_len = len_type & 0x0FFF;

    uint16_t checksum = (buffer[nBytes - 2] << 8) | buffer[nBytes - 1];

    printf("Message Recieved: \n");
    printf("    RHP version: %u\n", version);
    printf("    RHP type: %u\n", rhp_type);
    printf("    RHP src port: %u (0x%04X)\n", srcPort, srcPort);
    printf("    RHP dst port: %u (0x%04X)\n", dstPort, dstPort);
    printf("    RHP length: %u\n", payload_len);
    printf("    Checksum: 0x%04X\n", checksum);
}
 

static size_t build_rhp_control(uint8_t *out, const char *msg, uint16_t srcPort, uint16_t dstPort, uint8_t version, uint8_t type) {
    uint8_t* w = out;
    uint16_t payload_len = (uint16_t)strlen(msg);

    put_u8(&w, version);
    put_u16be(&w, srcPort);
    put_u16be(&w, dstPort);

    uint16_t len_type = (uint16_t)(((type & 0x0F) << 4) | (payload_len & 0x000F) | (payload_len & 0x0FF0) << 8);
   
    put_u16be(&w, len_type);
    
    size_t bytes_before_checksum = (size_t)(w - out) + payload_len;

    bool need_buffer = (bytes_before_checksum % 2) != 0;

    if (need_buffer) {
    put_u8(&w, 0x00);
    }

    memcpy(w, msg, payload_len);
    w += payload_len;

    
    put_u16be(&w, 0x0000);
    size_t total_len = (size_t)(w-out);
    uint16_t csum = internet_checksum(out, total_len);
    out[total_len - 2] = (uint8_t)(csum >> 8);
    out[total_len - 1] = (uint8_t)(csum & 0xFF);

    //dump_packet(out, total_len, true);
    printf("Computed checksum: 0x%04X\n", csum);

    uint16_t verify = internet_checksum(out, total_len);
    printf("Computed checksum: 0x%04X\n", verify);

    return total_len;
}

static size_t build_rhp_with_rhmp(uint8_t *out,
                                  uint16_t srcPort, uint8_t version,
                                  uint16_t commID14, uint8_t rhmp_type6,
                                  const uint8_t *pl, uint16_t pl_len)
{
    uint8_t *w = out;


    put_u8(&w, version);
    put_u16be(&w, srcPort);
    put_u16be(&w, RHP_DSTPORT_RHMP);


    uint8_t *len_type_at = w;
    put_u16be(&w, 0x0000);  // placeholder


    size_t rhmp_len = build_rhmp(&w, commID14, rhmp_type6, pl, pl_len);

    uint16_t rhp_payload_len = (uint16_t)rhmp_len;
    // uint16_t len_type = (uint16_t)(((RHMP_TYPE & 0x0F) << 4) | (0b0100 & 0x000F) | (0b0100 & 0x0FF0) << 8);
     uint16_t len_type = 0b0000010001000000;
    len_type_at[1] = (uint8_t)(len_type & 0xFF);   
    len_type_at[0] = (uint8_t)(len_type >> 8);


    size_t bytes_before_checksum = (size_t)(w - out);
    // if (bytes_before_checksum % 2) {
    //     put_u8(&w, 0x00);
    // }

    put_u16be(&w, 0x0000);
    size_t total_len = (size_t)(w-out);
    uint16_t csum = internet_checksum(out, total_len);
    out[total_len - 2] = (uint8_t)(csum >> 8);
    out[total_len - 1] = (uint8_t)(csum & 0xFF);

    //dump_packet(out, total_len, true);
    printf("Computed checksum: 0x%04X\n", csum);

    uint16_t verify = internet_checksum(out, total_len);
    printf("Computed checksum: 0x%04X\n", verify);

    return total_len;

    // uint8_t *chk = w;
    // put_u16be(&w, 0x0000);


    // size_t total_len = (size_t)(w - out);
    // uint16_t csum = internet_checksum(out, total_len);
    // chk[1] = (uint8_t)(csum & 0xFF);
    // chk[0] = (uint8_t)(csum >> 8);

    // return total_len;
}


static size_t build_rhmp(uint8_t **w,
                         uint16_t commID14, uint8_t rhmp_type6,
                         const uint8_t *pl, uint16_t pl_len)
{
    // uint16_t w0 = (uint16_t)((commID14 & 0x3FFF) | ((rhmp_type6 & 0x03) << 14));
    // uint16_t w0 = (uint16_t)(((commID14 << 10) & 0x3F00 ) | ((rhmp_type6 << 8) & 0x3) | (commID14 & 0x00FF));
    // uint16_t w0 = 0b0000001100010010;
    uint8_t w0 = (uint16_t)((commID14 & 0xFF));
    uint8_t w1 = (uint16_t)(((rhmp_type6 & 0x3) << 6) | ((commID14 & 0x3F00) >> 8));
    uint8_t w2 = (uint16_t)(((pl_len & 0xF) << 4 ) | ((rhmp_type6 & 0x3C) >> 2));
    uint8_t w3 = (uint16_t)((pl_len & 0xFF0 >> 4));


    // uint16_t w1 = (uint16_t)(((rhmp_type6 >> 2) & 0x0F) | ((pl_len & 0x0FFF) << 4));
    // uint16_t w1 = (uint16_t) (((pl_len << 8) & 0xFF ) | ((rhmp_type6 << 4) & 0x3C ) | (pl_len) & 0x00F);
    // uint16_t w1 = 0b0000000000000001;
    put_u8(w, 0x00);
    // put_u16be(w, w0);  
    // put_u16be(w, w1);
    put_u8(w, w0);
    put_u8(w, w1);
    put_u8(w, w2);
    put_u8(w, w3);

    if (pl_len && pl) {
        memcpy(*w, pl, pl_len);
        *w += pl_len;
    }
    return (size_t)(4 + pl_len);
}

int main() {
int clientSocket, nBytes;
char buffer[BUFSIZE];
struct sockaddr_in clientAddr, serverAddr;
uint8_t out[BUFSIZE];
// uint8_t* w = out;
// uint16_t payload_len = (uint16_t)strlen(MESSAGE);

/*Create UDP socket*/
if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("cannot create socket");
    return 0;
}

/* Bind to an arbitrary return address.
* Because this is the client side, we don't care about the address
* since no application will initiate communication here - it will
* just send responses
* INADDR_ANY is the IP address and 0 is the port (allow OS to select port)
* htonl converts a long integer (e.g. address) to a network representation
* htons converts a short integer (e.g. port) to a network representation */
memset((char *) &clientAddr, 0, sizeof (clientAddr));
clientAddr.sin_family = AF_INET;
clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
clientAddr.sin_port = htons(0);

if (bind(clientSocket, (struct sockaddr *) &clientAddr, sizeof (clientAddr)) < 0) {
    perror("bind failed");
    return 0;
}

/* Configure settings in server address struct */
memset((char*) &serverAddr, 0, sizeof (serverAddr));
serverAddr.sin_family = AF_INET;
serverAddr.sin_port = htons(PORT);
serverAddr.sin_addr.s_addr = inet_addr(SERVER);
memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);


// put_u8(&w, VERSION);
// put_u16be(&w, SRC_PORT);
// put_u16be(&w, DSTPORT);



// uint16_t len_type = (uint16_t)(((TYPE & 0x0F) << 4) | (payload_len & 0x000F) | (payload_len & 0x0FF0) << 8);
// put_u16be(&w, len_type);
  
// size_t bytes_before_checksum = (size_t)(w - out) + payload_len;

// bool need_buffer = (bytes_before_checksum % 2) != 0;


// if (need_buffer) {
//     put_u8(&w, 0x00);
// }



// memcpy(w, MESSAGE, payload_len);
// w += payload_len;


// put_u16be(&w, 0x0000);
// size_t total_len = (size_t)(w-out);
// uint16_t csum = internet_checksum(out, total_len);
// out[total_len - 2] = (uint8_t)(csum >> 8);
// out[total_len - 1] = (uint8_t)(csum & 0xFF);

printf("Sending RHMP Message_Request…\n");
size_t tx1 = build_rhp_with_rhmp(out, SRC_PORT, VERSION,
                                 RHMP_COMM_ID, RHMP_Message_Request,
                                 NULL, 0);
dump_packet(out, tx1, true);

if (sendto(clientSocket, out, tx1, 0,
           (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
    perror("sendto RHMP failed");
    return 0;
}

nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
if (nBytes > 0) {
    uint16_t chk = internet_checksum((const uint8_t*)buffer, (size_t)nBytes);
    printf("RHMP reply checksum %s\n", (chk == 0) ? "passed" : "FAILED");
    dump_packet((const uint8_t*)buffer, (size_t)nBytes, false);
    print_message_recieved((const uint8_t*)buffer, (size_t)nBytes);
}

// printf("Sending RHMP ID_Request…\n");
// size_t tx2 = build_rhp_with_rhmp(out, SRC_PORT, VERSION,
//                                  RHMP_COMM_ID, RHMP_ID_Request,
//                                  NULL, 0);
// dump_packet(out, tx2, true);

// if (sendto(clientSocket, out, tx2, 0,
//            (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
//     perror("sendto RHMP failed");
//     return 0;
// }

// nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
// if (nBytes > 0) {
//     uint16_t chk = internet_checksum((const uint8_t*)buffer, (size_t)nBytes);
//     printf("RHMP reply checksum %s\n", (chk == 0) ? "passed" : "FAILED");
//     dump_packet((const uint8_t*)buffer, (size_t)nBytes, false);
//     print_message_recieved((const uint8_t*)buffer, (size_t)nBytes);
// }


// size_t total_len = build_rhp_control(out, "hello", SRC_PORT, DSTPORT, VERSION, TYPE);
// printf("Sending RHP message: %s\n", MESSAGE);
// dump_packet(out, total_len, true);
// /* send a message to the server */
// if (sendto(clientSocket, out, total_len, 0,
// (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
//     perror("sendto failed");
//     return 0;
// }

// /* Receive message from server */
// nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
// uint16_t received_checksum = (buffer[nBytes - 2] << 8) | buffer[nBytes -1];
// uint16_t computed_checksum = internet_checksum((uint8_t*)buffer, nBytes);

// // if(computed_checksum == 0x0000){
// //     printf("Checksum passed\n");
// //     dump_packet((uint8_t*)buffer, (size_t)nBytes, false);
// //     print_message_recieved((uint8_t*)buffer, nBytes);
// // } else {
// //     printf("Checksum failed |\n");
// //     printf("Received: 0x%04X, Computed: 0x%04X \n", received_checksum, computed_checksum);
// //     printf("Resending message...\n");
// //     if (sendto(clientSocket, out, total_len, 0, (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
// //        perror("sendto failed");
// //        return 0;
// //     }
// //     nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
// //     computed_checksum = internet_checksum((uint8_t*)buffer, nBytes);

// //     if (computed_checksum == 0x0000) {
// //         printf("Checksum passed \n");
// //         //dump_packet((uint8_t*)buffer, (size_t)nBytes, false);
// //         print_message_recieved((uint8_t*)buffer, nBytes);
// //     } else {
// //         printf("Second attempt failed. Aborting.\n");
// //     }

// }

// printf("Received from server: %s\n", buffer);
// dump_packet(buffer, (size_t)nBytes, false);

// print_message_recieved(buffer, nBytes);


close(clientSocket);
return 0;
}

