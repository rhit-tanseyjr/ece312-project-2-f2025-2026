/************* UDP CLIENT CODE *******************
 * Authors: John Tansey & Elliott Rogers
 * Date: 10/21/2025
 * 
 * Description:
 * Builds and sends RHP control and RHMP request packets to a server,
 * receives responses, verifies checksums, and prints parsed packet data.
 */

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

/*
*   Writes an 8-bit value to a buffer in big-endian order 
*   and advances the pointer.
*/
static void put_u8(uint8_t **p, uint8_t v){
    uint8_t* current = *p;
    *current = v;
    current = current+1;
    *p = current;
}

/*
*   Writes a 16-bit value to a buffer in big-endian order 
*   and advances the pointer.
*/
static void put_u16be(uint8_t **p, uint16_t v){
    uint8_t* current = *p;

    
    *current = (uint8_t)(v & 0xFF);
    current = current + 1;

    *current = (uint8_t)(v>>8);
    current = current + 1;


    *p = current;
}

/*
*   Calculates the Internet checksum (one’s complement sum) 
*   for the given data buffer.
*/
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

/*
*   Converts a byte to its 8-bit binary string representation.
*/
static void byte_to_bits(uint8_t b, char out[9]){
    for (int i =7; i>=0; i--) {
        out[7-i] = (char)('0' + ((b>>i) & 1));
        out[8] = '\0';
    }
}

/*
*   Prints a formatted hex and ASCII dump of a packet buffer.
*/
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

/*
*   Parses and prints the fields of a received RHP message.
*/
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


/*
*  Builds an RHP control packet from the given message and header fields.
*/
static size_t build_rhp_control(uint8_t *out, const char *msg, uint16_t srcPort, uint16_t dstPort, uint8_t version, uint8_t type) {
    uint8_t* w = out;
    uint16_t payload_len = (uint16_t)strlen(msg);

    // Write RHP header fields
    put_u8(&w, version);
    put_u16be(&w, srcPort);
    put_u16be(&w, dstPort);

     // Combine type (upper 4 bits) and payload length (lower 12 bits)
    uint16_t len_type = (uint16_t)(((type & 0x0F) << 4) | (payload_len & 0x000F) | (payload_len & 0x0FF0) << 8);
    put_u16be(&w, len_type);

    // Determine bytes before checksum for alignment
    size_t bytes_before_checksum = (size_t)(w - out) + payload_len;

    // Add buffer byte if payload length is odd (word alignment)
    bool need_buffer = (bytes_before_checksum % 2) != 0;
    if (need_buffer) {
    put_u8(&w, 0x00);
    }

    //Copy payload into packet
    memcpy(w, msg, payload_len);
    w += payload_len;

    // Reserve space for checksum
    put_u16be(&w, 0x0000);

    //Compute and insert Internet checksum
    size_t total_len = (size_t)(w-out);
    uint16_t csum = internet_checksum(out, total_len);
    out[total_len - 2] = (uint8_t)(csum >> 8);
    out[total_len - 1] = (uint8_t)(csum & 0xFF);

    // Uncomment for debugging packet contents
    //dump_packet(out, total_len, true);
    printf("Computed checksum: 0x%04X\n", csum);

    // Verify checksum correctness after insertion
    uint16_t verify = internet_checksum(out, total_len);
    printf("Computed checksum: 0x%04X\n", verify);

    return total_len;
}

/*
* Builds an RHP packet carrying an RHMP payload
*/ 
static size_t build_rhp_with_rhmp(uint8_t *out,
                                  uint16_t srcPort, uint8_t version,
                                  uint16_t commID14, uint8_t rhmp_type6,
                                  const uint8_t *pl, uint16_t pl_len)
{
    uint8_t *w = out;

    // RHP header (version, src, dst)
    put_u8(&w, version);
    put_u16be(&w, srcPort);
    put_u16be(&w, RHP_DSTPORT_RHMP);

    // Remember location of len_type
    uint8_t *len_type_at = w;
    put_u16be(&w, 0x0000);  // placeholder (to be filled once length is known)

    // Build RHMP payload into the packet and get its length in bytes
    size_t rhmp_len = build_rhmp(&w, commID14, rhmp_type6, pl, pl_len);

    // Contstruct RHP len type field
    uint16_t rhp_payload_len = (uint16_t)rhmp_len;
    uint16_t len_type = (uint16_t)(((rhp_payload_len & 0x0FF) << 8) | ((RHMP_TYPE & 0xF) <<4) | ((rhp_payload_len) & 0xF00) >> 4);

    // Backfill len|type 
    len_type_at[0] = (uint8_t)(len_type >> 8);
    len_type_at[1] = (uint8_t)(len_type & 0xFF);

    // Reserve checksum field, compute, and insert it
    put_u16be(&w, 0x0000);
    size_t total_len = (size_t)(w - out);

    uint16_t csum = internet_checksum(out, total_len);
    out[total_len - 2] = (uint8_t)(csum >> 8);
    out[total_len - 1] = (uint8_t)(csum & 0xFF);

    // Uncomment for debugging packet contents
    // dump_packet(out, total_len, true);
    printf("Computed checksum: 0x%04X\n", csum);

    // Quick verify after insertion (should be 0x0000)
    uint16_t verify = internet_checksum(out, total_len);
    printf("Verification checksum: 0x%04X\n", verify);

    return total_len;
}

/*
*   Builds an RHMP header (commID:14, type:6, len:12) plus payload; advances *w and returns bytes written.
*/
static size_t build_rhmp(uint8_t **w,
                         uint16_t commID14, uint8_t rhmp_type6,
                         const uint8_t *pl, uint16_t pl_len)
{


    // Pack header bytes:
    // b0: low 8 bits of commID
    uint8_t w0 = (uint16_t)((commID14 & 0xFF));
    // b1: top 2 bits = rtype[1:0], low 6 bits = commID[13:8]
    uint8_t w1 = (uint16_t)(((rhmp_type6 & 0x3) << 6) | ((commID14 & 0x3F00) >> 8));
    // b2: high nibble = len[3:0], low nibble = rtype[5:2]
    uint8_t w2 = (uint16_t)(((pl_len & 0xF) << 4 ) | ((rhmp_type6 & 0x3C) >> 2));
    // b3: len[11:4]
    uint8_t w3 = (uint16_t)((pl_len & 0xFF0 >> 4));

    //Insert Buffer
    put_u8(w, 0x00);

    // Write header
    put_u8(w, w0);
    put_u8(w, w1);
    put_u8(w, w2);
    put_u8(w, w3);


    // Write payload (if any)
    if (pl_len && pl) {
        memcpy(*w, pl, pl_len);
        *w += pl_len;
    }

    // 4 header bytes + payload
    return (size_t)(4 + pl_len);
}

// Parses and prints the contents of an RHMP response packet.
static void parse_rhmp_response(const uint8_t* buffer, size_t nBytes) {

    // Verify checksum over the entire packet
    uint16_t chk = internet_checksum(buffer, nBytes);
    printf("Checksum %s\n", (chk == 0) ? "passed" : "FAILED");

    // Extract RHP header fields
    uint8_t version = buffer[0];
    uint16_t srcPort = (buffer[2] << 8) | buffer[1];
    uint16_t dstPort = (buffer[4] << 8) | buffer[3];
    uint16_t len_type = (buffer[6] << 8) | buffer[5];
    uint8_t rhp_type = (len_type >> 12) & 0x0F;
    uint16_t payload_len = len_type & 0x0FFF;
    uint16_t checksum = (buffer[nBytes - 2] << 8) | buffer[nBytes - 1];

    // Print RHP header information
    printf("RHP Header:\n");
    printf("    Version: %u\n", version);
    printf("    Type: %u\n", rhp_type);
    printf("    Src Port: %u (0x%04X)\n", srcPort, srcPort);
    printf("    Dst Port: %u (0x%04X)\n", dstPort, dstPort);
    printf("    Length: %u\n", payload_len);
    printf("    Checksum: 0x%04X\n", checksum);

    // Locate RHMP header and payload within the RHP packet
    const uint8_t* rhmp = buffer + 7;
    const uint8_t* payload = rhmp + 4;

    // Handle RHP Control messages (type 0)
    if (rhp_type == 0) {
        printf("RHP Control Payload: ");
        for (int i = 0; i < payload_len; i++) {
            char c = isprint(payload[i]) ? payload[i] : '.';
            printf("%c", c);
        }
        printf("\n");
    }

    // Handle RHP type 4: RHMP response packets
    else if (rhp_type == 4 && payload_len >= 4) {
        
        // Extract RHMP header fields
        uint8_t b0 = rhmp[1];
        uint8_t b1 = rhmp[2];
        uint8_t b2 = rhmp[3];
        uint8_t b3 = rhmp[4];

        // Handle possible odd-length alignment difference
        if (payload_len % 2 != 0) {   
            b0 = rhmp[0];
            b1 = rhmp[1];
            b2 = rhmp[2];
            b3 = rhmp[3];
        }

        // Decode RHMP header bit fields
        uint16_t commID = (uint16_t)(b0 | ((b1 & 0x3F) << 8));
        uint8_t type = (uint8_t)(((b1 & 0xC0) >> 6) | ((b2 & 0x0F) << 2));
        uint16_t length = (uint16_t)(((b2 & 0xF0) >> 4) | (b3 << 4));

        // Print RHMP header info
        printf("RHMP Response: \n");
        printf("    commID: %u (0x%04X)\n", commID, commID);
        printf("    type: %u\n", type);
        printf("    length: %u\n", length);
    
        // Handle RHMP Message Response (prints message string)
        if (type == RHMP_Message_Response) {
            printf("    Message: ");
            for (int i = 0; i < length; i++) {
                char c = isprint(payload[i]) ? payload[i] : '.';
                printf("%c", c);
            }
            printf("\n");
        }

        // Handle RHMP ID Response (prints 4-byte integer)
        else if (type == RHMP_ID_Response && length == 4) {
            uint32_t id = (payload[0] << 24) | (payload[1] << 16) |
                          (payload[2] << 8) | payload[3];
            printf("    ID: %u (0x%08X)\n", id, id);
        }

        // Unknown response type
        else printf("   Unknown Type! ");
    
        printf("\n");
    }
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


    // Build and send a RHP control message: hi
    size_t tx_hi = build_rhp_control(out, "hi", SRC_PORT, DSTPORT, VERSION, TYPE);
    printf("\nRHP cotrol message: hi\n");
    //dump_packet(out, tx_hi, true);
    sendto(clientSocket, out, tx_hi, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    // if reply fails checksum, retry once
    if (internet_checksum(buffer, nBytes) != 0) {
        printf("Checksum failed — retrying...\n");
        sendto(clientSocket, out, tx_hi, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    }
    //dump_packet(buffer, nBytes, false);
    parse_rhmp_response(buffer, nBytes);

    // Build and send RHP control message: hello
    size_t tx_hello = build_rhp_control(out, "hello", SRC_PORT, DSTPORT, VERSION, TYPE);
    printf("\nRHP control message: hello\n");
    //dump_packet(out, tx_hello, true);
    sendto(clientSocket, out, tx_hello, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    // Retry once on checksum failure
    if (internet_checksum(buffer, nBytes) != 0) {
        printf("Checksum failed — retrying...\n");
        sendto(clientSocket, out, tx_hello, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    }
    //dump_packet(buffer, nBytes, false);
    parse_rhmp_response(buffer, nBytes);

    // Build and send RHMP Message_Request 
    size_t tx_msg = build_rhp_with_rhmp(out, SRC_PORT, VERSION, RHMP_COMM_ID, RHMP_Message_Request, NULL, 0);
    printf("\nRHMP Message_Request\n");
    //dump_packet(out, tx_msg, true);
    sendto(clientSocket, out, tx_msg, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    // Retry once on checksum failure
    if (internet_checksum(buffer, nBytes) != 0) {
        printf("Checksum failed — retrying...\n");
        sendto(clientSocket, out, tx_msg, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    }
    // dump_packet(buffer, nBytes, false);
    parse_rhmp_response(buffer, nBytes);

    // Build and send RHMP ID_Request
    size_t tx_id = build_rhp_with_rhmp(out, SRC_PORT, VERSION, RHMP_COMM_ID, RHMP_ID_Request, NULL, 0);
    printf("\nRHMP ID_Request\n");
    // dump_packet(out, tx_id, true);
    sendto(clientSocket, out, tx_id, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    // Retry once on checksum failure
    if (internet_checksum(buffer, nBytes) != 0) {
        printf("Checksum failed — retrying...\n");
        sendto(clientSocket, out, tx_id, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);
    }
    parse_rhmp_response(buffer, nBytes);
    // dump_packet(buffer, nBytes, false);




    close(clientSocket);
    return 0;
}