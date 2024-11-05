#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#define BUF_SIZE 1024
#define alpha 0.125
#define beta 0.25
#define SAMPLE_SIZE 10

#define DBG(...) do {                                      \
    fprintf(stderr, "[DBG] %s:%d ", __FILE__, __LINE__);   \
    fprintf(stderr, __VA_ARGS__);                          \
    fprintf(stderr, "\n");                                 \
} while (0);

#define PANIC(...) do {                                    \
    fprintf(stderr, "[PANIC] %s:%d ", __FILE__, __LINE__); \
    fprintf(stderr, __VA_ARGS__);                          \
    fprintf(stderr, "\n");                                 \
    exit(1);                                               \
} while (0);


#define da_append(da, item)                                                              \
    do {                                                                                 \
        if ((da)->count >= (da)->capacity) {                                             \
            (da)->capacity = (da)->capacity == 0 ? BUF_SIZE : (da)->capacity*2;   \
            (da)->items = realloc((da)->items, (da)->capacity*sizeof(*(da)->items)); \
            assert((da)->items != NULL && "Buy more RAM lol");                       \
        }                                                                                \
                                                                                         \
        (da)->items[(da)->count++] = (item);                                             \
    } while (0)

/////////////////////////////
// checking the bits of flags to see if SYN, ACK, or SYNACK (0 if neither
#define ACK (1 << 4)
#define SYN (1 << 1)

FILE* convert_pcap_to_csv(char* filename){
    char buffer[BUF_SIZE];

    snprintf(buffer, BUF_SIZE, "tshark -r %s -T fields -Eseparator=',' -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.len -e tcp.time_delta -e tcp.flags -e tcp.ack -e tcp.seq -e tcp.window_size_value -e _ws.col.info", filename);

    FILE* pipe = popen(buffer, "r");

    return pipe;
}

typedef struct {
    size_t cwnd;
    size_t ssthresh;
    int congestionEvent;
    int no;
    double time;
    char *source;
    char *destination;
    int protocol;
    size_t length;
    size_t tcp_segment_len;
    double tcp_delta;
    int tcp_flags;
    size_t tcp_ack;
    size_t tcp_seq;
    size_t tcp_window_size;
    char *info;
} Row;

void remove_chars(char *s, char c) {
    int i = 0;
    for (char *v = s; *v; v++) {
        if (*v != c) {
            s[i++] = *v;
        }
    }
    s[i] = '\0';
}

char *read_column(ptr)
    char **ptr;
{
    if (**ptr == ',') {
        char *ret = *ptr;
        **ptr = '\0';
        *ptr += 1;
        return ret;
    }

    char *ret = *ptr;

    char skip = 0;
    for (;**ptr; *ptr += 1) {
        if (skip) {
            skip = 0;
            continue;
        }

        if (**ptr == '\\') skip = 1;
        if (**ptr == ',') break;
    }
    *(*ptr)++ = '\0';
    if (**ptr == ',') *ptr += 1;
    remove_chars(ret, '\\');
    return ret;
}

typedef struct {
    Row *items;
    size_t capacity;
    size_t count;
} Rows;

typedef struct {
    size_t key;
    size_t value;
} Entry;

typedef struct {
    Entry *items;
    size_t count;
    size_t capacity;
} Dict;

// Every pointer is an allocation, so either free or just agree that memory management is boring.
Rows parse_csv(fp)
    FILE* fp;
{
    Rows rows = { 0 };

    char buf[BUF_SIZE] = { 0 };
    while (fgets(buf, BUF_SIZE, fp)) {
        size_t len = strlen(buf);
        if (buf[len - 1] == '\n') buf[--len] = '\0';
        char *line = buf;
        printf("line = %s\n", line);
        Row row = { 0 };
        row.no = atoi(read_column(&line));
        row.time = atof(read_column(&line));
        row.source = strdup(read_column(&line));
        row.destination = strdup(read_column(&line));
        row.protocol = atoi(read_column(&line));
        row.length = atol(read_column(&line));
        row.tcp_segment_len = atoi(read_column(&line));
        row.tcp_delta = atof(read_column(&line));
        char *flags_col = read_column(&line);
        row.tcp_flags = *flags_col ? strtol(flags_col + 2, NULL, 16) : 0;
        row.tcp_ack = atol(read_column(&line));
        row.tcp_seq = atol(read_column(&line));
        row.tcp_window_size = atol(read_column(&line));
        char *info = strdup(line);
        remove_chars(info, '\\');
        row.info = info;
        da_append(&rows, row);
    }
    return rows;
}

char *escape_quotes(char *str) {
    size_t count = 0;
    for (char *s = str; *s; count += *(s++) == '"');
    size_t len = strlen(str) + count + 1;
    char *out = malloc(len);
    size_t i = 0;
    for (char *s = str; *s && i < len - 1; ++s) {
        if (*s == '"') {
            out[i++] = '\\';
            out[i++] = '"';
        } else {
            out[i++] = *s;
        }
    }
    return out;
}

void write_csv(FILE *out, Rows rows) {
    fprintf(out, "cwnd, ssthresh, congestionEvent, no, time, source, destination, protocol, length, tcp_segment_len, tcp_delta, tcp_flags, tcp_ack, tcp_seq, tcp_window_size, info\n");

    for (size_t i = 0; i < rows.count; ++i) {
        Row row = rows.items[i];
        fprintf(out, "%ld,", row.cwnd);
        fprintf(out, "%ld,", row.ssthresh);
        fprintf(out, "%d,", row.congestionEvent);
        fprintf(out, "%d,", row.no);
        fprintf(out, "%f,", row.time);
        char *s = escape_quotes(row.source);
        fprintf(out, "\"%s\",", s);
        free(s);
        s = escape_quotes(row.destination);
        fprintf(out, "\"%s\",", s);
        free(s);
        fprintf(out, "%d,", row.protocol);
        fprintf(out, "%ld,", row.length);
        fprintf(out, "%ld,", row.tcp_segment_len);
        fprintf(out, "%f,", row.tcp_delta);
        fprintf(out, "0x%04x,", row.tcp_flags);
        fprintf(out, "%ld,", row.tcp_ack);
        fprintf(out, "%ld,", row.tcp_seq);
        fprintf(out, "%ld,", row.tcp_window_size);
        remove_chars(row.info, '"');
        fprintf(out, "\"%s\"", row.info);
        fprintf(out, "\n");
    }
}

void print_rows(rows)
    Rows rows;
{
    for (size_t i = 0; i < rows.count; ++i) {
        printf("Row { no = %d, time = %lf, source = \"%s\", destination = \"%s\", protocol = %d, length = %ld, tcp_segment_len = %ld, tcp_delta = %lf, tcp_flags = 0x%04x, tcp_ack = %ld, tcp_seq = %ld, tcp_window_size = %ld, info = \"%s\" }\n",
                rows.items[i].no,
                rows.items[i].time,
                rows.items[i].source,
                rows.items[i].destination,
                rows.items[i].protocol,
                rows.items[i].length,
                rows.items[i].tcp_segment_len,
                rows.items[i].tcp_delta,
                rows.items[i].tcp_flags,
                rows.items[i].tcp_ack,
                rows.items[i].tcp_seq,
                rows.items[i].tcp_window_size,
                rows.items[i].info
          );
    }
}


/////////////////////////////
// Find and print congestion events from an array of Rows

typedef struct{
    char* source;
    char* destination;
    Dict acks;
    Dict seqs;
} Conversation;

typedef struct {
    Conversation *items;
    size_t capacity;
    size_t count;
} Conversations;

int compareConversations(Conversation first, Conversation second){
    return !(strcmp(first.source, second.source) || (strcmp(first.destination, second.destination)));
}

size_t *get_dict_entry(Dict dict, size_t key) {
    for (size_t i = 0; i < dict.count; ++i) {
        Entry *entry = &dict.items[i];
        if (entry->key == key) {
            return &entry->value;
        }
    }
    return NULL;
}

Rows reno = { 0 };
Rows taho = { 0 };

int handleCongestionEvents(Rows rows){
    // create a Conversation struct to keep track of duplicate acks for each conversation
    Conversations conversations = { 0 };
    Conversation conversation = {
        .source = rows.items[0].source,
        .destination = rows.items[0].destination,
        0
    };

    size_t renoCwnd = 1;
    size_t tahoCwnd = 1;
    size_t renoSsthresh = 8;
    size_t tahoSsthresh = 8;
    double sampleRtt = 0.0;
    int sampleSize = 0;
    double estimatedRtt = 0.0;
    double timeoutInterval = 0.0;
    double devRtt = 0.0;

    double samples[SAMPLE_SIZE] = {0};
    int currSample = 0;
    double averageRtt = 0.0;

    for (size_t i=0; i<rows.count; i++){
        // generate an estimatedRtt
        // work backwards to find ack packet, then back from that to find acked segment
        if (rows.items[i].tcp_flags & ACK){
            // find corresponding SYN
            for (int j=i; j>=0; j--){
                if (rows.items[j].tcp_seq + rows.items[j].tcp_segment_len == rows.items[i].tcp_ack){
                    // subtract the time to get the rtt
                    sampleRtt = rows.items[i].time - rows.items[j].time;
                    // place the sample in the correct spot
                    averageRtt *= sampleSize;
                    averageRtt -= samples[(currSample+1) % SAMPLE_SIZE];
                    if (sampleSize < SAMPLE_SIZE){
                        sampleSize++;
                    }
                    samples[currSample] = sampleRtt;
                    averageRtt += sampleRtt;
                    averageRtt /= sampleSize;
                    currSample++;
                    currSample %= SAMPLE_SIZE;
                    break;
                }
            }
        }
        printf("Average Rtt: %lf\n", averageRtt);
        // find estimated rtt
        estimatedRtt = (1 - alpha) * estimatedRtt + alpha * averageRtt;
        printf("Estimated Rtt: %lf\n", estimatedRtt);
        // find devRtt
        devRtt = (1 - beta) * devRtt + beta * fabs(averageRtt - estimatedRtt);
        printf("devRtt: %lf\n", devRtt);
        timeoutInterval = estimatedRtt + devRtt * 4;
        printf("Timout Interval: %lf\n", timeoutInterval);
        

        // triple duplicate ACKs.
        // Look for Four ACKS with the same ACK number from the same machine to another
        int same = 0;
        int found = 0;
        for (size_t j=0; j<conversations.count; j++){
            conversation.source = rows.items[i].source;
            conversation.destination = rows.items[i].destination;
            same = compareConversations(conversation, conversations.items[j]);
            if (same){
                found = 1;
                break;
            }
        }
        if (!found){
            da_append(&conversations, conversation);
        }

        // if this is an ack, add it to the tree
        int tcpType = rows.items[i].tcp_flags;
        if (tcpType & ACK && !(tcpType & SYN)){
            size_t* entry = get_dict_entry(conversation.acks, rows.items[i].tcp_ack);
            if (entry) {
                *entry += 1;
            } else {
                da_append(&conversation.acks, ((Entry) { .key = rows.items[i].tcp_ack, .value = 1 }));
            }
        } else if (rows.items[i].tcp_seq > 1){ 
            size_t* entry = get_dict_entry(conversation.seqs, rows.items[i].tcp_seq);
            if (entry){
                *entry += 1;
            } else {
                da_append(&conversation.seqs, ((Entry) { .key = rows.items[i].tcp_seq, .value = 1 }));
            }
            
        }
        if (tcpType & SYN){
            size_t* entry = get_dict_entry(conversation.seqs, rows.items[i].tcp_ack);
            if (entry) {
                *entry += 1;
            } else {
                da_append(&conversation.seqs, ((Entry) { .key = rows.items[i].tcp_ack, .value = 1 }));
            }
        }         
        // if there are 4 acks of the same ack print it size_t* count = get_dict_entry(conversation.acks, rows.items[i].tcp_ack);
        int congestionEvent = 0;
        size_t* count = get_dict_entry(conversation.acks, rows.items[i].tcp_ack);

        if (count && *count >= 4) {
            *count = 0;
            printf("Triple duplicate ack!\n");
            congestionEvent = 1;
        }

        // if there are 2 seqs of the same seq print it
        count = get_dict_entry(conversation.seqs, rows.items[i].tcp_seq);
        if (count && *count >= 2) {
            *count = 0;
            printf("Retransmission!\n");
            congestionEvent = 1;
        }

        // check window size
        if (rows.items[i].tcp_window_size < 10){
            printf("Window size too small!\n");
            congestionEvent = 1;
        }

        // cwnd = 1 MSS,
        // doubled every RTT, switch to linear when reaching half of its timeout cwnd
        // cwnd = sent, but not acked + available but not used
        // taho - cut to 1 MSS when triple dup
        // reno - cut in half when triple dup
        da_append(&taho, rows.items[i]);
        da_append(&reno, rows.items[i]);

        taho.items[taho.count-1].congestionEvent = congestionEvent;
        reno.items[reno.count-1].congestionEvent = congestionEvent;

        taho.items[taho.count-1].cwnd = tahoCwnd;
        reno.items[reno.count-1].cwnd = renoCwnd;
        taho.items[taho.count-1].ssthresh = tahoSsthresh;
        reno.items[reno.count-1].ssthresh = renoSsthresh;

        if (congestionEvent){
            renoSsthresh = renoCwnd >> 1;
            tahoSsthresh = tahoCwnd >> 1;
            tahoCwnd = 1;
            renoCwnd >>= 1;
        } else if (tcpType & ACK) {
            // Add tahoe
            if (tahoCwnd < tahoSsthresh){ 
                tahoCwnd <<= 1;
            } else {
                tahoCwnd -=- 1;
            }
            
            // Add reno
            if (renoCwnd < renoSsthresh){ 
                renoCwnd <<= 1;
            } else {
                renoCwnd -=- 1;
            }
        }




    }

    return 0;
}

int main(int argc, char** argv){
    if (argc < 2){
        fprintf(stderr, "Please supply the input file as an arg.\n");
        return 1;
    }

    char* filename = argv[1];

    FILE* csvFile = convert_pcap_to_csv(filename);

    Rows rows = parse_csv(csvFile);
    printf("\n"); // make jumping easier in tmux
    print_rows(rows);
    printf("\n"); // make jumping easier in tmux
    handleCongestionEvents(rows);
    printf("\n"); // make jumping easier in tmux

    FILE* tahoFile = fopen("taho_output.csv", "w");
    FILE* renoFile = fopen("reno_output.csv", "w");

    write_csv(tahoFile, taho);
    write_csv(renoFile, reno);

    return 0;
}

