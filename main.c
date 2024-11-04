#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define BUF_SIZE 1024

FILE* convert_pcap_to_csv(char* filename){
    char buffer[BUF_SIZE];

    snprintf(buffer, BUF_SIZE, "tshark -r %s -T fields -Eseparator=',' -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.len -e tcp.time_delta -e tcp.flags -e tcp.ack -e tcp.seq -e tcp.window_size_value -e _ws.col.info", filename);

    FILE* pipe = popen(buffer, "r");

    return pipe;
}

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

typedef struct {
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
    for (size_t i = 0; i < rows.count; ++i) {
        Row row = rows.items[i];
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
        s = escape_quotes(row.info);
        fprintf(out, "\"%s\"", s);
        free(s);
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
// checking the bits of flags to see if SYN, ACK, or SYNACK (0 if neither
#define ACK (1 << 4)
#define SYN (1 << 1)

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

    for (size_t i=0; i<rows.count; i++){
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
        if (tcpType & ACK){
            size_t *entry = get_dict_entry(conversation.acks, rows.items[i].tcp_ack);
            if (entry) {
                *entry += 1;
            } else {
                da_append(&conversation.acks, ((Entry) { .key = rows.items[i].tcp_ack, .value = 1 }));
            }
        } else { // if this is not an ack, check for retransmission
            size_t *entry = get_dict_entry(conversation.seqs, rows.items[i].tcp_seq);
            if (entry){
                *entry += 1;
            } else {
                da_append(&conversation.seqs, ((Entry) { .key = rows.items[i].tcp_seq, .value = 1 }));
            }
            
        }
        if (tcpType & SYN){
            size_t *entry = get_dict_entry(conversation.seqs, rows.items[i].tcp_ack);
            if (entry) {
                *entry += 1;
            } else {
                da_append(&conversation.seqs, ((Entry) { .key = rows.items[i].tcp_ack, .value = 1 }));
            }
        }         
        // if there are 4 acks of the same ack print it
        size_t* count = get_dict_entry(conversation.acks, rows.items[i].tcp_ack);
        if (count && *count >= 4) {
            printf("Triple duplicate ack!\n");
        }

        // if there are 2 seqs of the same seq print it
        count = get_dict_entry(conversation.seqs, rows.items[i].tcp_seq);
        if (count && *count >= 2) {
            printf("Retransmission!\n");
        }

        // check window size
        if (rows.items[i].tcp_window_size < 10){
            printf("Window size too small!\n");
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
    //write_csv(stdout, rows);

    return 0;
}

