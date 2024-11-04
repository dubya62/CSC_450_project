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

#define DBG(...) do {                             \
    printf("[DBG] %s:%d ", __FILE__, __LINE__);   \
    printf(__VA_ARGS__);                          \
    printf("\n");                                 \
} while (0);

#define PANIC(...) do {                           \
    printf("[PANIC] %s:%d ", __FILE__, __LINE__); \
    printf(__VA_ARGS__);                          \
    printf("\n");                                 \
    exit(1);                                      \
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
        row.info = strdup(line);
        da_append(&rows, row);
    }

    for (size_t i = 0; i < rows.count; ++i) {
        printf("info %d = %d\n", i, rows.items[i].no);
    }
    return rows;
}

void print_rows(rows)
    Rows rows;
{
    for (size_t i = 0; i < rows.count; ++i) {
        printf("Row {\n\
    no = %d,\n\
    time = %lf,\n\
    source = \"%s\",\n\
    destination = \"%s\",\n\
    protocol = %d,\n\
    length = %ld,\n\
    tcp_segment_len = %ld,\n\
    tcp_delta = %lf,\n\
    tcp_flags = 0x%04x,\n\
    tcp_ack = %ld,\n\
    tcp_seq = %ld,\n\
    tcp_window_size = %ld,\n\
    info = \"%s\",\n }\n",
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
#define ACK 1
#define SYN 2
#define SYNACK 3
#define getTcpType(row) (((row.tcp_flags & 0x10) >> 4) | (row.tcp_flags & 0x2))

/////////////////////////////
// Tree data structure definition
typedef struct TreeNode{
    int active; // 4 bytes - whether or not this is an actual node
    size_t value; // 8 bytes
    int count; // special field for counting occurences 4 bytes

} TreeNode;

typedef struct Tree{
    size_t capacity;
    TreeNode* data;
} Tree;


Tree* initTree(size_t capacity){
    Tree* result = (Tree*) malloc(sizeof(Tree));
    result->capacity = capacity;
    size_t allocationSize = sizeof(TreeNode) * capacity;
    result->data = (TreeNode*) malloc(allocationSize);
    memset(result->data, 0, allocationSize);
    return result;
}


// get indices of interest. -1 if invalid
#define getLeftChild(tree, index) (-1 * ((index << 1) + 1 >= tree->capacity) + ((index << 1) + 1) * (((index) << 1) + 1< tree->capacity))
#define getRightChild(tree, index) (-1 * ((index << 1) + 2 >= tree->capacity) + ((index << 1) + 2) * ((index << 1) + 2 < tree->capacity))
#define getParent(tree, index) ((-1 * (index == 0)) + ((index-1) >> 1) * (index != 0))

// returns index of the value or -1 if not in the tree
size_t valueIsInTree(Tree* tree, size_t value){
    size_t curr = 0;
    while (1){
        if (!(tree->data[curr].active)){
            return -1;
        }
        if (tree->data[curr].value == value){
            return curr;
        } 
        if (tree->data[curr].value > value){
            curr = getLeftChild(tree, curr);
        } else {
            curr = getRightChild(tree, curr);
        }
        if (curr == -1){
            return curr;
        }
    }
}

// creates a new node if the element does not exists
// or increases the count if it does
// return 1 if a new node was created, 0 if added to the count, or -1 if no room
int addValueToTree(Tree* tree, size_t value){
    size_t curr = 0;
    while (1){
        if (!(tree->data[curr].active)){
            // this is where it should go
            tree->data[curr].active = 1;
            tree->data[curr].value = value;
            tree->data[curr].count = 1;
            return 1;
        }
        if (tree->data[curr].value == value){
            // increment the count
            tree->data[curr].count++;
            return 0;
        }
        if (tree->data[curr].value > value){
            curr = getLeftChild(tree, curr);
        } else {
            curr = getRightChild(tree, curr);
        }
        if (curr == -1){
            return -1;
        }
    }
}

// remove a given index from the tree and replace it with its successor
int handleRemovedNode(Tree* tree, size_t index){
    // go left, then right as far as possible
    int leftExists = getLeftChild(tree, index);
    if (leftExists == -1 || !(tree->data[leftExists].active)){
        // go right, then left as far as possible
        int rightExists = getRightChild(tree, index);
        if (rightExists == -1 || !(tree->data[rightExists].active)){
            // this node has no children. Exterminate
            tree->data[index].active = 0;
            return 0;
        }
        // now go left until a -1
        int leftmost = rightExists;
        while (leftmost != -1 && tree->data[leftmost].active){
            rightExists = leftmost;
            leftmost = getLeftChild(tree, leftmost);
        }
        tree->data[index].value = tree->data[rightExists].value;
        tree->data[index].count= tree->data[rightExists].count;
        // handle the node that was taken from
        handleRemovedNode(tree, rightExists);
        return 0;
    }
    // now go right until a -1
    int rightmost = leftExists;
    while (rightmost != -1 && tree->data[rightmost].active){
        leftExists = rightmost;
        rightmost = getRightChild(tree, rightmost);
    }
    tree->data[index].value = tree->data[leftExists].value;
    tree->data[index].count = tree->data[leftExists].count;
    // handle the node that was taken from
    handleRemovedNode(tree, leftExists);
    return 0;
}

// remove a node from a tree by value.
// return 1 if a node was deleted; otherwise -1
int removeValueFromTree(Tree* tree, size_t value){
    size_t curr = 0;
    while (1){
        if (!(tree->data[curr].active)){
            // this node does not exist
            return -1;
        }
        if (tree->data[curr].value == value){
            // delete this node
            handleRemovedNode(tree, curr);
            return 0;
        }
        if (tree->data[curr].value > value){
            curr = getLeftChild(tree, curr);
        } else {
            curr = getRightChild(tree, curr);
        }
        if (curr == -1){
            return -1;
        }
    }

}

// print tree
int printSubtree(Tree* tree, size_t index){
    int leftChild = getLeftChild(tree, index);
    int rightChild = getRightChild(tree, index);
    if (leftChild != -1){
        printSubtree(tree, leftChild);
    }
    if (tree->data[index].active){
        printf("%ld:%ld:%d\n", index, tree->data[index].value, tree->data[index].count);
    }
    if (rightChild != -1){
        printSubtree(tree, rightChild);
    }

}
int printTree(Tree* tree){
    printf("Index:Value:Count\n");
    printSubtree(tree, 0);
}

/////////////////////////////
// Find and print congestion events from an array of Rows

typedef struct{
    char* source;
    char* destination;
    Tree* acks;
    Tree* seqs;
} Conversation;

typedef struct {
    Conversation *items;
    size_t capacity;
    size_t count;
} Conversations;

int compareConversations(Conversation* first, Conversation* second){
    return !(strcmp(first->source, second->source) || (strcmp(first->destination, second->destination)));
}

Conversation* initConversation(char* source, char* destination){
    Conversation* conversation = (Conversation*) malloc(sizeof(Conversation));
    conversation->source = source;
    conversation->destination = destination;
    conversation->acks = initTree(25000);
    conversation->seqs = initTree(25000);
    return conversation;
}

Rows reno = { 0 };
Rows taho = { 0 };

int handleCongestionEvents(Rows rows){
    // create a Conversation struct to keep track of duplicate acks for each conversation
    Conversations conversations = { 0 };
    Conversation* conversation = initConversation(rows.items[0].source, rows.items[0].destination);

    for (size_t i=0; i<rows.count; i++){
        // triple duplicate ACKs.
        // Look for Four ACKS with the same ACK number from the same machine to another
        int same = 0;
        int found = 0;
        for (size_t j=0; j<conversations.count; j++){
            conversation->source = rows.items[i].source;
            conversation->destination = rows.items[i].destination;
            same = compareConversations(conversation, conversations.items+j);
            if (same){
                found = 1;
                break;
            }
        }
        if (!found){
            da_append(&conversations, *conversation);
        }

        // if this is an ack, add it to the tree
        int tcpType = getTcpType(rows.items[i]);
        if (tcpType & ACK){
            addValueToTree(conversation->acks, rows.items[i].tcp_ack);
        } 
        if (tcpType & SYN){
            addValueToTree(conversation->seqs, rows.items[i].tcp_seq);
        }         
        // if there are 4 acks of the same ack print it
        int conversationIndex = valueIsInTree(conversation->acks, rows.items[i].tcp_ack);
        if (conversationIndex > 0 && conversation->acks->data[conversationIndex].count >= 4){
            printf("Triple duplicate ack!\n");
        }
        printTree(conversation->acks);
    }

    return 0;
}

/////////////////////////////

int main(int argc, char** argv){
    
    if (argc < 2){
        fprintf(stderr, "Please supply the input file as an arg.\n");
        return 1;
    }

    char* filename = argv[1];

    FILE* csvFile = convert_pcap_to_csv(filename);

    Rows rows = parse_csv(csvFile);
    print_rows(rows);

    handleCongestionEvents(rows);

    return 0;
}

