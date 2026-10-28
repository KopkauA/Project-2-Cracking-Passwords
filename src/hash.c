/*

REQUIREMENTS:
- Change the code in the file hash.c to make it faster using threads without changing the correct output. 
- You cannot modify other files (main.c, hash.h, hash_functions.c, hash_functions.h, Makefile). 
- You are only allowed to use:
	1. The pthread and semaphore libraries (and other standard C libraries), 
	2. Your knowledge of algorithms and data structures
	3. Your C coding skills
- Using non-standard libraries, changing compiler flags, and other tricks are not allowed. 
- If, at any point in time, your program has more than 12 threads (including the main thread) in execution, your submission will be deemed invalid. 
- In other words, your process cannot have more than 12 threads running simultaneously.

*/

/*
Group: Group #16
Members: Aubrey Kopkau (U12459434), Chloe Robinson (U17294327), [Name 3 (UID)], [Name 4 (UID)]
Description: Modification of hash.c to improve password cracking performance while preserving correct output and original password and algorithm ordering. 
Improvements made include:
    Computing MD5, SHA1, SHA256 and SHA512 concurrently across password recordings
    Storing first 16B in binary form avoiding hexadecimal string conversion
    Using hash table to optimize hash comparison
    Replace sprintf with memcompare for hash table look up
    Preserving the original password and algorithm order to ensure the output remains correct.
*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

//Added allowed libraries
#include <pthread.h>
#include <semaphore.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define MAX_WORKERS 11 // 11 workers + 1 main threads to calculate hash passwords
#define HASH_BUCKETS 65536 // 2^16 buckets for hash table
#define CHUNK_SIZE 64 // 64 passwords at once

//ADDED: helper functions for hashing and comparing hashes
/* Helper to convert a single hex character to its 4-bit nibble */
static inline int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

/* Converts a 32-character hex string into 16 raw binary bytes */
static void hex_to_bin(const char *hex, unsigned char *bin) {
    for (int i = 0; i < KEEP; i++) {
        bin[i] = (unsigned char)((hex_char_to_val(hex[2 * i]) << 4) |
                                 hex_char_to_val(hex[2 * i + 1]));
    }
}

/* Fast bucket indexing: use the first 2 raw bytes (16 bits) directly */
static inline size_t hash_bin(const unsigned char *b) {
    return (((size_t)b[0] << 8) | (size_t)b[1]) % HASH_BUCKETS;
}

struct cracked_hash {
    unsigned char bin_hash[KEEP];
    char *password;
    const char *alg;
    size_t found_idx;           // Password index to enforce first-occurrence rule
    pthread_mutex_t lock;       // Per-target entry lock
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

static const int n_algs = 4;
static hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
static char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

struct stream_context {
    FILE *fp_passwords;
    pthread_mutex_t file_mutex;
    size_t current_idx;
    int eof_reached;

    struct cracked_hash *cracked;
    int n_hashed;
    size_t *heads;
    size_t *next;

    int remaining_unfound;
    pthread_mutex_t count_mutex;
};

static void *hash_worker(void *arg) {
    struct stream_context *ctx = (struct stream_context *)arg;
    char local_passwords[CHUNK_SIZE][256];
    size_t local_indices[CHUNK_SIZE];

    while (1) {
        // Early exit: stop immediately if all targets have been solved
        pthread_mutex_lock(&ctx->count_mutex);
        if (ctx->remaining_unfound <= 0) {
            pthread_mutex_unlock(&ctx->count_mutex);
            break;
        }
        pthread_mutex_unlock(&ctx->count_mutex);

        // Read next dynamic batch directly from file (streaming)
        pthread_mutex_lock(&ctx->file_mutex);
        if (ctx->eof_reached) {
            pthread_mutex_unlock(&ctx->file_mutex);
            break;
        }

        int count = 0;
        size_t base_idx = ctx->current_idx;
        while (count < CHUNK_SIZE && fscanf(ctx->fp_passwords, "%255s", local_passwords[count]) == 1) {
            local_indices[count] = base_idx + count;
            count++;
        }
        ctx->current_idx += count;

        if (count < CHUNK_SIZE) {
            ctx->eof_reached = 1;
        }
        pthread_mutex_unlock(&ctx->file_mutex);

        if (count == 0) {
            break;
        }

        // Hash and match immediately in parallel
        for (int p = 0; p < count; p++) {
            char *pwd = local_passwords[p];
            size_t idx = local_indices[p];
            unsigned int len = (unsigned int)strlen(pwd);

            for (int i = 0; i < n_algs; i++) {
                unsigned char *hash = fn[i]((unsigned char *)pwd, len);
                if (!hash) continue;

                size_t b = hash_bin(hash);

                for (size_t j = ctx->heads[b]; j != (size_t)-1; j = ctx->next[j]) {
                    struct cracked_hash *target = &ctx->cracked[j];

                    if (memcmp(hash, target->bin_hash, KEEP) == 0) {
                        pthread_mutex_lock(&target->lock);
                        if (target->password == NULL) {
                            target->password = strdup(pwd);
                            target->alg = algs[i];
                            target->found_idx = idx;

                            pthread_mutex_lock(&ctx->count_mutex);
                            ctx->remaining_unfound--;
                            pthread_mutex_unlock(&ctx->count_mutex);
                        } else if (idx < target->found_idx) {
                            free(target->password);
                            target->password = strdup(pwd);
                            target->alg = algs[i];
                            target->found_idx = idx;
                        }
                        pthread_mutex_unlock(&target->lock);
                    }
                }

                free(hash);
            }
        }
    }

    return NULL;
}

/*
    Function: crack_hashed_passwords
    Parameters: 
        password_list:
        harshed_list:
        output:
*/
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    FILE *fp;
    char hex_hash[256];

    // 1. Load hashed passwords
    int n_hashed = 0;
    fp = fopen(hashed_list, "r");
    assert(fp != NULL);
    while (fscanf(fp, "%255s", hex_hash) == 1)
        n_hashed++;
    rewind(fp);

    struct cracked_hash *cracked_hashes = malloc(n_hashed * sizeof(struct cracked_hash));
    assert(n_hashed == 0 || cracked_hashes != NULL);
    for (int i = 0; i < n_hashed; i++) {
        fscanf(fp, "%255s", hex_hash);
        hex_to_bin(hex_hash, cracked_hashes[i].bin_hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;
        cracked_hashes[i].found_idx = (size_t)-1;
        pthread_mutex_init(&cracked_hashes[i].lock, NULL);
    }
    fclose(fp);

    // Hash Table Mapping Target digest to target indices
    size_t *heads = malloc(HASH_BUCKETS * sizeof(*heads));
    size_t *next = malloc((size_t)n_hashed * sizeof(*next));
    assert(heads != NULL);
    assert(n_hashed == 0 || next != NULL);

    for (size_t b = 0; b < HASH_BUCKETS; b++)
        heads[b] = (size_t)-1;

    for (int i = n_hashed - 1; i >= 0; i--) {
        size_t b = hash_bin(cracked_hashes[i].bin_hash);
        next[i] = heads[b];
        heads[b] = (size_t)i;
    }

    // Open password file for parallel streaming (no giant array in memory)
    FILE *fp_passwords = fopen(password_list, "r");
    assert(fp_passwords != NULL);
    setvbuf(fp_passwords, NULL, _IOFBF, 64 * 1024);

    // Initialize streaming synchronization context
    struct stream_context ctx = {
        .fp_passwords = fp_passwords,
        .current_idx = 0,
        .eof_reached = 0,
        .cracked = cracked_hashes,
        .n_hashed = n_hashed,
        .heads = heads,
        .next = next,
        .remaining_unfound = n_hashed
    };

    pthread_mutex_init(&ctx.file_mutex, NULL);
    pthread_mutex_init(&ctx.count_mutex, NULL);

    pthread_t threads[MAX_WORKERS];
    int created = 0;

    for (int i = 0; i < MAX_WORKERS; i++) {
        if (pthread_create(&threads[created], NULL, hash_worker, &ctx) != 0)
            break;
        created++;
    }

    // Main thread helps process chunks (11 workers + 1 main thread = 12 total threads)
    hash_worker(&ctx);

    for (int i = 0; i < created; i++)
        pthread_join(threads[i], NULL);

    fclose(fp_passwords);

    // Print results in original target hash order
    fp = fopen(output, "w");
    assert(fp != NULL);
    for (int i = 0; i < n_hashed; i++) {
        if (cracked_hashes[i].password == NULL)
            fprintf(fp, "not found\n");
        else
            fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
    }
    fclose(fp);

    // Free resources
    pthread_mutex_destroy(&ctx.file_mutex);
    pthread_mutex_destroy(&ctx.count_mutex);

    for (int i = 0; i < n_hashed; i++) {
        free(cracked_hashes[i].password);
        pthread_mutex_destroy(&cracked_hashes[i].lock);
    }

    free(next);
    free(heads);
    free(cracked_hashes);
}