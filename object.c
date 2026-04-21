// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ───────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Build header string e.g. "blob 16\0"
    const char *type_str = (type == OBJ_BLOB) ? "blob" :
                           (type == OBJ_TREE) ? "tree" : "commit";
    char header[64];
    int hlen = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1; // +1 for \0

    // Step 2: Combine header + data into one buffer
    size_t full_len = hlen + len;
    uint8_t *full = malloc(full_len);
    if (!full) return -1;
    memcpy(full, header, hlen);
    memcpy(full + hlen, data, len);

    // Step 3: Compute SHA-256 hash of full object
    compute_hash(full, full_len, id_out);

    // Step 4: Deduplication — skip if already exists
    if (object_exists(id_out)) { free(full); return 0; }

    // Step 5: Create shard directory e.g. .pes/objects/ab/
    char path[512], tmppath[512], dirpath[512];
    object_path(id_out, path, sizeof(path));
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    snprintf(dirpath, sizeof(dirpath), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(dirpath, 0755);

    // Step 6: Write to a temp file
    snprintf(tmppath, sizeof(tmppath), "%s.tmp", path);
    int fd = open(tmppath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { free(full); return -1; }
    write(fd, full, full_len);

    // Step 7: fsync temp file to disk
    fsync(fd);
    close(fd);
    free(full);

    // Step 8: Atomic rename temp -> final path
    if (rename(tmppath, path) < 0) return -1;

    // Step 9: fsync the directory to persist the rename
    int dfd = open(dirpath, O_RDONLY);
    if (dfd >= 0) { fsync(dfd); close(dfd); }

    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Get file path from hash
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 2: Open and read entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    size_t full_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *full = malloc(full_len);
    if (!full) { fclose(f); return -1; }
    fread(full, 1, full_len, f);
    fclose(f);

    // Step 3: Verify integrity by recomputing hash
    ObjectID computed;
    compute_hash(full, full_len, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) { free(full); return -1; }

    // Step 4: Find the \0 that separates header from data
    uint8_t *null_pos = memchr(full, '\0', full_len);
    if (!null_pos) { free(full); return -1; }

    // Step 5: Parse object type from header
    if      (strncmp((char*)full, "blob",   4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char*)full, "tree",   4) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char*)full, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else { free(full); return -1; }

    // Step 6: Copy data portion (everything after \0) into output buffer
    size_t header_len = null_pos - full + 1;
    *len_out = full_len - header_len;
    *data_out = malloc(*len_out);
    if (!*data_out) { free(full); return -1; }
    memcpy(*data_out, full + header_len, *len_out);
    free(full);
    return 0;
}