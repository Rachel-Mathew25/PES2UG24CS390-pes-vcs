// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1;

        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';

        ptr = null_byte + 1;

        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1;
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Recursive helper: builds a tree from a slice of index entries at a given depth
static int write_tree_level(IndexEntry *entries, int count, int depth, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        // Find the component at this depth level
        char *path = entries[i].path;

        // Split path by '/'
        char *slash = strchr(path, '/');

        if (slash == NULL) {
            // This is a file at this level
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            strncpy(te->name, path, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            te->hash = entries[i].id;
            i++;
        } else {
            // This is a subdirectory — group all entries with same prefix
            char dirname[256];
            size_t dirlen = slash - path;
            strncpy(dirname, path, dirlen);
            dirname[dirlen] = '\0';

            // Find all entries belonging to this subdirectory
            int j = i;
            while (j < count) {
                char *p = entries[j].path;
                char *s = strchr(p, '/');
                if (s == NULL) break;
                size_t dl = s - p;
                if (dl != dirlen || strncmp(p, dirname, dirlen) != 0) break;
                j++;
            }

            // Build sub-entries with prefix stripped
            IndexEntry *sub = malloc((j - i) * sizeof(IndexEntry));
            if (!sub) return -1;
            for (int k = i; k < j; k++) {
                sub[k - i] = entries[k];
                // Strip "dirname/" prefix
                char *rest = strchr(entries[k].path, '/') + 1;
                strncpy(sub[k - i].path, rest, sizeof(sub[k-i].path) - 1);
                sub[k - i].path[sizeof(sub[k-i].path) - 1] = '\0';
            }

            // Recurse into subdirectory
            ObjectID sub_id;
            if (write_tree_level(sub, j - i, depth + 1, &sub_id) < 0) {
                free(sub);
                return -1;
            }
            free(sub);

            // Add subtree entry
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            strncpy(te->name, dirname, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            te->hash = sub_id;

            i = j;
        }
    }

    // Serialize and write tree object
    void *data;
    size_t len;
    if (tree_serialize(&tree, &data, &len) < 0) return -1;
    int ret = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return ret;
}

int tree_from_index(ObjectID *id_out) {
    Index idx;
    if (index_load(&idx) < 0) return -1;
    if (idx.count == 0) {
        // Empty tree
        Tree empty;
        empty.count = 0;
        void *data;
        size_t len;
        if (tree_serialize(&empty, &data, &len) < 0) return -1;
        int ret = object_write(OBJ_TREE, data, len, id_out);
        free(data);
        return ret;
    }
    return write_tree_level(idx.entries, idx.count, 0, id_out);
}