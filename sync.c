//go:build ignore
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"
#include "sync.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} map_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 10240);
} hash_map SEC(".maps");

#define MEM_READ(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

static void __always_inline
log_map_update(struct bpf_map* updated_map, unsigned int *pKey, unsigned int *pValue, enum map_updater update_type)
{ 
  // Get basic info about the map
  uint32_t map_id = MEM_READ(updated_map->id);
  uint32_t key_size = MEM_READ(updated_map->key_size);
  uint32_t value_size = MEM_READ(updated_map->value_size);
 
  // memset the whole struct to ensure verifier is happy
  struct MapData out_data;
  __builtin_memset(&out_data, 0, sizeof(out_data));

  bpf_probe_read_str(out_data.name, BPF_NAME_LEN, updated_map->name);
  bpf_probe_read(&out_data.key, sizeof(*pKey), pKey);
  out_data.key_size = key_size;
  if (pValue != 0) {
    bpf_probe_read(&out_data.value, sizeof(*pValue), pValue);
    out_data.value_size = value_size;
  }
  out_data.map_id = map_id;
  out_data.pid = (unsigned int)(bpf_get_current_pid_tgid() >> 32);
  out_data.update_type = update_type;

  // Write data to be processed in userspace
  bpf_ringbuf_output(&map_events, &out_data, sizeof(out_data), 0);
}

SEC("fentry/htab_map_update_elem")
int BPF_PROG(bpf_prog_kern_hmapupdate, struct bpf_map *map, void *key, void *value, u64 map_flags) {
  bpf_printk("htab_map_update_elem\n");

  log_map_update(map, key, value, MAP_UPDATE);
  return 0;
}

SEC("fentry/htab_map_delete_elem")
int BPF_PROG(bpf_prog_kern_hmapdelete, struct bpf_map *map, void *key) {
  bpf_printk("htab_map_delete_elem\n");

  log_map_update(map, key, 0, MAP_DELETE);
  return 0;
}