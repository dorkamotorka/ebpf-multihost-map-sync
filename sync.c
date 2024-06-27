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
    __type(key, int); // pid_tgid
    __type(value, int);
    __uint(max_entries, 10240);
} hash_map SEC(".maps");

#define MEM_READ(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

static void __always_inline
log_map_update(struct bpf_map* updated_map, char *pKey, char *pValue, enum map_updater update_type)
{ 
  // Get basic info about the map
  uint32_t map_id = MEM_READ(updated_map->id);
  uint32_t key_size = MEM_READ(updated_map->key_size);
  uint32_t value_size = MEM_READ(updated_map->value_size);
  char filter[] = { 'c', 't', '_', 'm', 'a', 'p', '\0'};
  int i;
 
  // Read the key and value into byte arrays
  // memset the whole struct to ensure verifier is happy
  struct MapData out_data;
  __builtin_memset(&out_data, 0, sizeof(out_data));

  // Parse the map name
  bpf_probe_read_str(out_data.name, BPF_NAME_LEN, updated_map->name);
  bpf_printk("here1\n");

/* #pragma unroll
  for (i = 0 ; i < sizeof(filter); i++) {
    if (out_data.name[i] != filter[i]) {
      return;
    }
  } */

  bpf_printk("here2\n");
  // Set basic data
  out_data.key_size = key_size;
  out_data.value_size = value_size;
  out_data.map_id = map_id;
  out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
  out_data.updater = update_type;

  
  // Parse the Key
  if (pKey) {
    if (key_size <= MAX_KEY_SIZE) {
      bpf_probe_read(out_data.key, key_size, pKey);
      out_data.key_size = key_size;
    } else {
      bpf_probe_read(out_data.key, MAX_KEY_SIZE, pKey);
      out_data.key_size = MAX_KEY_SIZE;
    }
  } else {
    out_data.key_size = 0;
  }

  // Parse the Value
  if (pValue) {
    if (value_size <= MAX_VALUE_SIZE) {
      bpf_probe_read(out_data.value, value_size, pValue);
      out_data.value_size = value_size;
    } else {
      bpf_probe_read(out_data.value, MAX_VALUE_SIZE, pValue);
      out_data.value_size = MAX_VALUE_SIZE;
    }
  } else {
    out_data.value_size = 0;
  }

  // Write data to be processed in userspace
  bpf_ringbuf_output(&map_events, &out_data, sizeof(out_data), 0);
}

SEC("fentry/htab_map_update_elem")
int BPF_PROG(bpf_prog_kern_hmapupdate, struct bpf_map *map, void *key, void *value, u64 map_flags) {
  bpf_printk("htab_map_update_elem\n");

  log_map_update(map, key, value, UPDATER_KERNEL_UPDATE);
  return 0;
}

SEC("fentry/htab_map_delete_elem")
int BPF_PROG(bpf_prog_kern_hmapdelete, struct bpf_map *map, void *key, void *value, u64 map_flags) {
  bpf_printk("htab_map_delete_elem\n");

  //log_map_update(map, key, value, UPDATER_KERNEL_DELETE);
  return 0;
}


SEC("tp/syscalls/sys_enter_bpf")
int bpf_prog_syscall(struct syscall_bpf_args *args) {
  //bpf_printk("sys_enter_bpf\n");
  if (args->cmd == BPF_MAP_GET_FD_BY_ID) {
      //bpf_printk("BPF_MAP_GET_FD_BY_ID\n");
      // Get The Map ID
      unsigned int map_id = 0;
      bpf_probe_read(&map_id, sizeof(map_id), &args->uattr->map_id);

      // memset the whole struct to ensure verifier is happy
      struct MapData out_data;
      __builtin_memset(&out_data, 0, sizeof(out_data));
      
      out_data.map_id = map_id;
      out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
      out_data.updater = UPDATER_SYSCALL_GET;
      // We don't know any key or value size, as we are just getting a handle
      out_data.key_size = 0;
      out_data.value_size = 0;

      // Write data to perf event
/*       int ret = bpf_ringbuf_output(&map_events, &out_data, sizeof(out_data), 0);
      if (ret != 0) {
        bpf_printk("Error writing to ringbuf\n");
				return 0;
			} */
  } else if (args->cmd == BPF_MAP_UPDATE_ELEM) {
      //bpf_printk("BPF_MAP_UPDATE_ELEM\n");
      unsigned int map_id = 0;
      bpf_probe_read(&map_id, sizeof(map_id), &args->uattr->map_id);
      
      // memset the whole struct to ensure verifier is happy
      struct MapData out_data;
      __builtin_memset(&out_data, 0, sizeof(out_data));

      out_data.map_id = map_id;
      out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
      out_data.updater = UPDATER_SYSCALL_UPDATE;
      // We don't know any key or value size, as we are just getting a handle
      out_data.key_size = 0;
      out_data.value_size = 0;
      
      // Write data to perf event
/*       int ret = bpf_ringbuf_output(&map_events, &out_data, sizeof(out_data), 0);
      if (ret != 0) {
        bpf_printk("Error writing to ringbuf\n");
				return 0;
			} */
      // Dummy way of testing whether the syscalls above get called
/*       int key = 1111;
      int value = 2222;
      bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY); */
  } else if (args->cmd == BPF_MAP_DELETE_ELEM) {
      //bpf_printk("BPF_MAP_DELETE_ELEM\n");
      unsigned int map_id = 0;
      bpf_probe_read(&map_id, sizeof(map_id), &args->uattr->map_id);
      
      // memset the whole struct to ensure verifier is happy
      struct MapData out_data;
      __builtin_memset(&out_data, 0, sizeof(out_data));

      out_data.map_id = map_id;
      out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
      out_data.updater = UPDATER_SYSCALL_DELETE;
      // We don't know any key or value size, as we are just getting a handle
      out_data.key_size = 0;
      out_data.value_size = 0;
      
      // Write data to perf event
 /*      int ret = bpf_ringbuf_output(&map_events, &out_data, sizeof(out_data), 0);
      if (ret != 0) {
        bpf_printk("Error writing to ringbuf\n");
				return 0;
			} */
      // Dummy way of testing whether the syscalls above get called
/*       int key = 1111;
      bpf_map_delete_elem(&hash_map, &key); */
  }
  return 0;
}