package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sync sync.c

import (
	"os"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/perf"
)

const BPF_NAME_LEN = 16
const MAX_KEY_SIZE = 64
const MAX_VALUE_SIZE = 280

type MapUpdater int32
const (
	UPDATER_KERNEL MapUpdater = iota
	UPDATER_USERMODE
	UPDATER_SYSCALL_GET
	UPDATER_SYSCALL_UPDATE
	DELETE_KERNEL
)

type MapData struct {
    MapID     uint32
    Name      [BPF_NAME_LEN]byte
    Updater   MapUpdater
    PID       uint32
    KeySize   uint32
    ValueSize uint32
    Key       [MAX_KEY_SIZE]byte
    Value     [MAX_VALUE_SIZE]byte
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	syncObjs := syncObjects{}
	if err := loadSyncObjects(&syncObjs, nil); err != nil {
		log.Fatal(err)
	}
	defer syncObjs.Close()

	kpUpdate, err := link.Kprobe("htab_map_update_elem", syncObjs.BpfProgKernHmapupdate, nil)
	if err != nil {
		log.Fatalf("opening htab_map_update_elem kprobe: %s", err)
	}
	defer kpUpdate.Close()

	kpDelete, err := link.Kprobe("htab_map_delete_elem", syncObjs.BpfProgKernHmapdelete, nil)
	if err != nil {
		log.Fatalf("opening htab_map_delete_elem kprobe: %s", err)
	}
	defer kpDelete.Close()

	kpLookup, err := link.Kprobe("htab_map_lookup_and_delete_elem", syncObjs.BpfProgKernHmaplkdelete, nil)
	if err != nil {
		log.Fatalf("opening htab_map_lookup_and_delete_elem kprobe: %s", err)
	}
	defer kpLookup.Close()

	w, err := link.Tracepoint("syscalls", "sys_enter_bpf", syncObjs.BpfProgSyscall, nil)
	if err != nil {
		log.Fatal("link sys_enter_bpf tracepoint")
	}
	defer w.Close()


	EventsReader, err := perf.NewReader(syncObjs.MapEvents, int(4096)*os.Getpagesize())
	if err != nil {
		log.Fatal("error creating perf event array reader")
	}
	for {
		var record perf.Record
		err := EventsReader.ReadInto(&record)
		if err != nil {
			log.Print("error reading from perf array")
		}

		if record.LostSamples != 0 {
			log.Printf("lost event %d", record.LostSamples)
		}

		if record.RawSample == nil || len(record.RawSample) == 0 {
			log.Print("read event nil or empty")
			return
		}

		Event := (*MapData)(unsafe.Pointer(&record.RawSample[0]))
		log.Printf("%+v", Event)
		log.Printf("Map ID: %d", Event.MapID)
		log.Printf("Name: %s", ConvertValueToString(Event.Name))
		log.Printf("PID: %d", Event.PID)
		log.Printf("Updater: %d", Event.Updater)
	}
}