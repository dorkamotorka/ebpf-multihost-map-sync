package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sync sync.c

import (
	"log"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func mapDemo(syncObjs *syncObjects) {
	time.Sleep(1 * time.Second)
	key := uint32(1)
	value := uint32(42)
	log.Println("--------------------")
	if err := syncObjs.HashMap.Update(key, value, ebpf.UpdateAny); err != nil {
		log.Fatalf("error updating map: %v", err)
	} else {
		log.Printf("Map entry updated")
	}
	log.Println("--------------------")
	if err := syncObjs.HashMap.Delete(key); err != nil {
		log.Fatalf("error deleting map: %v", err)
	} else {
		log.Printf("Map entry deleted")
	}
	log.Println("--------------------")
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

	fUpdate, err := link.AttachTracing(link.TracingOptions{
		Program: syncObjs.syncPrograms.BpfProgKernHmapupdate,
	})
	if err != nil {
		log.Fatalf("opening htab_map_update_elem kprobe: %s", err)
	}
	defer fUpdate.Close()

	fDelete, err := link.AttachTracing(link.TracingOptions{
		Program: syncObjs.syncPrograms.BpfProgKernHmapdelete,
	})
	if err != nil {
		log.Fatalf("opening htab_map_delete_elem kprobe: %s", err)
	}
	defer fDelete.Close()

	//go mapDemo(&syncObjs)

	rd, err := ringbuf.NewReader(syncObjs.MapEvents)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}

		Event := (*MapData)(unsafe.Pointer(&record.RawSample[0]))
		//log.Printf("%+v", Event)
		log.Printf("Map ID: %d", Event.MapID)
		log.Printf("Name: %s", ConvertValueToString(Event.Name))
		log.Printf("PID: %d", Event.PID)
		log.Printf("Updater: %s", Event.Updater.String())
		log.Println("=====================================")
	}
}