package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sync sync.c

import (
	"log"
	"unsafe"
	"sync"
	"context"
	"net"
	"time"
	"flag"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Node struct {
	UnimplementedSyncServiceServer
	value int32
	key  int32
	_type  int32
	mapid  int32
	mu    sync.Mutex
}

func (n *Node) SetValue(ctx context.Context, in *ValueRequest) (*Empty, error) {
	n.mu.Lock()
	n.value = in.GetValue()
	n.key = in.GetKey()
	n._type = in.GetType()
	n.mapid = in.GetMapid()
	log.Printf("Client %s key %d to value %d on eBPF Map %d", MapUpdater(n._type).String(), n.key, n.value, n.mapid)
	n.mu.Unlock()

	return &Empty{}, nil
}

func startServer(node *Node, port string) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	RegisterSyncServiceServer(s, node)

	log.Printf("Server is running at %s", port)
	if err := s.Serve(l); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	serverIP := flag.String("ip", "localhost", "Server IP address")
	serverPort := flag.String("port", "50051", "Server port")
	flag.Parse()
	address := *serverIP + ":" + *serverPort

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

	rd, err := ringbuf.NewReader(syncObjs.MapEvents)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	go startServer(&Node{}, ":50051")

	for {
		record, err := rd.Read()
		if err != nil {
			panic(err)
		}

		Event := (*MapData)(unsafe.Pointer(&record.RawSample[0]))
		log.Printf("Map ID: %d", Event.MapID)
		log.Printf("Name: %s", string(Event.Name[:]))
		log.Printf("PID: %d", Event.PID)
		log.Printf("Update Type: %s", Event.UpdateType.String())
		log.Printf("Key: %d", Event.Key)
		log.Printf("Key Size: %d", Event.KeySize)
		log.Printf("Value: %d", Event.Value)
		log.Printf("Value Size: %d", Event.ValueSize)
		log.Println("=====================================")

		conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("Did not connect: %v", err)
			continue
		}

		client := NewSyncServiceClient(conn)

		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		_, err = client.SetValue(ctx, &ValueRequest{Key: int32(Event.Key), Value: int32(Event.Value), Type: int32(Event.UpdateType), Mapid: int32(Event.MapID)})
		if err != nil {
			log.Printf("Could not set value: %v", err)
		} else {
			log.Printf("Successfully send sync message")
		}
	}
}