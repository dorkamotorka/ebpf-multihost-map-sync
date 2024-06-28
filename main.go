package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type Config sync sync.c

import (
	"os"
	"context"
	"flag"
	"log"
	"net"
	"time"
	"unsafe"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Node struct {
	UnimplementedSyncServiceServer
	syncObjs syncObjects
}

func (n *Node) SetValue(ctx context.Context, in *ValueRequest) (*Empty, error) {
	value := in.GetValue()
	key := in.GetKey()
	_type := in.GetType()
	
	// According to https://man7.org/linux/man-pages/man2/bpf.2.html, these calls are atomic!
	if MapUpdater(_type).String() == "UPDATE" {
		n.syncObjs.HashMap.Update(key, value, ebpf.UpdateAny)
		log.Printf("Client updated key %d to value %d", key, value)
	} else if MapUpdater(_type).String() == "DELETE" {
		n.syncObjs.HashMap.Delete(key)
		log.Printf("Client deleted key %d", key)
	}

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
	serverIP := flag.String("ip", "localhost", "Server IP address of the peer (to sync to)")
	serverPort := flag.Int("port", 50051, "Current host listen port")
	flag.Parse()
	address := *serverIP + ":" + fmt.Sprint(*serverPort)

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

	// Update the config map with the server's port and PID.
	// This is compulsory to prevent the server from sending map updates to itself.
	// NOTE: this also prevents each server to log eBPF map updates done by the same process that loaded them.
	var key uint32 = 0
	config := syncConfig{
		HostPort: uint16(*serverPort),
		HostPid: uint64(os.Getpid()),
	}
	err = syncObjs.syncMaps.MapConfig.Update(&key, &config, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to update the map: %v", err)
	}

	// Spawn the gRPC server to listen for eBPF map updates from neighbours.
	go startServer(&Node{syncObjs: syncObjs}, ":" + fmt.Sprint(*serverPort))

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
		log.Printf("Map ID: %d", Event.MapID)
		log.Printf("Name: %s", string(Event.Name[:]))
		log.Printf("PID: %d", Event.PID)
		log.Printf("Update Type: %s", Event.UpdateType.String())
		log.Printf("Key: %d", Event.Key)
		log.Printf("Key Size: %d", Event.KeySize)
		log.Printf("Value: %d", Event.Value)
		log.Printf("Value Size: %d", Event.ValueSize)

		conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("Failed to connect to peer: %v", err)
			continue
		}
		client := NewSyncServiceClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)
		_, err = client.SetValue(ctx, &ValueRequest{Key: int32(Event.Key), Value: int32(Event.Value), Type: int32(Event.UpdateType), Mapid: int32(Event.MapID)})
		if err != nil {
			log.Printf("Could not set value on peer: %v", err)
		} else {
			log.Printf("Successfully send sync message")
		}
		log.Println("=====================================")
	}
}