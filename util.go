package main

const BPF_NAME_LEN = 16
const MAX_KEY_SIZE = 64
const MAX_VALUE_SIZE = 280

// Order matters!
type MapUpdater int32
const (
	MAP_UPDATE MapUpdater = iota
	MAP_DELETE
)

const (
	UPDATE = "UPDATE"
	DELETE = "DELETE"
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

func (e MapUpdater) String() string {
	switch e {
	case MAP_UPDATE:
		return UPDATE
	case MAP_DELETE:
		return DELETE
	default:
		return "UNKNOWN"
	}
}