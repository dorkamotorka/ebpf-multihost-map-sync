package main

import (
	"strings"
	"strconv"
)

const BPF_NAME_LEN = 16
const MAX_KEY_SIZE = 64
const MAX_VALUE_SIZE = 280

type MapUpdater int32
const (
	UPDATER_USERMODE MapUpdater = iota
	UPDATER_SYSCALL_GET
	UPDATER_SYSCALL_UPDATE
	UPDATER_SYSCALL_DELETE
	UPDATER_KERNEL_UPDATE
	UPDATER_KERNEL_DELETE
)

const (
	USERMODE = "USERMODE"
	USER_GET = "GET"
	USER_UPDATE = "UPDATE"
	USER_DELETE = "DELETE"
	KERNEL_UPDATE = "KERNEL_UPDATE"
	KERNEL_DELETE = "KERNEL_DELETE"
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
	case UPDATER_USERMODE:
		return USERMODE
	case UPDATER_SYSCALL_GET:
		return USER_GET
	case UPDATER_SYSCALL_UPDATE:
		return USER_UPDATE
	case UPDATER_SYSCALL_DELETE:
		return USER_DELETE
	case UPDATER_KERNEL_UPDATE:
		return KERNEL_UPDATE
	case UPDATER_KERNEL_DELETE:
		return KERNEL_DELETE
	default:
		return "Unknown"
	}
}

type EventValue interface{}
func ConvertValueToString(value EventValue) string {
	switch v := value.(type) {
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case []EventValue:
		strArray := make([]string, len(v))
		for i, elem := range v {
			strArray[i] = ConvertValueToString(elem)
		}
		return strings.Join(strArray, " ")
	default:
		return "Unknown"
	}
}