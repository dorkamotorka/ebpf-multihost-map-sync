package main

import (
	"strings"
	"strconv"
)

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