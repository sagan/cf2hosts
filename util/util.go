package util

import (
	"fmt"
	"strconv"
)

func ToString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func ToInt(v any) int {
	if v == nil {
		return 0
	}
	switch value := v.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		i, err := strconv.Atoi(ToString(v))
		if err != nil {
			return 0
		}
		return i
	}
}
