package utils

import (
	"fmt"
	"strconv"
	"time"
)

func ToString(i interface{}) (string, error) {

	switch s := i.(type) {
	case string:
		return s, nil
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32), nil
	case int:
		return strconv.Itoa(s), nil
	case int64:
		return strconv.FormatInt(s, 10), nil
	case int32:
		return strconv.Itoa(int(s)), nil
	case int16:
		return strconv.FormatInt(int64(s), 10), nil
	case int8:
		return strconv.FormatInt(int64(s), 10), nil
	case uint:
		return strconv.FormatInt(int64(s), 10), nil
	case uint64:
		return strconv.FormatInt(int64(s), 10), nil
	case uint32:
		return strconv.FormatInt(int64(s), 10), nil
	case uint16:
		return strconv.FormatInt(int64(s), 10), nil
	case uint8:
		return strconv.FormatInt(int64(s), 10), nil
	case []byte:
		return string(s), nil
	case nil:
		return "", fmt.Errorf("empty value")
	case time.Time:
		return strconv.FormatInt(s.UnixNano(), 10), nil
	default:
		return "", fmt.Errorf("unsupported value %#v of type %T", i, i)
	}
}
