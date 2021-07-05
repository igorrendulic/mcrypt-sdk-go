package mcrypt

import (
	"fmt"
	"testing"
)

const (
	testPath = "/Users/igor/workspace/configfiles/dev.mailio.rendulic.me/igortest4-dtable-servicekeys.json"
)

func TestLoadConfig(t *testing.T) {
	mcrypt := NewMCrypt(testPath)
	fmt.Printf("mcrypt: %v\n", mcrypt)
}
