package download

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	Client = &MockClient{}
	ret := m.Run()
	os.Exit(ret)
}
