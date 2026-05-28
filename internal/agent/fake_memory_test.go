package agent

import (
	"fmt"

	"github.com/diffsec/quokka/internal/memory"
)

// fakeMemoryReader satisfies MemoryReader from a plain map keyed by name.
// Tests in this package use it in place of the gone-away yaml-backed
// memory.Store.
type fakeMemoryReader struct {
	items map[string]*memory.Memory
}

func newFakeMemory() *fakeMemoryReader {
	return &fakeMemoryReader{items: map[string]*memory.Memory{}}
}

func (f *fakeMemoryReader) put(m *memory.Memory) {
	if f.items == nil {
		f.items = map[string]*memory.Memory{}
	}
	f.items[m.Name] = m
}

func (f *fakeMemoryReader) ReadByName(name string) (*memory.Memory, error) {
	m, ok := f.items[name]
	if !ok {
		return nil, fmt.Errorf("memory %q not found", name)
	}
	return m, nil
}
