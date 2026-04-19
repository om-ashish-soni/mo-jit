package gate

import (
	"sync"
	"testing"
)

func TestFDTableStdioPreseeded(t *testing.T) {
	tbl := NewFDTable()
	cases := []struct {
		g, h int
		name string
	}{
		{0, 0, "stdin"},
		{1, 1, "stdout"},
		{2, 2, "stderr"},
	}
	for _, tc := range cases {
		got, ok := tbl.Resolve(tc.g)
		if !ok {
			t.Errorf("%s (guest %d) not preseeded", tc.name, tc.g)
			continue
		}
		if got != tc.h {
			t.Errorf("%s (guest %d) -> host %d, want host %d", tc.name, tc.g, got, tc.h)
		}
	}
	if l := tbl.Len(); l != 3 {
		t.Errorf("initial Len = %d, want 3", l)
	}
}

func TestFDTableAllocateStartsAt3(t *testing.T) {
	tbl := NewFDTable()
	g := tbl.Allocate(100)
	if g != 3 {
		t.Errorf("first Allocate = %d, want 3", g)
	}
	if got, ok := tbl.Resolve(g); !ok || got != 100 {
		t.Errorf("Resolve(%d) = (%d, %v), want (100, true)", g, got, ok)
	}
}

func TestFDTableAllocateLowestFree(t *testing.T) {
	tbl := NewFDTable()
	a := tbl.Allocate(100) // 3
	b := tbl.Allocate(101) // 4
	c := tbl.Allocate(102) // 5
	if a != 3 || b != 4 || c != 5 {
		t.Fatalf("allocation order: got %d,%d,%d; want 3,4,5", a, b, c)
	}

	// Close the middle one — next Allocate must reclaim fd 4.
	if _, ok := tbl.Close(b); !ok {
		t.Fatalf("Close(%d) failed", b)
	}
	d := tbl.Allocate(103)
	if d != 4 {
		t.Errorf("post-close Allocate = %d, want 4 (lowest free)", d)
	}
}

func TestFDTableResolveClosedIsFalse(t *testing.T) {
	tbl := NewFDTable()
	g := tbl.Allocate(100)
	if _, ok := tbl.Close(g); !ok {
		t.Fatalf("Close(%d) failed", g)
	}
	if _, ok := tbl.Resolve(g); ok {
		t.Errorf("Resolve(%d) after Close returned ok=true", g)
	}
}

func TestFDTableCloseUnknownIsFalse(t *testing.T) {
	tbl := NewFDTable()
	if _, ok := tbl.Close(999); ok {
		t.Errorf("Close(999) on empty table returned ok=true")
	}
}

func TestFDTableCloseStdio(t *testing.T) {
	// The gate allows closing stdio — userspace may want to
	// reopen 0/1/2 onto pipes. Just make sure the entry goes away.
	tbl := NewFDTable()
	if _, ok := tbl.Close(1); !ok {
		t.Fatal("Close(1) should succeed on preseeded table")
	}
	if _, ok := tbl.Resolve(1); ok {
		t.Errorf("Resolve(1) after Close returned ok=true")
	}
	// Reallocation must reclaim fd 1 as the lowest free slot.
	g := tbl.Allocate(42)
	if g != 1 {
		t.Errorf("after Close(1), Allocate = %d, want 1", g)
	}
}

func TestFDTableConcurrentAllocateClose(t *testing.T) {
	tbl := NewFDTable()
	const N = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			g := tbl.Allocate(i)
			tbl.Close(g)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			_, _ = tbl.Resolve(1)
		}
	}()
	wg.Wait()
}

func TestDispatcherHasPreseededFDTable(t *testing.T) {
	d := NewDispatcher(Policy{LowerDir: "/tmp/lower"})
	if d.FDs == nil {
		t.Fatal("NewDispatcher left FDs nil")
	}
	if _, ok := d.FDs.Resolve(0); !ok {
		t.Error("stdin not preseeded in Dispatcher.FDs")
	}
}
