package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestHelperAtomicWriteReplacesFileAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	if err := helperAtomicWrite(path, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := helperAtomicWrite(path, []byte("two"), 0644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "two" {
		t.Errorf("content = %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestHelperAtomicWriteRefusesSymlinksAndDirectories(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	os.WriteFile(target, []byte("keep"), 0600)
	link := filepath.Join(dir, "link.conf")
	os.Symlink(target, link)
	if err := helperAtomicWrite(link, []byte("x"), 0600); err == nil {
		t.Error("a symlink at the target must be refused")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the symlink target was modified: %q", b)
	}
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0755)
	if err := helperAtomicWrite(sub, []byte("x"), 0600); err == nil {
		t.Error("a directory at the target must be refused")
	}
}

// A reader must only ever see one complete version, never a truncated or mixed file.
func TestHelperAtomicWriteIsNeverSeenHalfWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "frr.conf")
	a := bytes.Repeat([]byte("A"), 256<<10)
	b := bytes.Repeat([]byte("B"), 256<<10)
	if err := helperAtomicWrite(path, a, 0600); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < 150; i++ {
			next := a
			if i%2 == 0 {
				next = b
			}
			if err := helperAtomicWrite(path, next, 0600); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	reads := 0
	for {
		select {
		case <-done:
			wg.Wait()
			if reads == 0 {
				t.Fatal("reader never ran")
			}
			return
		default:
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("file vanished during replacement: %v", err)
			}
			if !bytes.Equal(got, a) && !bytes.Equal(got, b) {
				t.Fatalf("saw a partial or mixed file (%d bytes)", len(got))
			}
			reads++
		}
	}
}
