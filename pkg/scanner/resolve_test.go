package scanner

import "testing"

func TestSetAndGetCustomName(t *testing.T) {
	SetCustomName("192.168.1.10", "my-laptop")

	name, ok := GetCustomName("192.168.1.10")
	if !ok {
		t.Fatal("expected custom name to exist")
	}
	if name != "my-laptop" {
		t.Errorf("name = %q, want %q", name, "my-laptop")
	}
}

func TestGetCustomName_Missing(t *testing.T) {
	name, ok := GetCustomName("192.168.1.99")
	if ok {
		t.Errorf("unexpected name %q for unknown IP", name)
	}
}

func TestSetCustomName_Overwrite(t *testing.T) {
	SetCustomName("10.0.0.1", "original")
	SetCustomName("10.0.0.1", "updated")

	name, ok := GetCustomName("10.0.0.1")
	if !ok {
		t.Fatal("expected custom name to exist after overwrite")
	}
	if name != "updated" {
		t.Errorf("name = %q, want %q", name, "updated")
	}
}

func TestCustomNamesIndependent(t *testing.T) {
	SetCustomName("192.168.1.1", "alpha")
	SetCustomName("192.168.1.2", "beta")

	name1, _ := GetCustomName("192.168.1.1")
	name2, _ := GetCustomName("192.168.1.2")
	if name1 != "alpha" || name2 != "beta" {
		t.Errorf("got %q and %q, want 'alpha' and 'beta'", name1, name2)
	}
}
