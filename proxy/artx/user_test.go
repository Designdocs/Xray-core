package artx

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestArtXUserManagerRejectsLocatorCollisions(t *testing.T) {
	server := &Server{}
	first := artxMemoryUser("first@example.com", "shared-psk")
	second := artxMemoryUser("second@example.com", "shared-psk")

	if err := server.AddUser(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := server.AddUser(context.Background(), second); err == nil {
		t.Fatal("accepted two users with the same locator")
	}
}

func TestArtXUserManagerRejectsBlankPSK(t *testing.T) {
	server := &Server{}
	if err := server.AddUser(context.Background(), artxMemoryUser("blank@example.com", " \t\n")); err == nil {
		t.Fatal("accepted a blank PSK")
	}
}

func TestArtXUserManagerAddGetRemove(t *testing.T) {
	ctx := context.Background()
	server := &Server{}
	user := artxMemoryUser("user@example.com", "secret")

	if err := server.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if got := server.GetUser(ctx, user.Email); got != user {
		t.Fatalf("GetUser() = %p, want %p", got, user)
	}
	if got := server.GetUsersCount(ctx); got != 1 {
		t.Fatalf("GetUsersCount() = %d", got)
	}
	if users := server.GetUsers(ctx); len(users) != 1 || users[0] != user {
		t.Fatalf("GetUsers() = %#v", users)
	}
	if err := server.RemoveUser(ctx, user.Email); err != nil {
		t.Fatal(err)
	}
	if got := server.GetUser(ctx, user.Email); got != nil {
		t.Fatalf("removed user still present: %#v", got)
	}
}

func artxMemoryUser(email, psk string) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: email, Account: &MemoryAccount{PSK: psk}}
}
