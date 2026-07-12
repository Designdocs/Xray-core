package artx

import "testing"

func TestAccountRejectsBlankPSK(t *testing.T) {
	for _, psk := range []string{"", " ", "\t\r\n"} {
		if _, err := (&Account{Psk: psk}).AsAccount(); err == nil {
			t.Fatalf("blank PSK %q accepted", psk)
		}
	}

	account, err := (&Account{Psk: "artx-psk"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if account.(*MemoryAccount).PSK != "artx-psk" {
		t.Fatalf("converted PSK = %q", account.(*MemoryAccount).PSK)
	}
}
