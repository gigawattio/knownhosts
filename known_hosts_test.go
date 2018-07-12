package knownhosts

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/gliderlabs/ssh"
)

const sampleData = `[goggles.com]:65532 ssh-ed25519 AAAA...usZKETcGA
goggles.com ssh-rsa AAAA...KUr2oK9EJ5e81
goggles.com ecdsa-sha2-nistp256 AAAA....+...=
|1|YeRBQhnHnXu8L7bZRy4tvDV1THY=|RklwZKJutNr9XWzauyx6tnYBYCM= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
`

func WriteSampleFile() (string, error) {
	f, err := ioutil.TempFile("", "known_hosts")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
		os.Chmod(f.Name(), os.FileMode(int(0600)))
	}()
	if _, err := f.WriteString(sampleData); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func TestAdd(t *testing.T) {
	filePath, err := WriteSampleFile()
	if err != nil {
		t.Fatal(err)
	}
	khs, err := New(filePath)
	if err != nil {
		t.Fatal(err)
	}

	if expected, actual := sampleData, khs.String(); actual != expected {
		t.Errorf("Expected unmodified known hosts to render identically to the sampleData input value, but instead got: %q", actual)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	srv := &ssh.Server{
		Handler: func(_ ssh.Session) {},
	}
	go func() {
		if err := srv.Serve(listener); err != nil && err != ssh.ErrServerClosed {
			t.Fatal(err)
		}
	}()
	defer func() {
		if err := srv.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	l0 := khs.Len()
	if changed, err := khs.Add(listener.Addr().String()); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Errorf("Expected changed=true but actual=%v", changed)
	}
	l1 := khs.Len()
	if delta := l1 - l0; delta != 1 {
		t.Errorf("Expected len delta of +1 but actual delta=%v", delta)
	}
	if changed, err := khs.Add(listener.Addr().String()); err != nil {
		t.Fatal(err)
	} else if changed {
		t.Errorf("Expected changed=false but actual=%v", changed)
	}
	l2 := khs.Len()
	if delta := l2 - l1; delta != 0 {
		t.Errorf("Expected len to delta of 0 but actual delta=%v", delta)
	}

	// TODO: Validate merging of matching keys, need to listen on 0.0.0.0

	// TODO: Host removal

	if err := khs.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestAddressMerge(t *testing.T) {
	filePath, err := WriteSampleFile()
	if err != nil {
		t.Fatal(err)
	}
	khs, err := New(filePath)
	if err != nil {
		t.Fatal(err)
	}

	if expected, actual := sampleData, khs.String(); actual != expected {
		t.Errorf("Expected unmodified known hosts to render identically to the sampleData input value, but instead got: %q", actual)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:")
	if err != nil {
		t.Fatal(err)
	}
	srv := &ssh.Server{
		Handler: func(_ ssh.Session) {},
	}
	go func() {
		if err := srv.Serve(listener); err != nil && err != ssh.ErrServerClosed {
			t.Fatal(err)
		}
	}()
	defer func() {
		if err := srv.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	pieces := strings.Split(listener.Addr().String(), ":")
	port := pieces[len(pieces)-1]

	if changed, err := khs.Add(listener.Addr().String()); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Errorf("Expected changed=true but actual=%v", changed)
	}

	l0 := len(khs.FindByAddr("ssh-rsa", listener.Addr().String()).Addrs)

	if changed, err := khs.Add(strings.Join([]string{"127.0.0.1", port}, ":")); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Errorf("Expected changed=true but actual=%v", changed)
	}

	l1 := len(khs.FindByAddr("ssh-rsa", listener.Addr().String()).Addrs)

	if delta := l1 - l0; delta != 1 {
		t.Errorf("Expected delta=1 but actual=%v", delta)
	}
}

func TestParseDuplicateKeys(t *testing.T) {
	f, err := ioutil.TempFile("", "known_hosts")
	if err != nil {
		t.Fatal(err)
	}

	const duplicateKeysData = `example.com ssh-rsa publickey1
192.168.1.103 ssh-rsa publickey1
127.0.0.1 ssh-rsa otherkey2
gigawatt.io ssh-rsa otherkey3`

	if _, err := f.WriteString(duplicateKeysData); err != nil {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	khs, err := New(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if expected, actual := 3, khs.Len(); actual != expected {
		t.Fatalf("Expected number of known_hosts items=%v but actual=%v", expected, actual)
	}
	if expected, actual := 2, len(khs.FindByKey("ssh-rsa", "publickey1").Addrs); actual != expected {
		t.Fatalf("Expected number of addresses=%v but actual=%v", expected, actual)
	}
}

func TestHashed(t *testing.T) {
	filePath, err := WriteSampleFile()
	if err != nil {
		t.Fatal(err)
	}
	khs, err := New(filePath)
	if err != nil {
		t.Fatal(err)
	}

	if kh := khs.FindByAddr("ssh-rsa", "github.com"); kh == nil {
		t.Errorf("Expected to find hashed entry but kh=%v", kh)
	}
}

func TestPublicKeyChangedDetection(t *testing.T) {
	filePath, err := WriteSampleFile()
	if err != nil {
		t.Fatal(err)
	}
	khs, err := New(filePath)
	if err != nil {
		t.Fatal(err)
	}

	if expected, actual := sampleData, khs.String(); actual != expected {
		t.Errorf("Expected unmodified known hosts to render identically to the sampleData input value, but instead got: %q", actual)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	srv := &ssh.Server{
		Handler: func(_ ssh.Session) {},
	}
	go func() {
		if err := srv.Serve(listener); err != nil && err != ssh.ErrServerClosed {
			t.Fatal(err)
		}
	}()
	defer func() {
		if err := srv.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	khs.Items = append(khs.Items, &KnownHost{
		Addrs:     []string{listener.Addr().String()},
		KeyType:   "ssh-rsa",
		PublicKey: "AAAAE.......z/z=",
	})

	if _, err := khs.Add(listener.Addr().String()); !IsErrKeyChanged(err) {
		t.Errorf("Expected IsErrKeyChanged(err)=true but actual result=%v", err)
	}
}

func TestKnownHostString(t *testing.T) {
	testCases := []struct {
		kh       KnownHost
		expected string
	}{
		{
			kh: KnownHost{
				Addrs:     []string{"localhost"},
				KeyType:   "ssh-rsa",
				PublicKey: "abcdefg=",
			},
			expected: "localhost ssh-rsa abcdefg=",
		},
		{
			kh: KnownHost{
				Addrs:     []string{"localhost:2222"},
				KeyType:   "ssh-rsa",
				PublicKey: "abcdefg=",
			},
			expected: "[localhost]:2222 ssh-rsa abcdefg=",
		},
	}
	for i, testCase := range testCases {
		if actual := testCase.kh.String(); actual != testCase.expected {
			t.Errorf("[i=%v] Expected string=%q but actual=%q", i, testCase.expected, actual)
		}
	}
}

func ExampleKnownHosts_Add() {
	filePath, err := WriteSampleFile()
	if err != nil {
		panic(err)
	}

	khs, err := New(filePath)
	if err != nil {
		panic(err)
	}
	if _, err := khs.Add("gitlab.com"); err != nil {
		panic(err)
	}
	if err := khs.Sync(); err != nil {
		panic(err)
	}
	bs, _ := ioutil.ReadFile(filePath)
	fmt.Println(string(bs))
}

func ExampleKnownHosts_FindByAddr() {
	filePath, err := WriteSampleFile()
	if err != nil {
		panic(err)
	}

	khs, err := New(filePath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%# v\n", khs.FindByAddr("ssh-rsa", "github.com"))
}

func ExampleKnownHosts_FindByKey() {
	filePath, err := WriteSampleFile()
	if err != nil {
		panic(err)
	}

	khs, err := New(filePath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%# v\n", khs.FindByKey("ssh-rsa", "AAAA...KUr2oK9EJ5e81"))
}
