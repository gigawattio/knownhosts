// Package knownhosts supports programmatic parsing, querying and
// manipulation of SSH known_hosts files.
package knownhosts

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gigawatt.io/concurrency"
	"gigawatt.io/oslib"
	"github.com/Eun/sshkeys"
	"golang.org/x/crypto/ssh"
)

var (
	DefaultKnownHostsTimeout = 10 * time.Second
	DefaultKnownHostsPath    = filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")

	knownHostAddrExpr = regexp.MustCompile(`^\[([^\]]+)\](?::([0-9]+))$`)

	ErrKeyChanged = errors.New("security violation: unexpected public key change detected")
)

type KnownHosts struct {
	FilePath string
	Items    []*KnownHost
}

type KnownHost struct {
	Addrs     []string
	KeyType   string
	PublicKey string
}

// New creates a new instance of KnownHosts.  If f is empty, then
// DefaultKnownHostsPath will be used.
func New(f string) (*KnownHosts, error) {
	khs := &KnownHosts{
		FilePath: f,
		Items:    []*KnownHost{},
	}

	if err := khs.init(); err != nil {
		return nil, err
	}
	if err := khs.Parse(); err != nil {
		return nil, err
	}
	return khs, nil
}

func (khs *KnownHosts) init() error {
	if khs.FilePath == "" {
		khs.FilePath = DefaultKnownHostsPath
	}
	if err := initProtectedFile(khs.FilePath); err != nil {
		return err
	}
	return nil
}

// Parse refreshes and parses the known hosts data from disk.
func (khs *KnownHosts) Parse() error {
	f, err := os.OpenFile(khs.FilePath, os.O_RDONLY, os.FileMode(int(0600)))
	if err != nil {
		return err
	}
	defer f.Close()

	parseHosts := func(s string) []string {
		hosts := []string{}
		for _, h := range strings.Split(s, ",") {
			h = knownHostAddrExpr.ReplaceAllString(h, "$1:$2")
			hosts = append(hosts, h)
		}
		return hosts
	}

	newItems := []*KnownHost{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		pieces := strings.SplitN(s.Text(), " ", 3)
		if len(pieces) != 3 {
			// Skip malformed lines.
			continue
		}

		// Parse hosts and IPs.
		kh := &KnownHost{
			Addrs:     parseHosts(pieces[0]),
			KeyType:   pieces[1],
			PublicKey: pieces[2],
		}
		newItems = append(newItems, kh)
	}

	khs.Items = newItems

	return nil
}

// Add resolves and adds a new set of known hosts, then renders to disk.
// There are obvious security considerations and implications here, since
// automatically adding to known_hosts can be MITM'd.
//
// Returns bool indicating if any state was changed, and any encountered error.
//
// Automatically merges records for different addresses sharing the same key.
func (khs *KnownHosts) Add(addrs ...string) (bool, error) {
	var (
		mu      = sync.Mutex{}
		funcs   = []func() error{}
		changed bool
	)

	addrs = uniqStrings(addrs)
	sort.Strings(addrs)

	for _, addr := range addrs {
		func(addr string) {
			funcs = append(funcs, func() error {
				dialAddr := addr
				if !strings.Contains(dialAddr, ":") {
					dialAddr += ":22"
				}
				keys, err := sshkeys.GetKeys(dialAddr, DefaultKnownHostsTimeout)
				if err != nil {
					return err
				}
				mu.Lock()
				defer mu.Unlock()
				for _, key := range keys {
					var (
						authorizedKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
						publicKey     = strings.SplitN(authorizedKey, " ", 2)[1]
					)

					keySearch := khs.FindByKey(key.Type(), publicKey)
					addrSearch := khs.FindByAddr(key.Type(), addr)

					if keySearch != nil && addrSearch != nil {
						// Addr and matching key entry found, everything checks out.
						continue
					} else if addrSearch != nil {
						if addrSearch.PublicKey != publicKey {
							return fmt.Errorf("%s for addr=%v", ErrKeyChanged, addr)
						}
					} else if keySearch != nil {
						keySearch.Addrs = append(keySearch.Addrs, addr)
						changed = true
					} else {
						kh := &KnownHost{
							Addrs:     []string{addr},
							KeyType:   key.Type(),
							PublicKey: publicKey,
						}
						khs.Items = append(khs.Items, kh)
						changed = true
					}
				}

				return nil
			})
		}(addr)
	}

	if err := concurrency.MultiGo(funcs...); err != nil {
		return changed, err
	}

	return changed, nil
}

// FindByAddr returns nil if no corresponding addr:port entry is found.
func (khs *KnownHosts) FindByAddr(keyType string, addr string) *KnownHost {
	for _, kh := range khs.Items {
		if kh.KeyType == keyType && kh.HasAddress(addr) {
			return kh
		}
	}
	return nil
}

// FindByKey returns nil if no corresponding key type and value entry is found.
func (khs *KnownHosts) FindByKey(keyType string, publicKey string) *KnownHost {
	for _, kh := range khs.Items {
		if kh.KeyType == keyType && kh.PublicKey == publicKey {
			return kh
		}
	}
	return nil
}

func (khs *KnownHosts) Len() int {
	return len(khs.Items)
}

// String transforms the current state known hosts into a string representation.
func (khs *KnownHosts) String() string {
	buf := &bytes.Buffer{}
	for _, kh := range khs.Items {
		buf.WriteString(kh.String())
		buf.WriteByte('\n')
	}
	return buf.String()
}

// Sync renders the current state to disk.
func (khs *KnownHosts) Sync() error {
	// Write the temporary file under the same directory as the destination to
	// avoid errors in linux / unix like:
	//
	//     panic: rename [temp location] [dest]: invalid cross-device link
	//
	// when renaming the temp file to the final destination.
	//
	// This occurs on *nix when the temp partition is different from that of
	// the destination known_hosts file.
	//
	// See also: https://groups.google.com/forum/#!topic/golang-dev/5w7Jmg_iCJQ
	f, err := ioutil.TempFile(oslib.PathDirName(khs.FilePath), "."+oslib.PathBaseName(khs.FilePath))
	if err != nil {
		return err
	}
	if _, err := f.WriteString(khs.String()); err != nil {
		f.Close()
		return err
	}
	f.Close()

	if err := os.Chmod(f.Name(), os.FileMode(int(0600))); err != nil {
		return fmt.Errorf("chmod'ing %q: %s", f.Name(), err)
	}
	if err := os.Rename(f.Name(), khs.FilePath); err != nil {
		return fmt.Errorf("renaming %q to %q: %s", f.Name(), khs.FilePath, err)
	}
	return nil
}

// String turns the known host information into a known_hosts file formatted
// entry.
func (kh KnownHost) String() string {
	line := &bytes.Buffer{}
	for _, a := range kh.Addrs {
		if line.Len() > 0 {
			line.WriteByte(',')
		}
		if strings.Contains(a, ":") {
			pieces := strings.SplitN(a, ":", 2)
			line.WriteString(fmt.Sprintf("[%v]:%v", pieces[0], pieces[1]))
		} else {
			line.WriteString(a)
		}
	}
	line.WriteString(fmt.Sprintf(" %v %v", kh.KeyType, kh.PublicKey))
	return line.String()
}

// HasAddress returns true if the specified addr or addr:port is contained.
func (kh KnownHost) HasAddress(addr string) bool {
	for _, a := range kh.Addrs {
		if a == addr || kh.checkHashed(a, addr) {
			return true
		}
	}
	return false
}

// checkHashed checks if an address spec matches a hashed address value.
func (_ KnownHost) checkHashed(hashed string, addr string) bool {
	if strings.HasPrefix(hashed, "|") {
		if pieces := strings.SplitN(hashed, "|", 4); len(pieces) == 4 {
			var (
				shaVersion = pieces[1]
				salt       = pieces[2]
				hash       = pieces[3]
			)
			if shaVersion == "1" {
				if test, err := HashAddr(salt, addr); err == nil && test == hash {
					return true
				}
			}
		}
	}
	return false
}

// HashAddr takes a salt and host address and returns the corresponding hash
// value.
func HashAddr(salt string, addr string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write([]byte(addr)); err != nil {
		return "", err
	}
	hash := mac.Sum(nil)
	b64hash := base64.StdEncoding.EncodeToString(hash)
	return string(b64hash), err
}

// IsErrKeyChanged returns true if the error message begins with the
// ErrKeyChanged message string.
func IsErrKeyChanged(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(err.Error(), ErrKeyChanged.Error())
}

// initProtectedFile ensures the parent directory exists before creating the
// named file with permissions mode=0600.
func initProtectedFile(f string) error {
	if err := initProtectedDir(oslib.PathDirName(f)); err != nil {
		return err
	}

	if exists, err := oslib.PathExists(f); err != nil {
		return err
	} else if !exists {
		f, err := os.OpenFile(f, os.O_CREATE, os.FileMode(int(0600)))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// initProtectedDir creates direcotry with mode=0700 if it doesn't already exist.
func initProtectedDir(p string) error {
	if exists, err := oslib.PathExists(p); err != nil {
		return err
	} else if !exists {
		if err := os.MkdirAll(p, os.FileMode(int(0700))); err != nil {
			return err
		}
	}
	return nil
}
