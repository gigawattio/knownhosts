# knownhosts

[![Documentation](https://godoc.org/github.com/gigawattio/knownhosts?status.svg)](https://godoc.org/github.com/gigawattio/knownhosts)
[![Build Status](https://travis-ci.org/gigawattio/knownhosts.svg?branch=master)](https://travis-ci.org/gigawattio/knownhosts)
[![Report Card](https://goreportcard.com/badge/github.com/gigawattio/knownhosts)](https://goreportcard.com/report/github.com/gigawattio/knownhosts)

### About

[gigawatt.io/knownhosts](https://gigawatt.io/knownhosts) is a golang package for programmatically parsing, querying and manipulating [SSH known_hosts files](http://man.openbsd.org/sshd.8) (usually located under `~/.ssh/known_hosts`).

This package provides functionality beyond the go stdlib [crypto/ssh/knownhosts](https://github.com/golang/crypto/tree/master/ssh/knownhosts), which doesn't expose much of practical use for known_hosts file management.

There are many possible (ab)use-cases for this library, so before importing it's recommended you review the [Security Considerations](#security-considerations) section below and think critically about the possible implications for your implementation.

Created by [Jay Taylor](https://jaytaylor.com/).

### Security Considerations

Programmatic addition of entries to ~/.ssh/known_hosts can be risky due to the potential for exposing [MITM attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) vulnerabilities in your application.  It is critical to account for this aspect in your design before importing this go package.

#### Further Reading

* [Can I automatically add a new host to known_hosts?](https://serverfault.com/questions/132970/can-i-automatically-add-a-new-host-to-known-hosts)
* [Non interactive git clone (ssh fingerprint prompt)](https://serverfault.com/a/701637)

### Usage

```go
package main

import (
    "fmt"

    "gigawatt.io/knownhosts"
)

func main() {
    khs, err := knownhosts.New("/tmp/test_known_tests")
    if err != nil {
        panic(err)
    }

    if _, err := khs.Add("github.com", "gitlab.com"); err != nil {
        panic(err)
    }

    fmt.Printf("khs.String() =>\n---\n%v\n---\n", khs.String())

    if err := khs.Sync(); err != nil {
        panic(err)
    }

    gh := khs.FindByAddr("ssh-rsa", "github.com")
    fmt.Printf("github.com query result: %# v\n", gh)

    gl := khs.FindByAddr("ssh-rsa", "gitlab.com")
    fmt.Printf("gitlab.com query result: %# v\n", gl)
}
```

Also see [the examples in the docs](https://godoc.org/github.com/gigawattio/knownhosts#pkg-examples).

### Motivation

This started with a requirement to clone git repositories non-interactively.  This gets around interactive SSH authentication prompts by always ensuring there is a known_hosts entry for each git host before initiating a clone.

```shell
Cloning into 'target'...
The authenticity of host 'gitlab.com (35.231.145.151)' can't be established.
ECDSA key fingerprint is f1:d0:fb:46:73:7a:70:92:5a:ab:5d:ef:43:e2:1c:35.
Are you sure you want to continue connecting (yes/no)?
```

```shell
The authenticity of host '[madmax.utwente.nl]:62222 ([4.3.2.1]:62222)' can't be established.
RSA key fingerprint is SHA256:USgS2JZsu19qqQQf16TomcatUPdogQuicksilvaAUSS.
RSA key fingerprint is MD5:8a:b9:db:ca:40:fe:32:ba:00:be:ef:04:ac:bd:9b:a8.
Are you sure you want to continue connecting (yes/no)?
```

### Requirements

* Go version 1.9 or newer

### Running the test suite

    go test ./...

#### License

Permissive MIT license, see the [LICENSE](LICENSE) file for more information.
