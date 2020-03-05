# Golang IOC Library

[![Go Report Card](https://goreportcard.com/badge/github.com/vertoforce/go-ioc)](https://goreportcard.com/report/github.com/vertoforce/go-ioc)
[![Documentation](https://godoc.org/github.com/vertoforce/go-ioc?status.svg)](https://godoc.org/github.com/vertoforce/go-ioc)

This library provides functions to extract IOCs from text or a reader.  You can also fang and defang IOCs

## Usage

### GetIOCs

```go
data := `this is a bad url http[://]google[.]com/path`
iocs := GetIOCs(data, false, true)
```

### Defang / Fang

```go
    ioc := &IOC{IOC: "google.com", Type: Domain}
    ioc = ioc.Defang()
    fmt.Println(ioc)
    ioc = ioc.Fang()
    fmt.Println(ioc)

    // Output: google[.]com|Domain
    // google.com|Domain
```

## How

The finding IOCs in readers uses these two libraries:

- [multiregex](https://github.com/vertoforce/multiregex)
- [streamregex](https://github.com/vertoforce/streamregex)

## IOC Methods

- String() string
- Defang() *IOC
- Fang() *IOC
- IsFanged() bool
