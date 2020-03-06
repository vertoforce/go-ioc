# Golang IOC Library

[![Go Report Card](https://goreportcard.com/badge/github.com/vertoforce/go-ioc)](https://goreportcard.com/report/github.com/vertoforce/go-ioc)
[![Documentation](https://godoc.org/github.com/vertoforce/go-ioc?status.svg)](https://godoc.org/github.com/vertoforce/go-ioc)

This library provides functions to extract IOCs from text or a reader.  You can also fang and defang IOCs.

## CLI Usage

```txt
go-ioc can be used to extract IOCs from articles, RSS feeds, and text.

Usage:
  go-ioc [command] [flags]
  go-ioc [command]

Examples:
go-ioc url https://google.com

Available Commands:
  docs        Generate docs
  help        Help about any command
  rss         Crawl a RSS feed and get all IOCs from articles in the feed
  stdin       Find IOCs from stdin
  url         Crawl a URL and print all the IOCs

Flags:
      --all                  Get all fanged IOCs.  This typically is rather noisy in that it finds _all_ links, etc
  -f, --format string        Print format for printing IOCs.  Options include: csv, table (default "csv")
  -h, --help                 help for go-ioc
  -o, --output string        Save IOCs to file
      --printFanged          Print all IOCs fanged, will override standardizeDefangs
  -s, --sort                 Sort IOCs by their type (default true)
      --standardizeDefangs   Standardize all defanged IOCs using square brackets (default true)
      --stats                Print count of each IOC found at start of output

Use "go-ioc [command] --help" for more information about a command.
```

### Docker usage

```sh
docker run -it vertoforce/go-ioc help
```

## Library Usage

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
