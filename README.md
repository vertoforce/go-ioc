# Golang IOC Library

This library provides functions to extract IOCs from text or a reader.  You can also fang and defang IOCs

## Usage

GetIOCs

```go
data := `this is a bad url http[://]google[.]com/path`

iocs := GetIOCs(data, false, true)
fmt.Println(iocs)

// Output: [{google[.]com Domain} {hxxp[://]google[.]com/path URL}]
```

GetIOCsReader

```go
data := `this is a bad url http[://]google[.]com/path`

iocs := GetIOCsReader(context.Background(), strings.NewReader(data), false, true)
for ioc := range iocs {
    fmt.Println(ioc)
}

// Output: {hxxp[://]google[.]com/path URL}
// {google[.]com Domain}
```

The getting of IOCs from a reader takes use of these two libraries:

- [multiregex](https://github.com/vertoforce/multiregex)
- [streamregex](https://github.com/vertoforce/streamregex)

## IOC Methods

- String() string
- Defang() IOC
- Fang() IOC
- IsFanged() bool

### Example

```go
    ioc := IOC{IOC: "google.com", Type: Domain}
    ioc = ioc.Defang()
    fmt.Println(ioc)

    // Output: {google[.]com Domain}
```
