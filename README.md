# Golang IOC Library

This library provides functions to extra IOCs from text, IOCs from a reader, and defang / fang IOCs

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

