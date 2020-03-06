package ioc

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/mmcdole/gofeed"
)

// GetIOCsFromRSS Given RSS feed url, parse articles for IOCs
func GetIOCsFromRSS(ctx context.Context, url string) ([]*IOC, error) {
	fp := gofeed.NewParser()

	feed, err := fp.ParseURL(url)
	if err != nil {
		return nil, err
	}

	var iocs []*IOC

	for i := range feed.Items {
		iocsI, err := GetIOCsFromURLPage(feed.Items[i].Link)
		if err != nil {
			return nil, err
		}

		// Check if cancelled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		iocs = append(iocs, iocsI...)
	}

	return iocs, nil
}

// GetIOCsFromURLPage Given a url get IOCs from the _text_ of the page
func GetIOCsFromURLPage(url string) ([]*IOC, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyString := string(body)

	return GetIOCsFromHTML(&bodyString)
}

// GetIOCsFromHTML Takes a html page as a string and will extract the IOCs
func GetIOCsFromHTML(htmlContent *string) ([]*IOC, error) {
	if htmlContent == nil {
		return nil, errors.New("Nil string pointer")
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(*htmlContent))
	if err != nil {
		return nil, err
	}

	iocs := []*IOC{}
	getIOCsFromSelection(doc.Selection, &iocs, 0)

	return iocs, nil
}

// getIOCsFromSelection Takes a goquery selection and recursively finds all the IOCs
func getIOCsFromSelection(sel *goquery.Selection, iocs *[]*IOC, depth int) {
	if depth >= maxHTMLRecursionDepth {
		return
	}

	addIfUnique := func(iocIn *IOC) {
		for _, ioc := range *iocs {
			if reflect.DeepEqual(ioc, iocIn) {
				return
			}
		}
		*iocs = append(*iocs, iocIn)
	}

	sel.Each(func(i int, sel *goquery.Selection) {
		// Get this element's text without children text
		thisText := sel.Clone().Children().Remove().End().Text()
		// Replace \n just in case
		thisText = strings.ReplaceAll(thisText, "\n", "    ")
		// Find IOCs
		iocs := GetIOCs(thisText, false, false)
		for _, ioc := range iocs {
			addIfUnique(ioc)
		}
	})

	sel.Children().Each(func(i int, sel *goquery.Selection) {
		getIOCsFromSelection(sel, iocs, depth+1)
	})
}
