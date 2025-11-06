/*
Package query provides a gjson based query syntax for matching and filtering json documents.
*/
package query

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

func init() {
	gjson.AddModifier("eq", func(json, arg string) string {
		// match if json is equal to arg
		if json == arg {
			return json
		}
		return ""
	})
	gjson.AddModifier("ne", func(json, arg string) string {
		// match if json is not equal to arg
		if json != arg {
			return json
		}
		return ""
	})
	gjson.AddModifier("in", func(json, arg string) string {
		// exact match of any item in list
		for _, v := range parseArray(arg) {
			if json == v {
				return json
			}
		}
		return ""
	})
	gjson.AddModifier("lt", func(json, arg string) string {
		// match if arg is larger than json number
		lhs, err := strconv.Atoi(json)
		if err != nil {
			return ""
		}
		rhs, err := strconv.Atoi(arg)
		if err != nil {
			return ""
		}
		if lhs < rhs {
			return json
		}
		return ""
	})
	gjson.AddModifier("gt", func(json, arg string) string {
		// match if arg is smaller than json number
		lhs, err := strconv.Atoi(json)
		if err != nil {
			return ""
		}
		rhs, err := strconv.Atoi(arg)
		if err != nil {
			return ""
		}
		if lhs > rhs {
			return json
		}
		return ""
	})
	gjson.AddModifier("re", func(json, arg string) string {
		// check if regex arg is a match over the whole json string
		r, err := regexp.Compile(gjson.Parse(arg).String())
		if err != nil {
			return ""
		}
		return r.FindString(json)
	})
	gjson.AddModifier("contains", func(json, arg string) string {
		// check if arg is a substring of json
		if strings.Contains(json, arg) {
			return json
		}
		return ""
	})
	gjson.AddModifier("icontains", func(json, arg string) string {
		// case insensitive check if arg is a substring of json
		if strings.Contains(strings.ToLower(json), strings.ToLower(arg)) {
			return json
		}
		return ""
	})
	gjson.AddModifier("any", func(json, arg string) string {
		// case sensitive contains any supplied substring in json
		for _, v := range parseArray(arg) {
			if strings.Contains(json, v) {
				return json
			}
		}
		return ""
	})
	gjson.AddModifier("iany", func(json, arg string) string {
		// case insensitive contains any supplied substring in json
		j := strings.ToLower(json)
		for _, v := range parseArray(strings.ToLower(arg)) {
			if strings.Contains(j, v) {
				return json
			}
		}
		return ""
	})
}
func comma(c rune) bool {
	return c == ','
}

// Try to parse an array out of a string first as JSON and then as csv
func parseArray(json string) []string {
	ret := []string{}
	if json[0] == '[' {
		// probably a json list
		for _, v := range gjson.Parse(json).Array() {
			ret = append(ret, v.String())
		}
	}
	if len(ret) <= 0 {
		ret = strings.FieldsFunc(json, comma)
	}
	return ret
}

// ExplainableMatches tests that supplied filters return a non-empty subset
// of the json document.  Filter is in gjson syntax with custom
// modifiers: eq, in, lt, gt, re, contains, icontains
//
// ExplainableMatches additionally returns the first filter that failed the match.
//
// Multiple supplied filters will be tested independently and
// results implicitly AND'ed together
//
// Example:
//
//		j := `{
//	 	"name": "Phil",
//			"cars": [
//				{"make": "Toyota", "model": "Corolla", "year": 1990},
//				{"make": "Mazda", "model": "MX5", "year": 2005}
//			]
//		}`
//		Matches(j, [`name|@in:["\"Phil\"","\"Fred\""]`, `cars.#(make=="Mazda")#|#(year>2002)`])
//		>> true
func ExplainableMatches(json []byte, filters []string) (string, bool) {
	for _, f := range filters {
		switch string(Filter(json, f)) {
		case "", "{}", "[]", "null":
			return f, false
		}
	}
	return "", true
}

// Matches is same as ExplainableMatches but does not return the first filter.
func Matches(json []byte, filters []string) bool {
	_, matched := ExplainableMatches(json, filters)
	return matched
}

// Filter returns the subset of the json document that matches
// the supplied gjson syntax formatted parameter.
//
// Custom modifiers are available that return their input value if
// matched, otherwise, the empty string:
// eq, in, lt, gt, re, contains, icontains
//
// Example:
//
//		j := `{
//	 	"name": "Phil",
//	 	"cars": [
//	 		{"make": "Toyota", "model": "Corolla", "year": 1990},
//				{"make": "Mazda", "model": "MX5", "year": 2005}
//			]
//		}`
//		Filter(j, `name|@in:["\"Phil\"","\"Fred\""]`)
//		>> "Phil"
//
//		Filter(j, `cars.#(make=="Mazda")#|#(year>2002)`)
//		>> [{"make": "Mazda", "model": "MX5", "year": 2005}]
func Filter(json []byte, filter string) []byte {
	result := gjson.GetBytes(json, filter)
	if result.Index > 0 {
		return json[result.Index : result.Index+len(result.Raw)]
	}
	return []byte(result.Raw)
}

// Valid tests whether the supplied json string is well-formed.
func Valid(json []byte) bool {
	return gjson.ValidBytes(json)
}
