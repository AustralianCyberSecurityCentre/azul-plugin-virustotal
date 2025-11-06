package query

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const LargeJson = `{"action":"enriched","source":{"group":{"name":"testsource1","organisation":"ASD's ACSC"},"reference":"ares","subreference":"steveh","path":[{"author":{"name":"ExamplePublisher","category":"Loader"},"event_type":"","sha256":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","event_id":"","timestamp":"2019-08-22T14:02:13.835941383+10:00"},{"author":{"name":"entropy","category":"plugin","version":"1.0"},"event_type":"","sha256":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","event_id":"","timestamp":"2019-08-22T14:02:16.303799298+10:00"}]},"author":{"name":"entropy","category":"plugin","version":"1.0"},"entity":{"datastreams":[{"label":"content","sha256":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","sha1":"f12d932991468ce62f854c1b93d872dc5ca6a4aa","md5":"ae4c93e12f1f28c92ad951a802db781e","mime_type":"application/zip","mime_magic":"Zip archive data, at least v2.0 to extract","file_format_legacy":"Not Yet Implemented","size":651906}],"features":[{"name":"entropy","value":7.98191277760225,"value_text":"7.9819","value_type":"float","author":{"name":"entropy","category":"plugin","version":"1.0"}}],"file_format_legacy":"Not Yet Implemented","id":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","info":{"entropy":{"overall":7.98191277760225,"block_size":814,"block_count":800,"blocks":[7.7178590787227614,7.56764130019787,7.623628614906964,7.16658027982474,7.511285411649219,7.72079585623346,7.679248110069014,7.734230155498086,7.782232559760044,7.719443666123593,7.709051146995637,7.693994512523687,7.721895617098214,7.713147729970372,7.692972404975388]}},"md5":"ae4c93e12f1f28c92ad951a802db781e","sha1":"f12d932991468ce62f854c1b93d872dc5ca6a4aa","sha256":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","size":651906},"timestamp":"2019-08-22T14:02:16.303799298+10:00"}`

const LargeJson2 = `{"author":{"name":"FilePublisher","version":"1.0","category":"Loader"},"action":"sourced","source":{"id":"testsource","references":{"source_host":"host1","source_user":"user2"},"security":{},"path":[{"author":{"name":"FilePublisher","version":"1.0","category":"Loader"},"action":"sourced","sha256":"afee748200d7b2fd79d5d8d39b6d2746aaba2969dffd82bc57505cc58d87a28a","filename":"foobar.docx","size":6231367,"type":"Office Open XML Document","timestamp":"2021-02-22T15:36:16.241364867+11:00"}],"timestamp":"2021-02-20T21:31:02.252829258+11:00"},"entity":{"id":"afee748200d7b2fd79d5d8d39b6d2746aaba2969dffd82bc57505cc58d87a28a","datastreams":[{"label":"content","sha512":"6973efc0c7acaf8cb104df8d0741ee494b945b46f73ef41491492c1ac8cba29e0e62e2aca5a57eb7bd994c850979ef82f68160ffe8579e4d86e558b74b9eb4cf","sha256":"afee748200d7b2fd79d5d8d39b6d2746aaba2969dffd82bc57505cc58d87a28a","sha1":"6007db9751304048addafed3f5efe0442bfb93d9","md5":"ee5211fd69cb22f395b0bb35fedbafb8","mime_type":"application/vnd.openxmlformats-officedocument.wordprocessingml.document","mime_magic":"Microsoft Word 2007+","file_format_legacy":"Office Open XML Document","size":6231367}],"sha512":"6973efc0c7acaf8cb104df8d0741ee494b945b46f73ef41491492c1ac8cba29e0e62e2aca5a57eb7bd994c850979ef82f68160ffe8579e4d86e558b74b9eb4cf","sha256":"afee748200d7b2fd79d5d8d39b6d2746aaba2969dffd82bc57505cc58d87a28a","sha1":"6007db9751304048addafed3f5efe0442bfb93d9","md5":"ee5211fd69cb22f395b0bb35fedbafb8","size":6231367,"type":"Office Open XML Document","features":[{"name":"file_format_legacy","value":"Office Open XML Document","type":"string","author":"FilePublisher"},{"name":"magic","value":"Microsoft Word 2007+","type":"string","author":"FilePublisher"},{"name":"mime","value":"application/vnd.openxmlformats-officedocument.wordprocessingml.document","type":"string","author":"FilePublisher"},{"name":"filename","value":"/samples/macros/foobar.docx","type":"filepath","author":"FilePublisher"}]},"timestamp":"2021-02-22T15:36:16.241364867+11:00","id":"e874b3eac52a2a4b42e912b3cb15e06f"}`

func TestFilter(t *testing.T) {
	j := []byte(LargeJson)
	f := `source.group.name`
	if r := Filter(j, f); string(r) != `"testsource1"` {
		t.Errorf("Unexpected result for path filter: %s | %s", r, f)
	}
	f = `entity.datastreams.#(mime_type=="application/zip")`
	if r := Filter(j, f); string(r) != `{"label":"content","sha256":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","sha1":"f12d932991468ce62f854c1b93d872dc5ca6a4aa","md5":"ae4c93e12f1f28c92ad951a802db781e","mime_type":"application/zip","mime_magic":"Zip archive data, at least v2.0 to extract","file_format_legacy":"Not Yet Implemented","size":651906}` {
		t.Errorf("Unexpected result for array filter: %s | %s", r, f)
	}
	f = `entity.datastreams|@contains:Zip`
	if r := Filter(j, f); string(r) != `[{"label":"content","sha256":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","sha1":"f12d932991468ce62f854c1b93d872dc5ca6a4aa","md5":"ae4c93e12f1f28c92ad951a802db781e","mime_type":"application/zip","mime_magic":"Zip archive data, at least v2.0 to extract","file_format_legacy":"Not Yet Implemented","size":651906}]` {
		t.Errorf("Unexpected result for contains filter: %s | %s", r, f)
	}
	f = `entity.datastreams|@icontains:ZIP`
	if r := Filter(j, f); string(r) != `[{"label":"content","sha256":"1315319acf2cd02ce17a4a6ce4b7ac413ca206807030cfb2c0fc2866530a1489","sha1":"f12d932991468ce62f854c1b93d872dc5ca6a4aa","md5":"ae4c93e12f1f28c92ad951a802db781e","mime_type":"application/zip","mime_magic":"Zip archive data, at least v2.0 to extract","file_format_legacy":"Not Yet Implemented","size":651906}]` {
		t.Errorf("Unexpected result for icontains filter: %s | %s", r, f)
	}
	f = `action|@ne:"enriched"`
	if r := Filter(j, f); string(r) != `` {
		t.Errorf("Unexpected result for ne filter matched: %s | %s", r, f)
	}
	f = `action|@ne:"mapped"`
	if r := Filter(j, f); string(r) != `"enriched"` {
		t.Errorf("Unexpected result for ne filter unmatched: '%s' | %s", r, f)
	}
}

func TestExplainableMatch(t *testing.T) {
	j := []byte(`{"datastreams":"this", "prop": true, "actually": "yes"}`)
	m := []string{
		`datastreams|@any:apple,this`,
		`actually|@any:yes,no`,
		`prop|@any:false`,
	}
	last, matched := ExplainableMatches(j, m)
	require.False(t, matched)
	require.Equal(t, "prop|@any:false", last)
}

func TestMatch(t *testing.T) {
	var j []byte
	var m []string

	// check eq
	j = []byte(`{"datastreams":[1,2,3,4]}`)
	m = []string{`datastreams|@eq:[1,2,3,4]`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":[1,2,3,4]}`)
	m = []string{`datastreams|@eq:[1,2,3,5]`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"goblin"}`)
	m = []string{`datastreams|@eq:"goblin"`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check ne
	j = []byte(`{"datastreams":[1,2,3,4]}`)
	m = []string{`datastreams|@ne:[1,2,3,4]`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":[1,2,3,4]}`)
	m = []string{`datastreams|@ne:[1,2,3,5]`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"goblin"}`)
	m = []string{`datastreams|@ne:"goblin"`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check in
	j = []byte(`{"datastreams":"apple pie"}`)
	m = []string{`datastreams|@in:["grape", "apple"]`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	// this one is missing quotes
	j = []byte(`{"datastreams":"apple"}`)
	m = []string{`datastreams|@in:["grape", "apple"]`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"apple"}`)
	m = []string{`datastreams|@in:["\"grape\"", "\"apple\""]`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	//check lt
	j = []byte(`{"datastreams":37}`)
	m = []string{`datastreams|@lt:40`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":37}`)
	m = []string{`datastreams|@lt:20`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	//check gt
	j = []byte(`{"datastreams":37}`)
	m = []string{`datastreams|@gt:40`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":37}`)
	m = []string{`datastreams|@gt:20`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check re
	j = []byte(`{"action": "this is just an example thing"}`)
	m = []string{`action|@re:".*ex..ple.*"`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"action": "event|@iany:[\"example\",\"bongo\",\"bango\"]"}`)
	m = []string{`action|@re:".*...nt|@iany"`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check contains
	j = []byte(`{"datastreams":"this is a really long string so yeah"}`)
	m = []string{`datastreams|@contains:really long string`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"this is a really long string so yeah"}`)
	m = []string{`datastreams|@contains:really long time`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check icontains
	j = []byte(`{"datastreams":"this is a really long string so yeah"}`)
	m = []string{`datastreams|@contains:really long String`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"this is a really long string so yeah"}`)
	m = []string{
		`datastreams|@contains:really long string`,
	}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check any
	j = []byte(`{"datastreams":"this"]}`)
	m = []string{`datastreams|@any:["apple","this"]`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"this"]}`)
	m = []string{`datastreams|@any:["Apple","This"]`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"this"]}`)
	m = []string{`datastreams|@any:apple,this`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"datastreams":"this"]}`)
	m = []string{`datastreams|@any:Apple,This`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	//
	// check iany operator
	//
	// check that iany work with big list of strings
	j = []byte(LargeJson2)
	m = []string{
		`entity.datastreams.#(label=="content")#.file_format_legacy|@iany:["MS Word Document","MS Excel Spreadsheet","MS PowerPoint Presentation","MS Visio Diagram","Office Open XML Document","Office Open XML Presentation","Office Open XML Spreadsheet","Text","datastreams"]`,
		`action|@ne:"enriched"`,
	}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	// check that iany works with last string
	j = []byte(`{"action":[{"key": "trouble"},{"key": "bubble"}]}`)
	m = []string{`action.#(key)#.key|@iany:["double", "trouble"]`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	// check that any is case sensitive
	j = []byte(`{"action":[{"key": "trouble"},{"key": "bubble"}]}`)
	m = []string{`action.#(key)#.key|@any:["Double", "Trouble"]`}
	if Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	// check that any is case sensitive
	j = []byte(`{"action":[{"key": "Trouble"},{"key": "Bubble"}]}`)
	m = []string{`action.#(key)#.key|@any:["Double", "Trouble"]`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	// check iany matches substring
	j = []byte(`{"action": "this is just an example thing"}`)
	m = []string{`action|@iany:["example","bongo","bango"]`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check iany matches non-json args
	j = []byte(`{"action": "this is just an example thing"}`)
	m = []string{`action|@iany:apple,example`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"action": "this is just an example thing"}`)
	m = []string{`action|@iany:Apple,Example`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}
	j = []byte(`{"action": "this is just an Example thing"}`)
	m = []string{`action|@iany:Apple,Example`}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

	// check usage of iany
	j = []byte(`{"entity":{"datastreams":[{"label":"content", "file_format_legacy": "content-type-1"}]}}`)
	m = []string{"entity.datastreams.#(label==\"content\")#.file_format_legacy|@any:[\"\\\"content-type-1\\\"\", \"\\\"content-type-2\\\"\"]"}
	if !Matches(j, m) {
		t.Errorf("%s | %s", j, m)
	}

}

func BenchmarkValidate(b *testing.B) {
	j := []byte(LargeJson)
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Valid(j)
	}
}

func BenchmarkFilterPath(b *testing.B) {
	j := []byte(LargeJson)
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Filter(j, `source.group.name`)
	}
}

func BenchmarkFilterArray(b *testing.B) {
	j := []byte(LargeJson)
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Filter(j, `entity.datastreams.#(mime_type=="application/zip")`)
	}
}

func BenchmarkFilterContains(b *testing.B) {
	j := []byte(LargeJson)
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Filter(j, `entity.datastreams|@contains:Zip`)
	}
}

func BenchmarkFilterIContains(b *testing.B) {
	j := []byte(LargeJson)
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Filter(j, `entity.datastreams|@icontains:ZIP`)
	}
}

func BenchmarkFilterRegex(b *testing.B) {
	j := []byte(LargeJson)
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Filter(j, `entity.datastreams|@re:"Zip\sArchive"`)
	}
}
