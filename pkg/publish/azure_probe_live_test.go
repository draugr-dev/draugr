//go:build integration

package publish

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestLiveAzureProbe records what the sandbox keeps of an HTML description, before the publisher
// is designed around it. Temporary; replaced by the lifecycle test.
func TestLiveAzureProbe(t *testing.T) {
	token, org, project := os.Getenv("SANDBOX_AZURE_TOKEN"), os.Getenv("SANDBOX_AZURE_ORG_URL"), os.Getenv("SANDBOX_AZURE_PROJECT")
	if token == "" || org == "" || project == "" {
		t.Skip("no Azure sandbox")
	}
	base := strings.TrimSuffix(org, "/") + "/" + url.PathEscape(project) + "/_apis/"
	call := func(method, path, ctype string, body any) (int, string) {
		var r io.Reader
		if body != nil {
			buf, _ := json.Marshal(body)
			r = bytes.NewReader(buf)
		}
		req, _ := http.NewRequest(method, base+path, r)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+token)))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		t.Logf("%s %s -> %d\n%s\n", method, path, resp.StatusCode, b)
		return resp.StatusCode, string(b)
	}

	call("GET", "wit/workitemtypecategories?api-version=7.1", "", nil)
	call("GET", "wit/workitemtypes/Task/states?api-version=7.1", "", nil)
	call("GET", "wit/workitemtypes/User%20Story/states?api-version=7.1", "", nil)

	desc := "<!-- draugr:issue v1 project=probe scope=all -->\n" +
		"<p>Plain <code>code</code> and <strong>bold</strong> and <a href=\"https://example.com\">a link</a>.</p>\n" +
		"<h3>Heading</h3>\n<hr>\n" +
		"<table><thead><tr><th>A</th><th>B</th></tr></thead><tbody><tr><td>1</td><td>2</td></tr></tbody></table>\n" +
		"<ul><li>one</li><li>two</li></ul>\n" +
		"<details><summary>More</summary><p>Hidden text</p></details>\n" +
		"<p data-draugr=\"project=probe\" title=\"draugr:issue\">attribute carrier</p>\n" +
		"<pre>pre block</pre>"
	code, out := call("POST", "wit/workitems/$Task?api-version=7.1", "application/json-patch+json", []map[string]any{
		{"op": "add", "path": "/fields/System.Title", "value": "draugr probe"},
		{"op": "add", "path": "/fields/System.Description", "value": desc},
		{"op": "add", "path": "/fields/System.Tags", "value": "draugr-probe; draugr:priority:high"},
	})
	if code != http.StatusOK {
		t.Fatalf("create: %d", code)
	}
	var made struct {
		ID  int64 `json:"id"`
		Rev int   `json:"rev"`
	}
	_ = json.Unmarshal([]byte(out), &made)
	id := jsonID(made.ID)

	call("GET", "wit/workitems/"+id+"?api-version=7.1", "", nil)
	call("POST", "wit/workItems/"+id+"/comments?api-version=7.1-preview.4", "application/json",
		map[string]any{"text": "<!-- a comment marker --><p>The gate passes on <code>main</code> in <a href=\"https://example.com\">job 1</a>.</p>"})
	call("GET", "wit/workItems/"+id+"/comments?api-version=7.1-preview.4", "", nil)
	call("POST", "wit/wiql?api-version=7.1", "application/json", map[string]any{
		"query": "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS 'draugr-probe' ORDER BY [System.Id]",
	})
	call("PATCH", "wit/workitems/"+id+"?api-version=7.1", "application/json-patch+json", []map[string]any{
		{"op": "test", "path": "/rev", "value": made.Rev + 5},
		{"op": "add", "path": "/fields/System.Title", "value": "draugr probe, stale rev"},
	})
	call("PATCH", "wit/workitems/"+id+"?api-version=7.1", "application/json-patch+json", []map[string]any{
		{"op": "add", "path": "/fields/System.AssignedTo", "value": "nobody-here@example.invalid"},
	})
	call("PATCH", "wit/workitems/"+id+"?api-version=7.1", "application/json-patch+json", []map[string]any{
		{"op": "add", "path": "/fields/System.State", "value": "Closed"},
	})
	call("GET", "wit/workitems/"+id+"?fields=System.State,System.Tags,System.Reason&api-version=7.1", "", nil)
}

func jsonID(n int64) string { b, _ := json.Marshal(n); return string(b) }
