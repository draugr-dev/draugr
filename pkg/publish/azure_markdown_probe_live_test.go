//go:build integration

package publish

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// TestLiveAzureMarkdownProbe records how Azure DevOps stores a Markdown description and comment.
// It asserts nothing and leaves its work item open, for a person to look at.
func TestLiveAzureMarkdownProbe(t *testing.T) {
	a := newLiveAzure(t)
	raw := func(method, path, contentType string, body any) (int, string) {
		var r io.Reader = http.NoBody
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequestWithContext(context.Background(), method, a.org+url.PathEscape(a.project)+"/_apis/"+path, r)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+a.token)))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	data := a.onMain(map[string][]sarif.Result{
		"sca":  {upgradeFinding("api", "CVE-2026-0001", "P1"), upgradeFinding("web", "CVE-2026-0002", "P2")},
		"sast": {codeFinding("api", "python.lang.eval", "P1", "app/app.py")},
	})
	part := issueParts(data, issueEntry{})[0]
	marker := issueMarker(a.name, "all", issueEntry{}, part)
	rendered := newIssueBody(data, "all", issueEntry{}, part).render(markdownFormat{}, 60_000)
	fields := strings.TrimSuffix(strings.TrimPrefix(marker, "<!-- draugr:issue "), " -->")
	rest := strings.TrimPrefix(rendered, marker+"\n")
	body := "[//]: # \"draugr:issue " + fields + "\"\n\n<span data-draugr-issue=\"" + fields + "\"></span>\n\n" + rest
	t.Logf("SENT description:\n%s", body)

	ops := []map[string]any{
		{"op": "add", "path": "/fields/System.Title", "value": "Markdown probe: " + a.name},
		{"op": "add", "path": "/fields/System.Tags", "value": "draugr-probe"},
		{"op": "add", "path": "/fields/System.Description", "value": body},
		{"op": "add", "path": "/multilineFieldsFormat/System.Description", "value": "Markdown"},
	}
	var id float64
	for _, v := range []string{"7.1"} {
		code, resp := raw(http.MethodPost, "wit/workitems/$Task?api-version="+v, "application/json-patch+json", ops)
		t.Logf("CREATE api-version=%s: %d %.400s", v, code, resp)
		if code < 300 && id == 0 {
			var w map[string]any
			_ = json.Unmarshal([]byte(resp), &w)
			id, _ = w["id"].(float64)
		}
	}
	if id == 0 {
		t.Fatal("no version created a Markdown item")
	}
	n := strconv.FormatInt(int64(id), 10)

	read := func(label string) string {
		for _, v := range []string{"7.1", "7.2-preview.3"} {
			code, resp := raw(http.MethodGet, "wit/workitems/"+n+"?api-version="+v, "", nil)
			var w struct {
				Rev    int               `json:"rev"`
				Fields map[string]any    `json:"fields"`
				Format map[string]string `json:"multilineFieldsFormat"`
				Links  map[string]any    `json:"_links"`
			}
			_ = json.Unmarshal([]byte(resp), &w)
			desc, _ := w.Fields["System.Description"].(string)
			t.Logf("%s GET api-version=%s: %d rev=%d multilineFieldsFormat=%v equal=%v", label, v, code, w.Rev, w.Format, desc == body)
			if v == "7.1" {
				return desc
			}
		}
		return ""
	}
	got := read("AFTER CREATE")
	if got != body {
		t.Logf("STORED description differs:\n%s", got)
	}

	body = strings.Replace(body, "CVE-2026-0002", "CVE-2026-0003", 1)
	code, resp := raw(http.MethodPatch, "wit/workitems/"+n+"?api-version=7.1", "application/json-patch+json",
		[]map[string]any{{"op": "add", "path": "/fields/System.Description", "value": body}})
	t.Logf("UPDATE without format op: %d %.200s", code, resp)
	if got := read("AFTER UPDATE"); got != body {
		t.Logf("STORED description after update differs:\n%s", got)
	}
	code, resp = raw(http.MethodPatch, "wit/workitems/"+n+"?api-version=7.1", "application/json-patch+json",
		[]map[string]any{{"op": "add", "path": "/multilineFieldsFormat/System.Description", "value": "Markdown"}})
	t.Logf("UPDATE repeating format op: %d %.200s", code, resp)

	comment := "The gate passes on `main` in [job 7](https://example.com/7).\n\n- **bold** and a `code span`"
	for _, q := range []string{
		"comments?format=markdown&api-version=7.1-preview.4",
	} {
		code, resp := raw(http.MethodPost, "wit/workItems/"+n+"/"+q, "application/json", map[string]string{"text": comment})
		t.Logf("COMMENT %s: %d %.300s", q, code, resp)
	}
	code, resp = raw(http.MethodGet, "wit/workItems/"+n+"/comments?order=asc&api-version=7.2-preview.4", "", nil)
	var cs struct {
		Comments []struct {
			Text     string `json:"text"`
			Rendered string `json:"renderedText"`
			Format   any    `json:"format"`
		} `json:"comments"`
	}
	_ = json.Unmarshal([]byte(resp), &cs)
	t.Logf("COMMENTS GET: %d", code)
	for i, c := range cs.Comments {
		t.Logf("comment %d format=%v\n text=%q\n rendered=%q", i, c.Format, c.Text, c.Rendered)
	}
	t.Logf("ITEM %s_workitems/edit/%s", a.org+url.PathEscape(a.project)+"/", n)
}
