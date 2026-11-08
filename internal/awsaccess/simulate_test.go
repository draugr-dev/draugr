package awsaccess

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// fakeIAM is a Simulator with a fixed answer. Synthetic: no recording of a successful simulation
// exists, because the role the recordings were made with may not call it.
type fakeIAM struct {
	roles    map[string]string
	allowed  []string
	roleErr  error
	simErr   error
	simAsked string
}

func (f *fakeIAM) RoleARN(_ context.Context, name string) (string, error) {
	if f.roleErr != nil {
		return "", f.roleErr
	}
	arn, ok := f.roles[name]
	if !ok {
		return "", errors.New("NoSuchEntity")
	}
	return arn, nil
}

func (f *fakeIAM) Allowed(_ context.Context, principal string, actions []string) ([]string, error) {
	f.simAsked = principal
	if f.simErr != nil {
		return nil, f.simErr
	}
	var out []string
	for _, a := range actions {
		if slices.Contains(f.allowed, a) {
			// IAM echoes a name in its own case.
			out = append(out, strings.ToUpper(a[:1])+a[1:])
		}
	}
	return out, nil
}

const ssoRole = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Audit_0000"

// A role session is simulated as the role it assumed, at the ARN with the path GetRole returns; a
// user as itself. The root and a federated user have no principal to simulate.
func TestPrincipalIsTheRoleWithItsPath(t *testing.T) {
	sim := &fakeIAM{roles: map[string]string{"AWSReservedSSO_Audit_0000": ssoRole}}
	for arn, want := range map[string]string{
		"arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Audit_0000/someone": ssoRole,
		"arn:aws:iam::111111111111:user/ops/scanner":                               "arn:aws:iam::111111111111:user/ops/scanner",
	} {
		got, err := Principal(context.Background(), sim, Caller{ARN: arn})
		if err != nil || got != want {
			t.Errorf("%s = %q, %v, want %q", arn, got, err, want)
		}
	}
	for _, arn := range []string{"arn:aws:iam::111111111111:root", "arn:aws:sts::111111111111:federated-user/bob"} {
		if _, err := Principal(context.Background(), sim, Caller{ARN: arn}); !errors.Is(err, ErrNotSimulated) {
			t.Errorf("%s = %v, want ErrNotSimulated", arn, err)
		}
	}
	if _, err := Principal(context.Background(), sim, Caller{ARN: "not-an-arn"}); err == nil {
		t.Error("a malformed ARN was accepted")
	}
	sim.roleErr = errors.New("AccessDenied: iam:GetRole")
	if _, err := Principal(context.Background(), sim,
		Caller{ARN: "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Audit_0000/someone"}); !errors.Is(err, sim.roleErr) {
		t.Errorf("a denied GetRole = %v, want it passed on", err)
	}
}

func TestDeniedIsWhatTheSimulationDoesNotAllow(t *testing.T) {
	session := Caller{ARN: "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Audit_0000/someone"}
	sim := &fakeIAM{roles: map[string]string{"AWSReservedSSO_Audit_0000": ssoRole},
		allowed: []string{"kms:ListAliases", "s3:GetBucketLocation"}}
	got, err := Denied(context.Background(), sim, session,
		[]string{"kms:DescribeKey", "kms:ListAliases", "s3:GetBucketLocation", "sns:GetTopicAttributes"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"kms:DescribeKey", "sns:GetTopicAttributes"}; !slices.Equal(got, want) {
		t.Errorf("denied = %v, want %v", got, want)
	}
	if sim.simAsked != ssoRole {
		t.Errorf("simulated %q, want the role", sim.simAsked)
	}

	sim.simErr = errors.New("AccessDenied: iam:SimulatePrincipalPolicy")
	if _, err := Denied(context.Background(), sim, session, []string{"kms:DescribeKey"}); !errors.Is(err, sim.simErr) {
		t.Errorf("a denied simulation = %v, want it passed on", err)
	}
	if _, err := Denied(context.Background(), sim, Caller{ARN: "arn:aws:iam::111111111111:root"}, nil); !errors.Is(err, ErrNotSimulated) {
		t.Errorf("the root = %v", err)
	}
}

// iamServer answers GetRole and SimulatePrincipalPolicy in IAM's XML, the simulation in two pages.
// Synthetic, in the shape IAM's API reference documents.
func iamServer(t *testing.T, deny bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "text/xml")
		if deny {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>` +
				`<Message>not authorized</Message></Error><RequestId>1</RequestId></ErrorResponse>`))
			return
		}
		switch r.Form.Get("Action") {
		case "GetRole":
			if r.Form.Get("RoleName") != "AWSReservedSSO_Audit_0000" {
				t.Errorf("RoleName = %q", r.Form.Get("RoleName"))
			}
			_, _ = w.Write([]byte(`<GetRoleResponse><GetRoleResult><Role><Path>/aws-reserved/sso.amazonaws.com/</Path>` +
				`<RoleName>AWSReservedSSO_Audit_0000</RoleName><RoleId>AROAAAAAAAAAAAAAAAAAA</RoleId>` +
				`<Arn>` + ssoRole + `</Arn>` +
				`<CreateDate>2026-01-01T00:00:00Z</CreateDate></Role></GetRoleResult></GetRoleResponse>`))
		case "SimulatePrincipalPolicy":
			if r.Form.Get("PolicySourceArn") != ssoRole {
				t.Errorf("PolicySourceArn = %q", r.Form.Get("PolicySourceArn"))
			}
			if r.Form.Get("Marker") == "" {
				_, _ = w.Write([]byte(`<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>` +
					`<IsTruncated>true</IsTruncated><Marker>m</Marker><EvaluationResults>` +
					`<member><EvalActionName>kms:DescribeKey</EvalActionName><EvalDecision>implicitDeny</EvalDecision></member>` +
					`</EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>` +
				`<IsTruncated>false</IsTruncated><EvaluationResults>` +
				`<member><EvalActionName>kms:ListAliases</EvalActionName><EvalDecision>allowed</EvalDecision></member>` +
				`<member><EvalActionName>sns:GetTopicAttributes</EvalActionName><EvalDecision>explicitDeny</EvalDecision></member>` +
				`</EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`))
		default:
			t.Errorf("unexpected action %q", r.Form.Get("Action"))
		}
	}))
}

func TestIAMAsksGetRoleThenSimulatesEveryPage(t *testing.T) {
	isolate(t)
	srv := iamServer(t, false)
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AAAAAAAAAAAAAAAAAAAA")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("AWS_ENDPOINT_URL_IAM", srv.URL)
	sim, err := NewIAM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session := Caller{ARN: "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Audit_0000/someone"}
	got, err := Denied(context.Background(), sim, session,
		[]string{"kms:DescribeKey", "kms:ListAliases", "sns:GetTopicAttributes"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"kms:DescribeKey", "sns:GetTopicAttributes"}; !slices.Equal(got, want) {
		t.Errorf("denied = %v, want %v", got, want)
	}
}

func TestIAMNamesWhatWasDenied(t *testing.T) {
	isolate(t)
	srv := iamServer(t, true)
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AAAAAAAAAAAAAAAAAAAA")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("AWS_ENDPOINT_URL_IAM", srv.URL)
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	sim, err := NewIAM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sim.RoleARN(context.Background(), "audit"); err == nil ||
		!strings.HasPrefix(err.Error(), "ask IAM for role audit: ") || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("GetRole = %v", err)
	}
	if _, err := sim.Allowed(context.Background(), ssoRole, []string{"kms:DescribeKey"}); err == nil ||
		!strings.HasPrefix(err.Error(), "simulate the policies of "+ssoRole+": ") {
		t.Errorf("SimulatePrincipalPolicy = %v", err)
	}
}

func TestNewIAMWithNoCredentials(t *testing.T) {
	isolate(t)
	if _, err := NewIAM(context.Background()); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v, want ErrNoCredentials", err)
	}
}
