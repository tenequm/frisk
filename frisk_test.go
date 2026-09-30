package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testLogger = slog.New(slog.NewJSONHandler(io.Discard, nil))

func TestParseCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		command  string
		segments [][]string
		complex  bool
	}{
		{"simple", "git status", [][]string{{"git", "status"}}, false},
		{"pipeline", "git log | head -5", [][]string{{"git", "log"}, {"head", "-5"}}, false},
		{"and-chain", "cd api && git status", [][]string{{"cd", "api"}, {"git", "status"}}, false},
		{"or-chain", "test -f x || echo no", [][]string{{"test", "-f", "x"}, {"echo", "no"}}, false},
		{"semicolons", "ls; pwd", [][]string{{"ls"}, {"pwd"}}, false},
		{"quotes", `grep "a b" f.txt`, [][]string{{"grep", "a b", "f.txt"}}, false},
		{"assignment stripped", "FOO=1 env", [][]string{{"env"}}, false},
		{"substitution is complex", "echo $(rm -rf /)", [][]string{{"echo", "$(rm", "-rf", "/)"}}, true},
		{"backtick is complex", "echo `id`", [][]string{{"echo", "`id`"}}, true},
		{"redirect is complex", "echo hi > f", [][]string{{"echo", "hi", ">", "f"}}, true},
		{"heredoc is complex", "cat <<EOF\nhi\nEOF", nil, true},
		{"background is complex", "sleep 5 &", [][]string{{"sleep", "5"}}, true},
		{"unclosed quote is complex", `echo "oops`, [][]string{{"echo", "oops"}}, true},
		{"hijacking assignment is complex", "GIT_PAGER=x git log", [][]string{{"git", "log"}}, true},
		{"credential glob is complex", "cat ~/.s*/id_*", [][]string{{"cat", "~/.s*/id_*"}}, true},
		{"quoted glob is not expanded", "jq '.items[]' f.json", [][]string{{"jq", ".items[]", "f.json"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			segments, unsound := parseCommand(tt.command)
			if unsound != tt.complex {
				t.Fatalf("unsound = %v, want %v", unsound, tt.complex)
			}
			if tt.name == "heredoc is complex" {
				return // segment shape after heredoc bail is unspecified
			}
			got, _ := json.Marshal(segments)
			want, _ := json.Marshal(tt.segments)
			if string(got) != string(want) {
				t.Fatalf("segments = %s, want %s", got, want)
			}
		})
	}
}

func TestMatchRule(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rule   string
		tokens []string
		want   bool
	}{
		{"git log *", []string{"git", "log"}, true},
		{"git log *", []string{"git", "log", "--oneline"}, true},
		{"git log *", []string{"git", "logs"}, false},
		{"git -C * log *", []string{"git", "-C", "/x", "log", "-1"}, true},
		{"git -C * log *", []string{"git", "-C", "/x", "push"}, false},
		{"pwd", []string{"pwd"}, true},
		{"pwd", []string{"pwd", "-P"}, false},
		{"gopass show -o *", []string{"gopass", "show", "-o", "api/KEY"}, true},
		{"rm -rf /tmp/x*", []string{"rm", "-rf", "/tmp/x1"}, true},
	}
	for _, tt := range tests {
		if got := matchRule(tt.rule, tt.tokens); got != tt.want {
			t.Errorf("matchRule(%q, %v) = %v, want %v", tt.rule, tt.tokens, got, tt.want)
		}
	}
}

func TestDecideStaticTiers(t *testing.T) {
	t.Parallel()
	cfg := &config{
		Permissions: permissionsConfig{
			Allow: []string{defaultsMarker, "just check"},
			Deny:  []string{"gopass show -o *"},
			Ask:   []string{"ssh prod *"},
		},
	}
	tests := []struct {
		name     string
		command  string
		decision string
		tier     string
	}{
		{"deny wins", "gopass show -o api/KEY", decisionDeny, "deny-rule"},
		{"deny wins inside chain", "cd x && gopass show -o k", decisionDeny, "deny-rule"},
		{"ask rule", "ssh prod uptime", decisionAsk, "ask-rule"},
		{"builtin readonly", "git -C /x log --oneline | head -3", decisionAllow, "static"},
		{"config allow", "just check", decisionAllow, "static"},
		{"write flag disqualifies", "sed -i s/a/b/ f.txt", "", "no-judge"},
		{"find -delete disqualifies", "find . -name x -delete", "", "no-judge"},
		{"unknown verb is silent without key", "terraform plan", "", "no-judge"},
		{"substitution never static", "cat $(echo /etc/passwd)", "", "no-judge"},
		{"redirect never static", "ls > f", "", "no-judge"},
		{"ssh key never static", "cat ~/.ssh/id_rsa", "", "no-judge"},
		{"ssh dir never static", "ls ~/.ssh", "", "no-judge"},
		{"aws credentials never static", "head /Users/x/.aws/credentials", "", "no-judge"},
		{"quoted gnupg path never static", `tail "$HOME/.gnupg/secring.gpg"`, "", "no-judge"},
		{"pem never static", "xxd certs/server.pem", "", "no-judge"},
		{"netrc in chain never static", "cd ~ && cat .netrc", "", "no-judge"},
		{"zshenv never static", "cat ~/.zshenv", "", "no-judge"},
		{"dotenv never static", "cat .env", "", "no-judge"},
		{"dotenv variant never static", "cat .env.local", "", "no-judge"},
		{"envrc never static", "cat ~/proj/.envrc", "", "no-judge"},
		{"env subdir stays static", "ls src/env/config.go", "allow", "static"},
		{"keychain never static", "nl login.keychain-db", "", "no-judge"},
		{"plain file stays static", "cat README.md", decisionAllow, "static"},
		{"jq key filter stays static", "jq .data.key f.json", decisionAllow, "static"},
		{"git -C remote add never static", "git -C repo remote add x url", "", "no-judge"},
		{"git remote add never static", "git remote add x url", "", "no-judge"},
		{"git -C remote -v stays static", "git -C repo remote -v", decisionAllow, "static"},
		{"git remote get-url stays static", "git remote get-url origin", decisionAllow, "static"},
		{"sed attached suffix never static", "sed -i.bak s/a/b/ f", "", "no-judge"},
		{"sed bundled -i never static", "sed -ni s/a/b/p f", "", "no-judge"},
		{"sed abbreviated --in-place never static", "sed --in-pl s/a/b/ f", "", "no-judge"},
		{"sort attached output never static", "sort -oout.txt f", "", "no-judge"},
		{"sort abbreviated --output never static", "sort --out=x f", "", "no-judge"},
		{"sed substitution stays static", "sed s/a/b/ f.txt", decisionAllow, "static"},
		{"sed -n stays static", "sed -n 1,5p f.txt", decisionAllow, "static"},
		{"sort -u stays static", "sort -u f.txt", decisionAllow, "static"},
		{"fd exec never static", "fd . -x rm {}", "", "no-judge"},
		{"fd bundled exec-batch never static", "fd -HX rm", "", "no-judge"},
		{"rg pre never static", "rg --pre=sh foo", "", "no-judge"},
		{"rg hostname-bin never static", "rg --hostname-bin=x foo", "", "no-judge"},
		{"git upload-pack never static", "git fetch --upload-pack=touch origin", "", "no-judge"},
		{"git abbreviated upload-pack never static", "git fetch --upload=touch origin", "", "no-judge"},
		{"xxd revert never static", "xxd -r a b", "", "no-judge"},
		{"fd pattern stays static", "fd pattern", decisionAllow, "static"},
		{"fd extension stays static", "fd -e go", decisionAllow, "static"},
		{"rg pretty stays static", "rg --pretty foo", decisionAllow, "static"},
		{"git fetch stays static", "git fetch origin", decisionAllow, "static"},
		{"xxd dump stays static", "xxd -p f.bin", decisionAllow, "static"},
		{"git ssh command env never static", "GIT_SSH_COMMAND=x git fetch origin", "", "no-judge"},
		{"lessopen env never static", "LESSOPEN=x less f", "", "no-judge"},
		{"path env never static", "PATH=/tmp git status", "", "no-judge"},
		{"git config env never static", "GIT_CONFIG_COUNT=1 git log", "", "no-judge"},
		{"benign env stays static", "FOO=1 rg x", decisionAllow, "static"},
		{"locale env stays static", "LC_ALL=C sort f.txt", decisionAllow, "static"},
		{"ssh glob never static", "cat ~/.ss*/id_*", "", "no-judge"},
		{"hidden brace never static", "cat ~/.s{s,}h/config", "", "no-judge"},
		{"aws glob never static", "head ~/.aws/cred*", "", "no-judge"},
		{"hidden glob never static", "ls .*", "", "no-judge"},
		{"source glob stays static", "ls *.go", decisionAllow, "static"},
		{"quoted jq brackets stay static", "jq '.items[]' f.json", decisionAllow, "static"},
		{"subdir glob stays static", "cat src/*.txt", decisionAllow, "static"},
		{"bare printenv never static", "printenv", "", "no-judge"},
		{"printenv secret never static", "printenv AWS_SECRET_ACCESS_KEY", "", "no-judge"},
		{"printenv flag only never static", "printenv -0", "", "no-judge"},
		{"bare env never static", "env", "", "no-judge"},
		{"echo secret ref never static", "echo $GITHUB_TOKEN", "", "no-judge"},
		{"echo braced secret ref never static", "echo ${API_KEY}", "", "no-judge"},
		{"gopass find never static", "gopass find foo", "", "no-judge"},
		{"printenv name stays static", "printenv HOME", decisionAllow, "static"},
		{"echo plain var stays static", "echo $HOME", decisionAllow, "static"},
		{"gopass ls stays static", "gopass ls", decisionAllow, "static"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := decide(cfg, tt.command, t.TempDir(), testLogger)
			if v.Decision != tt.decision || v.Tier != tt.tier {
				t.Fatalf("decide(%q) = (%q, %q), want (%q, %q)", tt.command, v.Decision, v.Tier, tt.decision, tt.tier)
			}
		})
	}
}

func TestAllowListWithoutDefaultsReplacesBuiltins(t *testing.T) {
	t.Parallel()
	cfg := &config{Permissions: permissionsConfig{Allow: []string{"just check"}}}
	if v := decide(cfg, "ls", t.TempDir(), testLogger); v.Decision != "" {
		t.Fatalf("ls should not be statically allowed when builtins are replaced, got %q", v.Decision)
	}
	if v := decide(cfg, "just check", t.TempDir(), testLogger); v.Decision != decisionAllow {
		t.Fatalf("just check should be allowed, got %q", v.Decision)
	}
}

func fakeJev(t *testing.T, answer jevAnswer) *config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing bearer auth")
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "jev-1.13.0",
			"answers": map[string]jevAnswer{"decision": answer},
		})
	}))
	t.Cleanup(srv.Close)
	prev := jevEndpoint
	jevEndpoint = srv.URL
	t.Cleanup(func() { jevEndpoint = prev })
	return &config{
		Jev: jevConfig{Model: "jev-test", KeyCmd: []string{"echo", "test-key"}},
	}
}

func TestJudgeVerdicts(t *testing.T) {
	tests := []struct {
		name     string
		answer   jevAnswer
		decision string
	}{
		{"confident allow", jevAnswer{Choice: "allow", Confidence: 0.98}, decisionAllow},
		{"low-confidence allow is silence", jevAnswer{Choice: "allow", Confidence: 0.60}, ""},
		{"ask passes through", jevAnswer{Choice: "ask", Confidence: 0.30}, decisionAsk},
		{"deny passes through", jevAnswer{Choice: "deny", Confidence: 0.90}, decisionDeny},
		{"defer is silence", jevAnswer{Choice: "defer", Confidence: 0.90}, ""},
		{"garbage is silence", jevAnswer{Choice: "banana", Confidence: 0.90}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := fakeJev(t, tt.answer)
			v := decide(cfg, "terraform plan", t.TempDir(), testLogger)
			if v.Decision != tt.decision {
				t.Fatalf("decision = %q, want %q", v.Decision, tt.decision)
			}
			if v.Tier != "judge" {
				t.Fatalf("tier = %q, want judge", v.Tier)
			}
		})
	}
}

func TestJudgeRecordsProbabilities(t *testing.T) {
	probs := map[string]float64{"allow": 0.94, "ask": 0.04, "deny": 0.01, "defer": 0.01}
	cfg := fakeJev(t, jevAnswer{Choice: "allow", Confidence: 0.94, Probabilities: probs})
	v := decide(cfg, "terraform plan", t.TempDir(), testLogger)
	if v.Decision != decisionAllow || v.Model != "jev-1.13.0" || v.Probabilities["allow"] != 0.94 {
		t.Fatalf("verdict = %+v", v)
	}

	var buf strings.Builder
	logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), v, "terraform plan")
	var rec struct {
		Probs map[string]float64 `json:"probs"`
		Model string             `json:"model"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
		t.Fatalf("log not JSON: %v: %s", err, buf.String())
	}
	if rec.Model != "jev-1.13.0" || rec.Probs["ask"] != 0.04 || len(rec.Probs) != 4 {
		t.Fatalf("log record = %s", buf.String())
	}
}

func TestJevUnreachableIsSilence(t *testing.T) {
	prev := jevEndpoint
	jevEndpoint = "http://127.0.0.1:1"
	t.Cleanup(func() { jevEndpoint = prev })
	cfg := &config{Jev: jevConfig{Model: "jev-test", KeyCmd: []string{"echo", "k"}, TimeoutMs: 200}}
	if v := decide(cfg, "terraform plan", t.TempDir(), testLogger); v.Decision != "" {
		t.Fatalf("unreachable jev must be silence, got %q", v.Decision)
	}
}

func TestProbeScript(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(resolved, "analyze.py")
	if writeErr := os.WriteFile(script, []byte("print('ok')\n"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}

	segments, _ := parseCommand("python3 analyze.py")
	probe, err := probeScript(segments, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if probe.Path != script || !strings.Contains(probe.Contents, "print") || len(probe.SHA) != 64 {
		t.Fatalf("probe = %+v", probe)
	}

	secret := filepath.Join(resolved, "leak.py")
	if err := os.WriteFile(secret, []byte("api_key = 'abcdefghij0123456789'\n"), 0o600); err != nil { // gitleaks:allow
		t.Fatal(err)
	}
	segments, _ = parseCommand("python3 leak.py")
	if _, probeErr := probeScript(segments, resolved); probeErr == nil {
		t.Fatal("credential-shaped script must not be sent")
	}

	segments, _ = parseCommand("git status")
	if probe, _ := probeScript(segments, resolved); probe.Path != "" {
		t.Fatalf("no script expected, got %q", probe.Path)
	}
}

func TestRunHookEndToEnd(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	input := `{"tool_name":"Bash","tool_input":{"command":"git status | head"},"cwd":"/tmp"}`
	var out strings.Builder
	if code := run([]string{"hook"}, strings.NewReader(input), &out); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	var resp map[string]map[string]string
	if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
		t.Fatalf("output not JSON: %v: %s", err, out.String())
	}
	if resp["hookSpecificOutput"]["permissionDecision"] != decisionAllow {
		t.Fatalf("want allow, got %s", out.String())
	}

	out.Reset()
	input = `{"tool_name":"Bash","tool_input":{"command":"terraform apply"},"cwd":"/tmp"}`
	if code := run([]string{"hook"}, strings.NewReader(input), &out); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if out.String() != "" {
		t.Fatalf("want silence, got %s", out.String())
	}

	out.Reset()
	if code := run([]string{"hook"}, strings.NewReader(`{"tool_name":"Edit"}`), &out); code != 0 || out.String() != "" {
		t.Fatalf("non-Bash must be silent, got %d %s", code, out.String())
	}
}

func TestBrokenConfigIsSilent(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := os.MkdirAll(filepath.Join(cfgDir, "frisk"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "frisk", "config.json"), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}

	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}`
	var out strings.Builder
	if code := run([]string{"hook"}, strings.NewReader(input), &out); code != 0 || out.String() != "" {
		t.Fatalf("broken config must be full silence, got %d %s", code, out.String())
	}
}
