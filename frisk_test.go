package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
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
		{"awk print stays static", "awk '{print $1}' f.txt", decisionAllow, "static"},
		{"awk field separator stays static", "awk -F: '{print $1}' /etc/passwd", decisionAllow, "static"},
		{"awk system never static", `awk 'BEGIN{system("id")}'`, "", "no-judge"},
		{"awk pipe never static", `awk '{print | "sh"}' f.txt`, "", "no-judge"},
		{"awk program file never static", "awk -f prog.awk f.txt", "", "no-judge"},
		{"awk environ never static", `awk 'BEGIN{print ENVIRON["HOME"]}'`, "", "no-judge"},
		{"yq read stays static", "yq .a f.yaml", decisionAllow, "static"},
		{"yq in-place never static", "yq -i .a=1 f.yaml", "", "no-judge"},
		{"yq env never static", "yq '.a = strenv(X)' f.yaml", "", "no-judge"},
		{"jq env field stays static", "jq .spec.env f.json", decisionAllow, "static"},
		{"jq env dump never static", "jq -n env", "", "no-judge"},
		{"jq ENV never static", "jq -n '$ENV.HOME'", "", "no-judge"},
		{"tree depth stays static", "tree -L 2", decisionAllow, "static"},
		{"tree output file never static", "tree -o out.txt", "", "no-judge"},
		{"od stays static", "od -c f.bin", decisionAllow, "static"},
		{"strings stays static", "strings bin/app", decisionAllow, "static"},
		{"more stays static", "more README.md", decisionAllow, "static"},
		{"less log file never static", "less -o log f.txt", "", "no-judge"},
		{"sw_vers stays static", "sw_vers -productVersion", decisionAllow, "static"},
		{"find name stays static", "find . -name '*.go'", decisionAllow, "static"},
		{"find type stays static", "find . -type f -newer x", decisionAllow, "static"},
		{"find -fls never static", "find . -fls out", "", "no-judge"},
		{"find -fprint0 never static", "find . -fprint0 out", "", "no-judge"},
		{"find -exec never static", "find . -exec rm {} +", "", "no-judge"},
		{"git config get stays static", "git config --get user.name", decisionAllow, "static"},
		{"git config list stays static", "git config --list", decisionAllow, "static"},
		{"git -C config get stays static", "git -C repo config --get user.name", decisionAllow, "static"},
		{"git config set never static", "git config user.name x", "", "no-judge"},
		{"git config global set never static", "git config --global user.name x", "", "no-judge"},
		{"git stash show stays static", "git stash show -p", decisionAllow, "static"},
		{"git -C stash list stays static", "git -C repo stash list", decisionAllow, "static"},
		{"git stash pop never static", "git stash pop", "", "no-judge"},
		{"bare git tag stays static", "git tag", decisionAllow, "static"},
		{"git tag list stays static", "git tag -l 'v*'", decisionAllow, "static"},
		{"git tag create never static", "git tag v1.0", "", "no-judge"},
		{"git -C tag create never static", "git -C repo tag v2", "", "no-judge"},
		{"git tag delete never static", "git tag -d v1", "", "no-judge"},
		{"bare git reflog stays static", "git reflog", decisionAllow, "static"},
		{"git reflog show stays static", "git reflog show HEAD", decisionAllow, "static"},
		{"git reflog expire never static", "git reflog expire --all", "", "no-judge"},
		{"git notes list stays static", "git notes list", decisionAllow, "static"},
		{"git notes add never static", "git notes add -m x", "", "no-judge"},
		{"gh pr view stays static", "gh pr view 12", decisionAllow, "static"},
		{"gh pr list stays static", "gh pr list --state open", decisionAllow, "static"},
		{"gh run watch stays static", "gh run watch 1", decisionAllow, "static"},
		{"gh search stays static", "gh search repos frisk", decisionAllow, "static"},
		{"gh pr merge never static", "gh pr merge 12", "", "no-judge"},
		{"gh api never static", "gh api repos/x/y", "", "no-judge"},
		{"gh release create never static", "gh release create v1", "", "no-judge"},
		{"gh auth token never static", "gh auth token", "", "no-judge"},
		{"gh show-token never static", "gh auth status --show-token", "", "no-judge"},
		{"gh browser env never static", "GH_BROWSER=evil gh pr view --web", "", "no-judge"},
		{"sed w command never static", "sed -n 'w /tmp/copy.txt' README.md", "", "no-judge"},
		{"sed addressed w command never static", "sed -n '/err/w out.txt' app.log", "", "no-judge"},
		{"sed s w flag never static", "sed 's/a/b/w /tmp/out.txt' README.md", "", "no-judge"},
		{"sed s gw flag never static", "sed 's/a/b/gw out.txt' README.md", "", "no-judge"},
		{"sed e command never static", "sed '1e touch /tmp/pwned' README.md", "", "no-judge"},
		{"sed s e flag never static", "sed 's/x/date/e' README.md", "", "no-judge"},
		{"sed -e w command never static", "sed -n -e p -e 'w out.txt' README.md", "", "no-judge"},
		{"sed w after line-length never static", "sed -l 5 'w out.txt' README.md", "", "no-judge"},
		{"sed script file never static", "sed -f edit.sed README.md", "", "no-judge"},
		{"sed range print stays static", "sed -n 1,9p f", decisionAllow, "static"},
		{"sed word with w and e stays static", "sed 's/where/there/' f", decisionAllow, "static"},
		{"sed -e scripts stay static", "sed -n -e '/start/,/end/p' -e 's/a/b/g' f.txt", decisionAllow, "static"},
		{"sed delete and append stay static", "sed '/^#/d;$a done' f.txt", decisionAllow, "static"},
		{"git diff output never static", "git diff --output=/tmp/x.patch", "", "no-judge"},
		{"git log output never static", "git log -p --output=/tmp/log.txt", "", "no-judge"},
		{"git show abbreviated output never static", "git show --out=f HEAD", "", "no-judge"},
		{"git log oneline stays static", "git log --oneline -5", decisionAllow, "static"},
		{"git diff stat stays static", "git diff --stat HEAD~1", decisionAllow, "static"},
		{"less lesskey-src never static", "less --lesskey-src=/tmp/k README.md", "", "no-judge"},
		{"less lesskey-file never static", "less --lesskey-file /tmp/k README.md", "", "no-judge"},
		{"less -k never static", "less -k /tmp/k README.md", "", "no-judge"},
		{"less with flags stays static", "less -SN README.md", decisionAllow, "static"},
		{"kube config never static", "head -50 ~/.kube/config", "", "no-judge"},
		{"docker config never static", "cat ~/.docker/config.json", "", "no-judge"},
		{"gh hosts never static", "cat ~/.config/gh/hosts.yml", "", "no-judge"},
		{"git-credentials never static", "cat ~/.git-credentials", "", "no-judge"},
		{"pgpass never static", "cat ~/.pgpass", "", "no-judge"},
		{"my.cnf never static", "cat ~/.my.cnf", "", "no-judge"},
		{"cargo credentials never static", "cat ~/.cargo/credentials.toml", "", "no-judge"},
		{"kube glob never static", "head ~/.kube/conf*", "", "no-judge"},
		{"cargo manifest stays static", "cat Cargo.toml", decisionAllow, "static"},
		{"project config stays static", "cat config/app.json", decisionAllow, "static"},
		{"date set never static", "date -s '2020-01-01'", "", "no-judge"},
		{"date long set never static", "date --set=2020-01-01", "", "no-judge"},
		{"date bundled set never static", "date -us 2020-01-01", "", "no-judge"},
		{"date format stays static", "date +%Y-%m-%d", decisionAllow, "static"},
		{"date utc stays static", "date -u", decisionAllow, "static"},
		{"kubectl get secret never static", "kubectl get secret db -o yaml", "", "no-judge"},
		{"kubectl get secrets never static", "kubectl get secrets", "", "no-judge"},
		{"kubectl get secret by name never static", "kubectl -n prod get secret/db", "", "no-judge"},
		{"kubectl get secret in list never static", "kubectl get pods,secrets -A", "", "no-judge"},
		{"kubectl get pods stays static", "kubectl get pods", decisionAllow, "static"},
		{"kubectl describe secret stays static", "kubectl describe secret x", decisionAllow, "static"},
		{"kubectl get sealedsecrets stays static", "kubectl get sealedsecrets", decisionAllow, "static"},
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

// jevCapture records what the fake server received.
type jevCapture struct {
	mu    sync.Mutex
	calls int
	raw   string
	req   jevRequest
}

type jevRequest struct {
	State     jevState               `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevQuestion struct {
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria"`
}

// jevState is the request state as the judge sees it.
type jevState struct {
	Cwd       string            `json:"cwd"`
	Probe     *jevProbeState    `json:"probe"`
	Git       map[string]string `json:"git"`
	Untrusted jevUntrusted      `json:"untrusted"`
}

type jevProbeState struct {
	Status string `json:"status"`
}

type jevUntrusted struct {
	Command    string              `json:"command"`
	Script     string              `json:"script"`
	ScriptPath string              `json:"script_path"`
	ScriptSHA  string              `json:"script_sha256"`
	Scripts    []map[string]string `json:"scripts"`
}

func (c *jevCapture) last() (int, jevState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.req.State
}

func (c *jevCapture) request() (string, jevRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.raw, c.req
}

func fakeJev(t *testing.T, answer jevAnswer) *config {
	t.Helper()
	cfg, _ := fakeJevCapture(t, answer)
	return cfg
}

func fakeJevCapture(t *testing.T, answer jevAnswer) (*config, *jevCapture) {
	t.Helper()
	return fakeJevAnswers(t, map[string]any{"decision": answer})
}

// fakeJevAnswers serves the given answers verbatim, so a test can return
// attribution answers or malformed ones.
func fakeJevAnswers(t *testing.T, answers map[string]any) (*config, *jevCapture) {
	t.Helper()
	capture := &jevCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing bearer auth")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		var req jevRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("bad request body: %v", err)
		}
		capture.mu.Lock()
		capture.calls++
		capture.raw, capture.req = string(raw), req
		capture.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "jev-1.13.0",
			"answers": answers,
		})
	}))
	t.Cleanup(srv.Close)
	prev := jevEndpoint
	jevEndpoint = srv.URL
	t.Cleanup(func() { jevEndpoint = prev })
	return &config{
		Jev: jevConfig{Model: "jev-test", KeyCmd: []string{"echo", "test-key"}},
	}, capture
}

func TestJudgeVerdicts(t *testing.T) {
	tests := []struct {
		name     string
		answer   jevAnswer
		decision string
	}{
		{"confident allow", jevAnswer{Choice: "allow", Confidence: 0.98}, decisionAllow},
		{"low-confidence allow is silence", jevAnswer{Choice: "allow", Confidence: 0.60}, ""},
		{"ask passes through", jevAnswer{Choice: "ask", Confidence: 0.80}, decisionAsk},
		{"ask at the floor stays ask", jevAnswer{Choice: "ask", Confidence: 0.50}, decisionAsk},
		{"uncertain ask is silence", jevAnswer{Choice: "ask", Confidence: 0.49}, ""},
		{"deny passes through", jevAnswer{Choice: "deny", Confidence: 0.90}, decisionDeny},
		{"deny at the floor stays deny", jevAnswer{Choice: "deny", Confidence: 0.50}, decisionDeny},
		{"uncertain deny becomes ask, not silence", jevAnswer{Choice: "deny", Confidence: 0.40}, decisionAsk},
		{"allow floor is unchanged", jevAnswer{Choice: "allow", Confidence: 0.74}, ""},
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

func TestJudgeReasons(t *testing.T) {
	const pushRule = "Publishing packages or pushing to a shared branch without review, which others may already have pulled."
	softClosest := `closest rule: soft_deny "` + pushRule[:70] + `..." (0.71)`
	const hardClosest = `closest rule: hard_deny "Reading, printing, or transmitting credentials or secret material. Mod..." (0.80)`
	ask := jevAnswer{Choice: "ask", Confidence: 0.62}
	r1 := jevAnswer{Choice: "r1", Confidence: 0.80}
	tests := []struct {
		name     string
		command  string
		answers  map[string]any
		decision string
		reason   string
	}{
		{
			"split and closest rule", "terraform apply",
			map[string]any{
				"decision": jevAnswer{Choice: "ask", Confidence: 0.62, Probabilities: map[string]float64{"allow": 0.30, "ask": 0.62, "deny": 0.08}},
				"ask_rule": jevAnswer{Choice: "r2", Confidence: 0.71},
			},
			decisionAsk, "jev ask (allow 0.30 / ask 0.62 / deny 0.08); " + softClosest,
		},
		{"no closest rule without an answer", "terraform apply", map[string]any{"decision": ask}, decisionAsk, "jev ask (0.62)"},
		{
			"attribution none is omitted", "terraform apply",
			map[string]any{"decision": ask, "ask_rule": jevAnswer{Choice: "none", Confidence: 0.90}},
			decisionAsk, "jev ask (0.62)",
		},
		{
			"malformed attribution is ignored", "terraform apply",
			map[string]any{"decision": ask, "ask_rule": "banana", "deny_rule": 7},
			decisionAsk, "jev ask (0.62)",
		},
		{
			"unknown rule key is ignored", "terraform apply",
			map[string]any{"decision": ask, "ask_rule": jevAnswer{Choice: "r9", Confidence: 0.90}},
			decisionAsk, "jev ask (0.62)",
		},
		{
			"deny reads only the deny rule", "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "deny", Confidence: 0.90}, "ask_rule": jevAnswer{Choice: "r2", Confidence: 0.99}, "deny_rule": r1},
			decisionDeny, "jev deny (0.90); " + hardClosest,
		},
		{
			"downgraded deny keeps its rule", "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "deny", Confidence: 0.40}, "deny_rule": r1},
			decisionAsk, "jev deny below confidence floor (0.40), asking; " + hardClosest,
		},
		{
			"silenced ask names no rule", "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "ask", Confidence: 0.49}, "ask_rule": r1},
			"", "jev ask below confidence floor (0.49)",
		},
		{
			"floor form carries the split", "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "ask", Confidence: 0.47, Probabilities: map[string]float64{"allow": 0.44, "ask": 0.48, "deny": 0.07}}},
			"", "jev ask below confidence floor (0.47, allow 0.44 / ask 0.48 / deny 0.07)",
		},
		{
			"allow names no rule", "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "allow", Confidence: 0.98}, "ask_rule": r1, "deny_rule": r1},
			decisionAllow, "jev allow (0.98)",
		},
		{
			"missing script is named", "python3 nope.py",
			map[string]any{"decision": ask},
			decisionAsk, "jev ask (0.62); script nope.py not attached: missing",
		},
		{
			"script lost after cd is named", "cd $DIR && python3 build.py",
			map[string]any{"decision": ask},
			decisionAsk, "jev ask (0.62); script build.py not attached: unresolvable after cd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, capture := fakeJevAnswers(t, tt.answers)
			cfg.Judge.SoftDeny = []string{defaultsMarker, pushRule}
			v := decide(cfg, tt.command, t.TempDir(), testLogger)
			if v.Decision != tt.decision || v.Reason != tt.reason {
				t.Fatalf("verdict = (%q, %q), want (%q, %q)", v.Decision, v.Reason, tt.decision, tt.reason)
			}
			_, req := capture.request()
			wantAsk := map[string]string{"r1": builtinJudge.SoftDeny[0], "r2": pushRule, "none": "No rule fits."}
			wantDeny := map[string]string{"r1": builtinJudge.HardDeny[0], "none": "No rule fits."}
			if !maps.Equal(req.Questions["ask_rule"].Criteria, wantAsk) || !maps.Equal(req.Questions["deny_rule"].Criteria, wantDeny) {
				t.Fatalf("rule questions = %+v", req.Questions)
			}
		})
	}
}

func TestLogsAttribution(t *testing.T) {
	cfg, _ := fakeJevAnswers(t, map[string]any{
		"decision":  jevAnswer{Choice: "ask", Confidence: 0.62},
		"ask_rule":  jevAnswer{Choice: "r1", Confidence: 0.71},
		"deny_rule": jevAnswer{Choice: "none", Confidence: 0.93},
	})
	v := decide(cfg, "terraform apply", t.TempDir(), testLogger)

	var buf strings.Builder
	logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), v, "terraform apply")
	var rec struct {
		Reason   string  `json:"reason"`
		AskRule  string  `json:"ask_rule"`
		AskConf  float64 `json:"ask_rule_confidence"`
		DenyRule string  `json:"deny_rule"`
		DenyConf float64 `json:"deny_rule_confidence"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
		t.Fatalf("log not JSON: %v: %s", err, buf.String())
	}
	if rec.AskRule != "r1" || rec.AskConf != 0.71 || rec.DenyRule != "none" || rec.DenyConf != 0.93 || rec.Reason != v.Reason {
		t.Fatalf("log record = %s", buf.String())
	}
}

func TestJoinReason(t *testing.T) {
	t.Parallel()
	got := joinReason("jev ask\n(0.62)", "", strings.Repeat("x", 400))
	if strings.ContainsAny(got, "\n\r") || !strings.HasPrefix(got, "jev ask (0.62); xxx") {
		t.Fatalf("reason = %q", got)
	}
	if n := len([]rune(got)); n != maxReasonChars+3 || !strings.HasSuffix(got, "...") {
		t.Fatalf("reason length = %d, want capped at %d plus ellipsis", n, maxReasonChars)
	}
}

// gitRepo builds a repo on branch feature tracking origin/main, whose remote
// URL carries userinfo, and returns the directory above it.
func gitRepo(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CEILING_DIRECTORIES", root)
	repo := filepath.Join(root, "repo")
	steps := [][]string{
		{"init", "-q", "-b", "main", repo},
		{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init"},
		{"-C", repo, "remote", "add", "origin", "https://deploy:s3cretpass@github.com/owner/repo.git"}, // gitleaks:allow
		{"-C", repo, "update-ref", "refs/remotes/origin/main", "HEAD"},
		{"-C", repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"},
		{"-C", repo, "checkout", "-q", "-b", "feature"},
		{"-C", repo, "branch", "-q", "--set-upstream-to=origin/main"},
	}
	for _, args := range steps {
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return root
}

func TestGitFacts(t *testing.T) {
	root := gitRepo(t)
	prev := gitFactsTimeout
	gitFactsTimeout = 10 * time.Second
	t.Cleanup(func() { gitFactsTimeout = prev })

	facts := map[string]string{
		"branch": "feature", "upstream": "origin/main", "default_branch": "main", "remote": "github.com/owner/repo",
	}
	tests := []struct {
		name    string
		cwd     string
		command string
		want    map[string]string
	}{
		{"git command", "repo", "git push", facts},
		{"gh command", "repo", "gh pr create --fill", facts},
		{"wrapped git command", "repo", "time git push", facts},
		{"literal cd target", ".", "cd repo && git push", facts},
		{"git -C target", ".", "git -C repo push", facts},
		{"non-git command", "repo", "terraform plan", nil},
		{"outside a repo", ".", "git push", nil},
		{"unknown directory", "repo", "cd $DIR && git push", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.90})
			decide(cfg, tt.command, filepath.Join(root, tt.cwd), testLogger)
			raw, req := capture.request()
			if !maps.Equal(req.State.Git, tt.want) {
				t.Fatalf("git state = %v, want %v", req.State.Git, tt.want)
			}
			if strings.Contains(raw, "s3cretpass") || strings.Contains(raw, "deploy") {
				t.Fatalf("remote userinfo leaked into the request: %s", raw)
			}
			explained := strings.Contains(req.Questions["decision"].Instructions, "`git.upstream`")
			if explained != (tt.want != nil) || strings.Contains(raw, `"git":{}`) {
				t.Fatalf("git instruction present = %v, want %v", explained, tt.want != nil)
			}
		})
	}
}

func TestRemoteSlug(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  string
		want string
	}{
		{"https://deploy:s3cretpass@github.com/owner/repo.git", "github.com/owner/repo"}, // gitleaks:allow
		{"https://github.com/owner/repo", "github.com/owner/repo"},
		{"https://github.com/owner/repo.git?token=abc", "github.com/owner/repo"},
		{"git@github.com:owner/repo.git", "github.com/owner/repo"},
		{"ssh://git@gitlab.example.com:2222/group/sub/repo.git", "gitlab.example.com/group/sub/repo"},
		{"/srv/git/repo.git", ""},
		{"../sibling/repo", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := remoteSlug(tt.raw); got != tt.want {
			t.Errorf("remoteSlug(%q) = %q, want %q", tt.raw, got, tt.want)
		}
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

// probeFixture lays out scripts, decoys, symlinks, and credential-shaped
// files, and returns the symlink-resolved root.
func probeFixture(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	filler := strings.Repeat("x = 1\n", 20<<10/6)
	files := map[string]string{
		"proj/stats.py":     "print('ok')\n",
		"proj/smoke.sh":     "#!/usr/bin/env bash\necho smoke\n",
		"proj/app.js":       "console.log(1)\n",
		"proj/teardown":     "#!/usr/bin/env bash\nrm -rf build\n",
		"proj/tool.ts":      "#!/usr/bin/env -S node22 --no-warnings\nconsole.log(1)\n",
		"proj/blob":         "\x7fELF\x02\x01\x01",
		"proj/decoy.py":     "print('decoy')\n",
		"proj/sub/stats.py": "print('sub')\n",
		"proj/big.py":       strings.Repeat("x = 1\n", maxScriptBytes/6+1),
		"proj/half1.py":     filler,
		"proj/half2.py":     filler + "y = 2\n",
		"proj/latin.py":     "# caf\xe9\nprint(1)\n",
		"proj/paths.py":     "ROOT = '/Users/someone/Projects/example/scripts/tools/helpers'\n",
		"outside/.netrc":    "machine example.com\n",
		"outside/netrc":     "machine api.example.com\n  login deploy\n  password hunter2hunter2\n", // gitleaks:allow
		"proj/keyed.py":     "api_key = 'abcdefghij0123456789'\n",                                   // gitleaks:allow
		"proj/dsn.py":       "URL = 'postgres://admin:S3cr3tP4ss@db.internal:5432/app'\n",           // gitleaks:allow
		"proj/oneline.py":   "# machine api.example.com login deploy password hunter2\n",            // gitleaks:allow
		"proj/aws.py":       "aws_secret_access_key = wJalr\n",                                      // gitleaks:allow
		"proj/hex.py":       "DIGEST = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'\n",
		"proj/b64.py":       "BLOB = 'aW1wb3J0IHNodXRpbCwgb3MKc2h1dGlsLnJtdHJlZShvcy5wYXRoLmV4cGFuZHVzZXIoIn4vLmNvbmZpZyIpKQ=='\n", // gitleaks:allow
	}
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{"proj/link_path.py": "../outside/.netrc", "proj/link_content.py": "../outside/netrc"}
	for rel, target := range links {
		if err := os.Symlink(target, filepath.Join(root, rel)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestProbeScripts(t *testing.T) {
	t.Parallel()
	root := probeFixture(t)
	tests := []struct {
		name    string
		cwd     string
		command string
		status  string
		paths   []string
	}{
		{"plain interpreter", "proj", "python3 stats.py", probeAttached, []string{"proj/stats.py"}},
		{"no script", "proj", "git status", "", nil},
		{"stacked wrappers", "proj", "time uv run python stats.py", probeAttached, []string{"proj/stats.py"}},
		{"timeout wrapper", "proj", "timeout 120 bash smoke.sh", probeAttached, []string{"proj/smoke.sh"}},
		{"timeout with signal flag", "proj", "timeout -s KILL 5 bash smoke.sh", probeAttached, []string{"proj/smoke.sh"}},
		{"redirect and pipe after script", "proj", "timeout 120 bash smoke.sh 2>&1 | tail -20", probeAttached, []string{"proj/smoke.sh"}},
		{"env nice nohup", "proj", "env FOO=1 nice -n 5 nohup python3 stats.py", probeAttached, []string{"proj/stats.py"}},
		{"exec wrapper", "proj", "exec python3 stats.py", probeAttached, []string{"proj/stats.py"}},
		{"uv run script file", "proj", "uv run --with rich stats.py", probeAttached, []string{"proj/stats.py"}},
		{"uvx wrapper", "proj", "uvx --from tools python stats.py", probeAttached, []string{"proj/stats.py"}},
		{"env chdir is unresolvable", "proj", "env -C sub python3 stats.py", probeUnresolvable, nil},
		{"uv directory is unresolvable", "proj", "uv run --directory sub python stats.py", probeUnresolvable, nil},
		{"versioned python", "proj", "python3.12 stats.py", probeAttached, []string{"proj/stats.py"}},
		{"versioned node", "proj", "node22 app.js", probeAttached, []string{"proj/app.js"}},
		{"extensionless shebang", "proj", "./teardown", probeAttached, []string{"proj/teardown"}},
		{"unknown extension shebang", "proj", "./tool.ts", probeAttached, []string{"proj/tool.ts"}},
		{"binary is not a script", "proj", "./blob", "", nil},
		{"flag value skipped", "proj", "python3 -W ignore stats.py", probeAttached, []string{"proj/stats.py"}},
		{"attached flag value skipped", "proj", "python3 -Wignore -u stats.py", probeAttached, []string{"proj/stats.py"}},
		{"node require skipped", "proj", "node -r dotenv/config app.js", probeAttached, []string{"proj/app.js"}},
		{"bash option value skipped", "proj", "bash -euo pipefail smoke.sh", probeAttached, []string{"proj/smoke.sh"}},
		{"python -c has no file", "proj", "python3 -c 'print(1)' stats.py", "", nil},
		{"python -m has no file", "proj", "python3 -m http.server", "", nil},
		{"python stdin has no file", "proj", "python3 - stats.py", "", nil},
		{"bash -c has no file", "proj", "bash -ec 'echo hi'", "", nil},
		{"node -e has no file", "proj", "node -e 'console.log(1)'", "", nil},
		{"cd then relative", "proj", "cd sub && python3 stats.py", probeAttached, []string{"proj/sub/stats.py"}},
		{"cd never falls back to cwd", "proj", "cd sub && python3 decoy.py", probeMissing, nil},
		{"cd variable is unresolvable", "proj", "cd $DIR && python3 stats.py", probeUnresolvable, nil},
		{"subshell cd is unresolvable", "proj", "(cd sub && python3 stats.py)", probeUnresolvable, nil},
		{"absolute path survives unknown cd", "proj", "cd $DIR && python3 {root}/proj/stats.py", probeAttached, []string{"proj/stats.py"}},
		{"variable target is unresolvable", "proj", "python3 $SCRIPT", probeUnresolvable, nil},
		{"bare script name is unresolvable", "proj", "smoke.sh", probeUnresolvable, nil},
		{"missing script", "proj", "python3 nope.py", probeMissing, nil},
		{"every script is probed", "proj", "python3 stats.py && bash smoke.sh", probeAttached, []string{"proj/stats.py", "proj/smoke.sh"}},
		{"repeated script sent once", "proj", "python3 stats.py; python3 stats.py", probeAttached, []string{"proj/stats.py"}},
		{"one missing among several", "proj", "python3 stats.py && bash nope.sh", probeMissing, []string{"proj/stats.py"}},
		{"combined cap truncates", "proj", "python3 half1.py && python3 half2.py", probeTruncated, []string{"proj/half1.py"}},
		{"oversize", "proj", "python3 big.py", probeOversize, nil},
		{"non-utf8", "proj", "python3 latin.py", probeNonUTF8, nil},
		{"symlink to credential path", "proj", "python3 link_path.py", probeWithheld, nil},
		{"symlink to credential content", "proj", "python3 link_content.py", probeWithheld, nil},
		{"withheld wins over attached", "proj", "python3 stats.py && python3 keyed.py", probeWithheld, []string{"proj/stats.py"}},
		{"key assignment withheld", "proj", "python3 keyed.py", probeWithheld, nil},
		{"url userinfo withheld", "proj", "python3 dsn.py", probeWithheld, nil},
		{"netrc line withheld", "proj", "python3 oneline.py", probeWithheld, nil},
		{"aws secret withheld", "proj", "python3 aws.py", probeWithheld, nil},
		{"long hex withheld", "proj", "python3 hex.py", probeWithheld, nil},
		{"long base64 withheld", "proj", "python3 b64.py", probeWithheld, nil},
		{"long path is not a secret", "proj", "python3 paths.py", probeAttached, []string{"proj/paths.py"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			segments, _ := parseCommand(strings.ReplaceAll(tt.command, "{root}", root))
			res := probeScripts(segments, filepath.Join(root, tt.cwd))
			if res.Status != tt.status {
				t.Fatalf("status = %q, want %q", res.Status, tt.status)
			}
			var got []string
			for _, s := range res.Scripts {
				rel, _ := filepath.Rel(root, s.Path)
				got = append(got, rel)
				if len(s.SHA) != 64 || s.Contents == "" {
					t.Fatalf("incomplete probe: %+v", s)
				}
			}
			if !slices.Equal(got, tt.paths) {
				t.Fatalf("scripts = %v, want %v", got, tt.paths)
			}
		})
	}
}

func TestJudgeState(t *testing.T) {
	root := probeFixture(t)
	cwd := filepath.Join(root, "proj")
	tests := []struct {
		name    string
		command string
		called  bool
		status  string // "" means no probe field
		scripts int
	}{
		{"single script keeps flat fields", "python3 stats.py", true, probeAttached, 1},
		{"several scripts ride as an array", "python3 stats.py && bash smoke.sh", true, probeAttached, 2},
		{"missing body is explained", "python3 nope.py", true, probeMissing, 0},
		{"oversize body is explained", "python3 big.py", true, probeOversize, 0},
		{"no script has no probe field", "terraform plan", true, "", 0},
		{"credential-shaped script never reaches the judge", "python3 keyed.py", false, probeWithheld, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "allow", Confidence: 0.98})
			v := decide(cfg, tt.command, cwd, testLogger)
			calls, state := capture.last()
			if (calls == 1) != tt.called {
				t.Fatalf("judge calls = %d, want called=%v", calls, tt.called)
			}
			if v.Probe != tt.status || v.Scripts != tt.scripts {
				t.Fatalf("verdict probe = (%q, %d), want (%q, %d)", v.Probe, v.Scripts, tt.status, tt.scripts)
			}

			var buf strings.Builder
			logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), v, tt.command)
			var rec struct {
				Probe   string `json:"probe"`
				Scripts *int   `json:"scripts"`
			}
			if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
				t.Fatalf("log not JSON: %v: %s", err, buf.String())
			}
			wantLogged := tt.status
			if wantLogged == "" {
				wantLogged = "none"
			}
			if rec.Probe != wantLogged || rec.Scripts == nil || *rec.Scripts != tt.scripts {
				t.Fatalf("log record = %s", buf.String())
			}
			if !tt.called {
				if v.Decision != "" {
					t.Fatalf("withheld script must be silence, got %q", v.Decision)
				}
				return
			}

			if state.Cwd != cwd {
				t.Fatalf("state cwd = %q, want %q", state.Cwd, cwd)
			}
			if (state.Probe != nil) != (tt.status != "") || (state.Probe != nil && state.Probe.Status != tt.status) {
				t.Fatalf("state probe = %+v, want status %q", state.Probe, tt.status)
			}
			u := state.Untrusted
			if u.Command != tt.command {
				t.Fatalf("untrusted command = %q", u.Command)
			}
			flat := u.Script != "" && u.ScriptPath != "" && len(u.ScriptSHA) == 64
			if flat != (tt.scripts == 1) || (tt.scripts > 1 && len(u.Scripts) != tt.scripts) || (tt.scripts <= 1 && u.Scripts != nil) {
				t.Fatalf("untrusted scripts = flat %v, array %d, want %d", flat, len(u.Scripts), tt.scripts)
			}
			for _, entry := range u.Scripts {
				if entry["path"] == "" || len(entry["sha256"]) != 64 || entry["contents"] == "" || len(entry) != 3 {
					t.Fatalf("script entry = %v", entry)
				}
			}
		})
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
