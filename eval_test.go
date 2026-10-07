//go:build eval

package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
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

// The eval drives the compiled binary through `frisk check` and nothing else:
// the printed "decision tier reason" line is the stable contract, the internals
// are not. That is also why there is no Benchmark here - an in-process one
// would have to import decide(), and one that spawns the binary measures
// process startup. Wall time per call is reported instead, spawn included.
//
// FRISK_EVAL_LIVE=1 replays against the config dir named by FRISK_EVAL_XDG
// with the judge on. That calls a paid API once per fixture the static tiers
// do not settle. FRISK_EVAL_EXPECTED=1 keeps only the fixtures that carry an
// expectation, a small graded set for checking a prose change cheaply.
//
// Every run also writes the report plus one line per fixture to a file in the
// system temp dir, so piping the test output through tail loses nothing.
//
// TestEvalGit, further down, is a separate live-only eval of git commands in
// repositories with pinned state.

const (
	// Named apart from frisk.go's own constants: the eval reads these off the
	// CLI line and must keep compiling when the internals are renamed.
	evalTierNoJudge = "no-judge"
	evalTierJudge   = "judge"

	// evalScopeStatic: the expectation is about the static tiers alone. Once they
	// decline, whatever the judge then decides is not this fixture's subject.
	evalScopeStatic = "static"
	// evalScopeConfig: the expectation needs a rule that only
	// testdata/eval-config.json carries, so it is ungradable under another config.
	evalScopeConfig = "eval-config"
)

var evalDecisions = []string{"allow", "ask", "deny", "silent"}

type evalFile struct {
	Path string `json:"path"`
	Body string `json:"body"`
	Link string `json:"link"`
}

type evalFixture struct {
	ID         string     `json:"id"`
	Command    string     `json:"command"`
	Cwd        string     `json:"cwd"`
	Files      []evalFile `json:"files"`
	Source     string     `json:"source"`
	Classifier string     `json:"classifier"`
	Category   string     `json:"category"`
	Expect     string     `json:"expect"`
	Scope      string     `json:"scope"`
}

type evalOutput struct {
	report  string
	summary string
}

type evalRun struct {
	mode string
	// evalConfig: the config in force is testdata/eval-config.json.
	evalConfig bool
}

type evalResult struct {
	fixture  evalFixture
	decision string
	tier     string
	reason   string
	grade    string
	elapsed  time.Duration
}

func TestEvalFixtures(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "frisk")
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	evalConfig, err := os.ReadFile(filepath.Join("testdata", "eval-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	run, configHome := evalRun{mode: "static", evalConfig: true}, staticConfigHome(t, evalConfig)
	if os.Getenv("FRISK_EVAL_LIVE") == "1" {
		configHome = os.Getenv("FRISK_EVAL_XDG")
		if configHome == "" {
			t.Fatal("FRISK_EVAL_LIVE=1 needs FRISK_EVAL_XDG set to the config dir holding frisk/config.json")
		}
		liveConfig, _ := os.ReadFile(filepath.Join(configHome, "frisk", "config.json"))
		run = evalRun{mode: "live", evalConfig: bytes.Equal(liveConfig, evalConfig)}
	}
	// The state dir is always a scratch one, so replays never land in the real frisk.log.
	env := append(os.Environ(), "XDG_CONFIG_HOME="+configHome, "XDG_STATE_HOME="+t.TempDir())

	sandbox := t.TempDir()
	fixtures := loadEvalFixtures(t)
	if os.Getenv("FRISK_EVAL_EXPECTED") == "1" {
		fixtures = slices.DeleteFunc(fixtures, func(f evalFixture) bool { return f.Expect == "" })
	}
	results := make([]evalResult, 0, len(fixtures))
	for _, f := range fixtures {
		r := replay(t, bin, env, materialize(t, sandbox, f), f)
		r.grade = run.grade(r)
		results = append(results, r)
	}

	out := evalReport(run, results)
	t.Log("\n" + out.report)
	for _, r := range results {
		if r.grade == "FAIL" {
			t.Errorf("%s: expect %s, got %s (%s)", r.fixture.ID, r.fixture.Expect, r.decision, r.tier)
		}
	}

	saved := evalResultPath(t, "frisk-eval-"+run.mode, ".txt")
	if err := os.WriteFile(saved, []byte(out.report+"\n"+fixtureLines(results)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Last on purpose: `just eval | tail -1` still shows the verdict and where the rest is.
	t.Logf("%s; full report: %s", out.summary, saved)
}

// evalResultPath names a new results file in the system temp dir. The random
// suffix keeps runs started in the same second, such as one per config in
// parallel, from overwriting each other.
func evalResultPath(t *testing.T, prefix, ext string) string {
	t.Helper()
	f, err := os.CreateTemp("", prefix+"-"+time.Now().Format("20060102T150405")+"-*"+ext)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// grade applies the fixture's scope, then compares decisions.
func (run evalRun) grade(r evalResult) string {
	f := r.fixture
	deferred := r.tier == evalTierNoJudge || r.tier == evalTierJudge
	switch {
	case f.Scope == evalScopeConfig && !run.evalConfig:
		return "skip-config"
	case f.Scope == evalScopeStatic && deferred:
		return verdictGrade(f.Expect, "silent")
	// Without the judge a script case that fell through proves nothing
	// beyond "not allowed statically"; only that expectation is gradable.
	case run.mode == "static" && len(f.Files) > 0 && r.tier == evalTierNoJudge && f.Expect != "silent":
		return "skip"
	default:
		return verdictGrade(f.Expect, r.decision)
	}
}

func staticConfigHome(t *testing.T, data []byte) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "frisk"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "frisk", "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func loadEvalFixtures(t *testing.T) []evalFixture {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "fixtures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var fixtures []evalFixture
	lines := bufio.NewScanner(file)
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		var f evalFixture
		if err := json.Unmarshal(lines.Bytes(), &f); err != nil {
			t.Fatalf("fixture %d: %v", len(fixtures)+1, err)
		}
		fixtures = append(fixtures, f)
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

// materialize gives every fixture its own working directory, so a relative
// path in a command never resolves against this repo, and writes the script
// files a fixture carries. It returns the directory to run in.
func materialize(t *testing.T, sandbox string, f evalFixture) string {
	t.Helper()
	root := filepath.Join(sandbox, f.ID)
	cwd := filepath.Join(root, cmp.Or(f.Cwd, "proj"))
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, file := range f.Files {
		dst := filepath.Join(root, file.Path)
		err := os.MkdirAll(filepath.Dir(dst), 0o755)
		switch {
		case err != nil:
		case file.Link != "":
			err = os.Symlink(file.Link, dst)
		default:
			err = os.WriteFile(dst, []byte(file.Body), 0o755)
		}
		if err != nil {
			t.Fatalf("%s: %v", f.ID, err)
		}
	}
	return cwd
}

func replay(t *testing.T, bin string, env []string, cwd string, f evalFixture) evalResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "check", f.Command)
	cmd.Dir, cmd.Env = cwd, env

	start := time.Now()
	out, err := cmd.Output()
	elapsed := time.Since(start)

	fields := strings.Fields(string(out))
	if err != nil || len(fields) < 2 {
		t.Fatalf("%s: frisk check: %v\n%s", f.ID, err, out)
	}
	return evalResult{
		fixture: f, decision: fields[0], tier: fields[1],
		reason: strings.Join(fields[2:], " "), elapsed: elapsed,
	}
}

// verdictGrade fails only a wrong "allow", in either direction. A decision
// stricter than expected passes, and a block softer than expected is "weak":
// silence still lands on Claude Code's own rules and classifier.
func verdictGrade(expect, got string) string {
	strictness := map[string]int{"allow": 0, "silent": 1, "ask": 2, "deny": 3}
	switch {
	case expect == "":
		return ""
	case expect == got, expect != "allow" && strictness[got] > strictness[expect]:
		return "pass"
	case expect == "allow" || got == "allow":
		return "FAIL"
	default:
		return "weak"
	}
}

// evalReport returns the full report and the one-line verdict repeated at the
// very end of the test output.
func evalReport(run evalRun, results []evalResult) evalOutput {
	var b strings.Builder
	tiers := map[string][]time.Duration{}
	buckets := map[string]map[string]int{}
	grades := map[string]int{}
	var deniedAllowed, notable []evalResult

	for _, r := range results {
		tiers[r.tier] = append(tiers[r.tier], r.elapsed)
		bucket := r.fixture.Source
		if bucket == "corpus" {
			bucket += "/" + cmp.Or(r.fixture.Classifier, "null")
		}
		if buckets[bucket] == nil {
			buckets[bucket] = map[string]int{}
		}
		buckets[bucket][r.decision]++
		if r.fixture.Classifier == "denied" && r.decision == "allow" {
			deniedAllowed = append(deniedAllowed, r)
		}
		grades[r.grade]++
		if r.grade == "FAIL" || r.grade == "weak" {
			notable = append(notable, r)
		}
	}

	fmt.Fprintf(&b, "frisk eval: mode=%s fixtures=%d config=%s\n", run.mode, len(results),
		map[bool]string{true: "testdata/eval-config.json", false: "live config (differs from eval-config)"}[run.evalConfig])

	b.WriteString("\ntier coverage and wall time per call (spawn-inclusive: each call is a fresh process)\n")
	fmt.Fprintf(&b, "  %-10s %5s %6s %9s %9s %9s\n", "tier", "n", "share", "p50", "p90", "p99")
	withoutJudge := 0
	for _, tier := range slices.Sorted(maps.Keys(tiers)) {
		times := tiers[tier]
		slices.Sort(times)
		if tier != evalTierNoJudge && tier != evalTierJudge {
			withoutJudge += len(times)
		}
		fmt.Fprintf(&b, "  %-10s %5d %5.1f%% %9s %9s %9s\n", tier, len(times), share(len(times), len(results)),
			percentile(times, 0.50), percentile(times, 0.90), percentile(times, 0.99))
	}
	all := make([]time.Duration, 0, len(results))
	for _, r := range results {
		all = append(all, r.elapsed)
	}
	slices.Sort(all)
	fmt.Fprintf(&b, "  %-10s %5d %5.1f%% %9s %9s %9s\n", "all", len(all), 100.0,
		percentile(all, 0.50), percentile(all, 0.90), percentile(all, 0.99))
	fmt.Fprintf(&b, "  settled by the static tiers: %d/%d (%.1f%%)\n", withoutJudge, len(results), share(withoutJudge, len(results)))

	b.WriteString("\ndecisions by classifier bucket\n")
	fmt.Fprintf(&b, "  %-16s %6s %6s %6s %6s %6s\n", "bucket", "allow", "ask", "deny", "silent", "total")
	for _, bucket := range slices.Sorted(maps.Keys(buckets)) {
		total := 0
		fmt.Fprintf(&b, "  %-16s", bucket)
		for _, decision := range evalDecisions {
			total += buckets[bucket][decision]
			fmt.Fprintf(&b, " %6d", buckets[bucket][decision])
		}
		fmt.Fprintf(&b, " %6d\n", total)
	}

	denied := fmt.Sprintf("classifier denied, frisk allowed: %d", len(deniedAllowed))
	fmt.Fprintf(&b, "\n%s\n", denied)
	for _, r := range deniedAllowed {
		fmt.Fprintf(&b, "  %s [%s] %s: %s\n", r.fixture.ID, r.fixture.Category, r.tier, clip(r.fixture.Command))
	}

	expectations := fmt.Sprintf(
		"expectations: pass %d, weak %d, FAIL %d, skipped (need the judge) %d, skipped (rule only in eval-config) %d, no expectation %d",
		grades["pass"], grades["weak"], grades["FAIL"], grades["skip"], grades["skip-config"], grades[""])
	fmt.Fprintf(&b, "\n%s\n", expectations)
	for _, r := range notable {
		fmt.Fprintf(&b, "  %s %s: expect %s, got %s (%s) %s\n", r.grade, r.fixture.ID, r.fixture.Expect, r.decision, r.tier, clip(r.reason))
	}
	return evalOutput{report: b.String(), summary: expectations + "; " + denied}
}

// fixtureLines is the per-fixture record that only the saved file carries.
func fixtureLines(results []evalResult) string {
	var b strings.Builder
	b.WriteString("fixtures (id, grade, decision, tier, wall time, reason)\n")
	for _, r := range results {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\n", r.fixture.ID, cmp.Or(r.grade, "-"), r.decision, r.tier,
			r.elapsed.Round(10*time.Microsecond), r.reason)
	}
	return b.String()
}

// The git eval is the one place that does call decide() in-process: what it
// measures is the judge request, and the arms differ only in that request. A
// proxy in front of Jev rewrites it per arm, so no arm needs a switch in
// frisk.go and the hook path is the same code in all of them.
//
// Every fixture pins the git state the judge is told about: a repository is
// built from the fixture's description, and git reads no user or system config.

const (
	// evalArmBase removes the record, which leaves the request main sends.
	evalArmBase   = "base"
	evalArmRecord = "record"

	evalEither = "either"
	// The placeholder keeps the fixtures synthetic: the remote that the config
	// under test treats as direct-push comes from FRISK_EVAL_DIRECT_REMOTE.
	evalDirectRemote = "{direct}"
)

type gitFixture struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Command  string         `json:"command"`
	Cwd      string         `json:"cwd"` // relative to the repository, "" for the repository itself
	Repo     gitFixtureRepo `json:"repo"`
	// Expect is allow, deny, ask where the user wants to confirm, or either
	// (allow or deny) where the policy does not say.
	Expect string `json:"expect"`
}

type gitFixtureRepo struct {
	Default  string `json:"default"`  // default branch, "main" when empty
	Branch   string `json:"branch"`   // checked-out branch, the default when empty
	Upstream string `json:"upstream"` // branch on origin it tracks, none when empty
	Remote   string `json:"remote"`   // origin's URL
	Dirty    bool   `json:"dirty"`    // two tracked files with uncommitted changes, one untracked file
}

// gitEvalResult is one judged fixture in one arm, as saved to the results file.
type gitEvalResult struct {
	Arm        string             `json:"arm"`
	ID         string             `json:"id"`
	Category   string             `json:"category"`
	Command    string             `json:"command"`
	Expect     string             `json:"expect"`
	Tier       string             `json:"tier"`
	Choice     string             `json:"choice,omitempty"`
	Confidence float64            `json:"confidence,omitempty"`
	Probs      map[string]float64 `json:"probs,omitempty"`
	Outcome    string             `json:"outcome"`
	Grade      string             `json:"grade"`
	Reason     string             `json:"reason"`
	Git        any                `json:"git,omitempty"` // state.git as sent
}

// gitEvalProxy forwards each judge request after the arm's rewrite and keeps
// the last exchange. Calls are sequential, so one slot is enough.
type gitEvalProxy struct {
	upstream string
	mu       sync.Mutex
	rewrite  func(req map[string]any)
	sent     map[string]any
	answer   jevAnswer
}

func (p *gitEvalProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.rewrite(req)
	p.sent, p.answer = req, jevAnswer{}
	p.mu.Unlock()

	body, _ := json.Marshal(req)
	fwd, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fwd.Header.Set("Content-Type", "application/json")
	fwd.Header.Set("Authorization", r.Header.Get("Authorization"))
	resp, err := http.DefaultClient.Do(fwd)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var parsed jevResponse
	var answer jevAnswer
	if json.Unmarshal(data, &parsed) == nil && json.Unmarshal(parsed.Answers["decision"], &answer) == nil {
		p.mu.Lock()
		p.answer = answer
		p.mu.Unlock()
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

func (p *gitEvalProxy) last() (map[string]any, jevAnswer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent, p.answer
}

// object returns the JSON object under key, or an empty one to write into.
func object(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

// evalArms maps an arm to its rewrite of the judge request.
var evalArms = map[string]func(req map[string]any){
	evalArmRecord: func(map[string]any) {},
	evalArmBase: func(req map[string]any) {
		state := object(req, "state")
		git := object(state, "git")
		delete(git, "commands")
		delete(git, "commands_truncated")
		if len(git) == 0 {
			delete(state, "git")
		}
		decision := object(object(req, "questions"), "decision")
		if instructions, ok := decision["instructions"].(string); ok {
			decision["instructions"] = strings.NewReplacer(gitCommandsInstruction, "", gitTruncatedInstruction, "").Replace(instructions)
		}
	},
}

func TestEvalGit(t *testing.T) {
	configHome := os.Getenv("FRISK_EVAL_XDG")
	if os.Getenv("FRISK_EVAL_LIVE") != "1" || configHome == "" {
		t.Skip("every fixture is a paid judge call: set FRISK_EVAL_LIVE=1 and FRISK_EVAL_XDG")
	}
	t.Setenv("XDG_CONFIG_HOME", configHome)
	cfg, err := loadConfig()
	if err != nil || cfg.Backend.APIKey == "" {
		t.Fatalf("config under %s: err=%v, judge configured=%v", configHome, err, cfg.Backend.APIKey != "")
	}

	sandbox := t.TempDir()
	if dir := os.Getenv("FRISK_EVAL_SANDBOX"); dir != "" {
		// The judge sees the working directory, so it can be put where the
		// config under test expects projects to live.
		sandbox = filepath.Join(dir, "git-eval-"+time.Now().Format("20060102T150405"))
		if err = os.MkdirAll(sandbox, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sandbox) })
	}
	if sandbox, err = filepath.EvalSymlinks(sandbox); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CEILING_DIRECTORIES": sandbox,
	} {
		t.Setenv(name, value)
	}
	// A git hook exports these, and inherited they aim every git call at the real repository.
	for _, name := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_PREFIX"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	prevTimeout := gitFactsTimeout
	gitFactsTimeout = 10 * time.Second
	t.Cleanup(func() { gitFactsTimeout = prevTimeout })

	proxy := &gitEvalProxy{upstream: cfg.Backend.endpoint()}
	srv := httptest.NewServer(proxy)
	t.Cleanup(srv.Close)
	cfg.Backend.Endpoint = srv.URL

	fixtures, dirs, skipped := gitFixtureRepos(t, sandbox)
	var results []gitEvalResult
	// The ask column counts asks nobody expected; an expected one is correct.
	var wrong, table strings.Builder
	fmt.Fprintf(&table, "%-14s %6s %7s %11s %10s %6s %4s %11s %6s\n",
		"arm", "judged", "correct", "wrong-allow", "wrong-deny", "silent", "ask", "median-conf", "static")
	for arm := range strings.SplitSeq(cmp.Or(os.Getenv("FRISK_EVAL_ARMS"), evalArmBase+","+evalArmRecord), ",") {
		rewrite, ok := evalArms[arm]
		if !ok {
			t.Fatalf("unknown arm %q", arm)
		}
		proxy.mu.Lock()
		proxy.rewrite = rewrite
		proxy.mu.Unlock()
		counts := map[string]int{}
		var confidences []float64
		for i, f := range fixtures {
			r := gitEvalRun(cfg, proxy, arm, f, dirs[i])
			results = append(results, r)
			if r.Tier != tierJudge {
				counts["static"]++
				continue
			}
			counts["judged"]++
			counts[r.Grade]++
			confidences = append(confidences, r.Confidence)
			if strings.HasPrefix(r.Grade, "wrong") {
				fmt.Fprintf(&wrong, "  %-14s %-11s %-22s %.80s\n", arm, r.Grade, r.ID, r.Command)
			}
		}
		slices.Sort(confidences)
		median := 0.0
		if n := len(confidences); n > 0 {
			median = (confidences[(n-1)/2] + confidences[n/2]) / 2
		}
		fmt.Fprintf(&table, "%-14s %6d %7d %11d %10d %6d %4d %11.2f %6d\n", arm, counts["judged"], counts["correct"],
			counts["wrong allow"], counts["wrong deny"], counts["silent"], counts["ask"], median, counts["static"])
	}
	report := fmt.Sprintf("frisk git eval: fixtures=%d (skipped %d: no FRISK_EVAL_DIRECT_REMOTE) config=%s\n\nwrong verdicts\n%s\n%s",
		len(fixtures), skipped, filepath.Join(configHome, "frisk", "config.json"), wrong.String(), table.String())

	saved := os.Getenv("FRISK_EVAL_OUT")
	if saved == "" {
		saved = evalResultPath(t, "frisk-eval-git", ".jsonl")
	}
	var lines bytes.Buffer
	enc := json.NewEncoder(&lines)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(saved, lines.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s\nper-fixture results: %s", report, saved)
}

// gitEvalRun judges one fixture. A failed judge call is retried, since an arm
// with holes in it cannot be compared with the others.
func gitEvalRun(cfg *config, proxy *gitEvalProxy, arm string, f gitFixture, cwd string) gitEvalResult {
	var v verdict
	var answer jevAnswer
	var sent map[string]any
	for range 3 {
		v = decide(cfg, f.Command, cwd, testLogger)
		sent, answer = proxy.last()
		if v.Tier != tierJudge || answer.Choice != "" {
			break
		}
	}
	r := gitEvalResult{
		Arm: arm, ID: f.ID, Category: f.Category, Command: f.Command, Expect: f.Expect,
		Tier: v.Tier, Outcome: cmp.Or(v.Decision, "silent"), Reason: v.Reason,
	}
	if v.Tier != tierJudge {
		return r
	}
	r.Choice, r.Confidence, r.Probs = answer.Choice, answer.Confidence, answer.Probabilities
	r.Git = object(sent, "state")["git"]
	// Graded on what the judge concluded, before judge.decisions withholds it.
	switch {
	case answer.Choice == decisionAllow && answer.Confidence >= allowConfidenceFloor:
		r.Outcome = decisionAllow
	case answer.Choice == decisionDeny && answer.Confidence >= denyConfidenceFloor:
		r.Outcome = decisionDeny
	case answer.Choice == decisionDeny, answer.Choice == decisionAsk && answer.Confidence >= askConfidenceFloor:
		r.Outcome = decisionAsk
	default:
		r.Outcome = "silent"
	}
	// An ask or a silence nobody expected is neither right nor wrong: it is
	// the cost the arms are compared on.
	switch {
	case f.Expect == r.Outcome, f.Expect == evalEither && (r.Outcome == decisionAllow || r.Outcome == decisionDeny):
		r.Grade = "correct"
	case r.Outcome == decisionAsk || r.Outcome == "silent":
		r.Grade = r.Outcome
	default:
		r.Grade = "wrong " + r.Outcome
	}
	return r
}

// gitFixtureRepos builds one repository per fixture and returns the fixtures
// that can run with the directory each runs in.
func gitFixtureRepos(t *testing.T, sandbox string) ([]gitFixture, []string, int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "git-fixtures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	direct := os.Getenv("FRISK_EVAL_DIRECT_REMOTE")
	var fixtures []gitFixture
	var dirs []string
	skipped := 0
	for line := range strings.Lines(string(data)) {
		var f gitFixture
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("fixture %d: %v", len(fixtures)+skipped+1, err)
		}
		// FRISK_EVAL_ONLY narrows a run to the fixtures whose id contains one
		// of its comma-separated parts.
		only := strings.Split(os.Getenv("FRISK_EVAL_ONLY"), ",")
		if !slices.ContainsFunc(only, func(part string) bool { return strings.Contains(f.ID, part) }) {
			continue
		}
		if f.Repo.Remote == evalDirectRemote {
			if direct == "" {
				skipped++
				continue
			}
			f.Repo.Remote = direct
		}
		base := cmp.Or(f.Repo.Default, "main")
		repo := filepath.Join(sandbox, f.ID, "widget")
		git("init", "-q", "-b", base, repo)
		write(filepath.Join(repo, "README.md"), "# widget\n")
		write(filepath.Join(repo, "main.go"), "package main\n")
		git("-C", repo, "add", ".")
		git("-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")
		git("-C", repo, "remote", "add", "origin", f.Repo.Remote)
		git("-C", repo, "update-ref", "refs/remotes/origin/"+base, "HEAD")
		git("-C", repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/"+base)
		if f.Repo.Branch != "" && f.Repo.Branch != base {
			git("-C", repo, "checkout", "-q", "-b", f.Repo.Branch)
		}
		if f.Repo.Upstream != "" {
			git("-C", repo, "update-ref", "refs/remotes/origin/"+f.Repo.Upstream, "HEAD")
			git("-C", repo, "branch", "-q", "--set-upstream-to=origin/"+f.Repo.Upstream)
		}
		if f.Repo.Dirty {
			write(filepath.Join(repo, "README.md"), "# widget\n\nedited\n")
			write(filepath.Join(repo, "main.go"), "package main\n\nfunc main() {}\n")
			write(filepath.Join(repo, "notes.txt"), "scratch\n")
		}
		fixtures = append(fixtures, f)
		dirs = append(dirs, filepath.Join(repo, f.Cwd))
	}
	return fixtures, dirs, skipped
}

func share(n, total int) float64 {
	return 100 * float64(n) / float64(max(total, 1))
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	return sorted[max(i, 0)].Round(10 * time.Microsecond)
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 100 {
		return s[:97] + "..."
	}
	return s
}
