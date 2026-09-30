//go:build eval

package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
// do not settle.
//
// Every run also writes the report plus one line per fixture to a file in the
// system temp dir, so piping the test output through tail loses nothing.

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

	saved := filepath.Join(os.TempDir(), "frisk-eval-"+run.mode+"-"+time.Now().Format("20060102T150405")+".txt")
	if err := os.WriteFile(saved, []byte(out.report+"\n"+fixtureLines(results)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Last on purpose: `just eval | tail -1` still shows the verdict and where the rest is.
	t.Logf("%s; full report: %s", out.summary, saved)
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
