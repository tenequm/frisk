package main

import (
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

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
	// A git hook exports GIT_DIR and friends. Inherited, they aim every git call
	// below at the real repository: init flips it to bare and commit lands on it.
	for _, v := range []string{
		"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_PREFIX",
		"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
	} {
		t.Setenv(v, "") // registers the restore; git reads an empty GIT_DIR as set
		if err := os.Unsetenv(v); err != nil {
			t.Fatal(err)
		}
	}
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
		{"git -C variable", ".", `R={root}/repo; git -C "$R" push`, facts},
		{"cd variable then git", ".", "R={root}/repo; cd $R && git push", facts},
		{"git -C reassigned variable", ".", "R={root}/repo; R=/elsewhere; git -C $R push", nil},
		{"non-git command", "repo", "terraform plan", nil},
		{"outside a repo", ".", "git push", nil},
		{"unknown directory", "repo", "cd $DIR && git push", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.90})
			decide(cfg, strings.ReplaceAll(tt.command, "{root}", root), filepath.Join(root, tt.cwd), testLogger)
			raw, req := capture.request()
			facts := map[string]string{}
			for name, value := range req.State.Git {
				if s, ok := value.(string); ok {
					facts[name] = s
				}
			}
			if !maps.Equal(facts, tt.want) {
				t.Fatalf("git state = %v, want %v", req.State.Git, tt.want)
			}
			if strings.Contains(raw, "s3cretpass") || strings.Contains(raw, "deploy:") {
				t.Fatalf("remote userinfo leaked into the request: %s", raw)
			}
			explained := strings.Contains(req.Questions["decision"].Instructions, "`git.upstream`")
			if explained != (tt.want != nil) || strings.Contains(raw, `"git":{}`) {
				t.Fatalf("git instruction present = %v, want %v", explained, tt.want != nil)
			}
		})
	}
}

// gitDo runs git in the hermetic environment gitRepo set up.
func gitDo(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// gitRepos adds to gitRepo one staged, one untracked and one ignored file in
// repo, a branch topic that exists only on origin, and a clean second
// repository "other" on its default branch trunk.
func gitRepos(t *testing.T) string {
	t.Helper()
	root := gitRepo(t)
	repo, other := filepath.Join(root, "repo"), filepath.Join(root, "other")
	if err := os.WriteFile(filepath.Join(repo, ".git", "info", "exclude"), []byte("*.log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"staged.txt", "untracked.txt", "debug.log"} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"-C", repo, "add", "staged.txt"},
		{"-C", repo, "update-ref", "refs/remotes/origin/topic", "HEAD"},
		{"init", "-q", "-b", "trunk", other},
		{"-C", other, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "other"},
		{"-C", other, "remote", "add", "origin", "git@git.example.com:team/other.git"},
		{"-C", other, "update-ref", "refs/remotes/origin/trunk", "HEAD"},
		{"-C", other, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk"},
		{"-C", repo, "fetch", "-q", other, "trunk:pr/7"},
		{"-C", repo, "branch", "-q", "merged", "main"},
	} {
		gitDo(t, args...)
	}
	return root
}

func TestGitRecords(t *testing.T) {
	root := gitRepos(t)
	prev := gitFactsTimeout
	gitFactsTimeout = 10 * time.Second
	t.Cleanup(func() { gitFactsTimeout = prev })

	tests := []struct {
		name    string
		command string
		want    string // state.git.commands as JSON, "" when the field is absent
		logged  string
	}{
		{
			"push to the default branch", "git push origin main",
			`[{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"yes","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"push of a topic branch", "git push -u origin feature",
			`[{"class":"remote","deletes_ref":false,"destination":"feature","destination_is_default":"no","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"forced push", "git push --force origin feature",
			`[{"class":"remote","deletes_ref":false,"destination":"feature","destination_is_default":"no","forced":true,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"push with no arguments goes to the upstream", "git push",
			`[{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"yes","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"push of HEAD goes to the current branch", "git push origin HEAD",
			`[{"class":"remote","deletes_ref":false,"destination":"feature","destination_is_default":"no","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"push to a remote without the upstream has no known destination", "git push elsewhere",
			`[{"class":"remote","deletes_ref":false,"destination":"unknown","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"push to a URL names it from the words", "git push https://example.com/o/r.git main",
			`[{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"unknown","forced":false,"remote":"example.com/o/r","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"push deleting a ref", "git push origin :old",
			`[{"class":"remote","deletes_ref":true,"destination":"old","destination_is_default":"no","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"push of every branch", "git push --all origin",
			`[{"class":"remote","deletes_ref":false,"destination":"unknown","destination_is_default":"unknown","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"discard with a dirty tree", "git reset --hard",
			`[{"class":"discard","state":"current","subcommand":"reset","uncommitted_files":1,"untracked_files":1}]`,
			"reset:discard",
		},
		{
			"clean -x also counts ignored files", "git clean -fdx",
			`[{"class":"discard","forced":true,"ignored_files":1,"state":"current","subcommand":"clean","uncommitted_files":1,"untracked_files":1}]`,
			"clean:discard",
		},
		{
			"clean -X counts ignored files", "git clean -f -X",
			`[{"class":"discard","forced":true,"ignored_files":1,"state":"current","subcommand":"clean","uncommitted_files":1,"untracked_files":1}]`,
			"clean:discard",
		},
		{
			"a dry run of clean -x stays a read", "git clean -nx",
			`[{"class":"read","state":"current","subcommand":"clean"}]`,
			"clean:read",
		},
		{
			"discard with a clean tree", "git -C ../other clean -fd",
			`[{"class":"discard","forced":true,"state":"current","subcommand":"clean","uncommitted_files":0,"untracked_files":0}]`,
			"clean:discard",
		},
		{
			"-C to another repository", "git -C ../other push origin trunk",
			`[{"class":"remote","deletes_ref":false,"destination":"trunk","destination_is_default":"yes","forced":false,"remote":"git.example.com/team/other","state":"current","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"a push that names its remote and branch does not go by the checked-out branch", "git switch -c x && git push -u origin x",
			`[{"class":"local","state":"current","subcommand":"switch"},` +
				`{"class":"remote","deletes_ref":false,"destination":"x","destination_is_default":"no","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"switch:local,push:remote",
		},
		{
			"a push that goes by the checked-out branch is unknown once it may have moved", "git switch main && git push",
			`[{"class":"local","state":"current","subcommand":"switch"},` +
				`{"class":"remote","deletes_ref":false,"destination":"unknown","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"switch:local,push:remote",
		},
		{
			"a push of HEAD is unknown once the branch may have moved", "git switch -c x && git push -u origin HEAD",
			`[{"class":"local","state":"current","subcommand":"switch"},` +
				`{"class":"remote","deletes_ref":false,"destination":"unknown","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"switch:local,push:remote",
		},
		{
			"a changed remote makes a push's facts unknown", "git remote set-url origin https://example.com/o/r.git && git push origin main",
			`[{"class":"remote","deletes_ref":false,"forced":false,"state":"current","subcommand":"remote"},` +
				`{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"remote:remote,push:remote",
		},
		{
			"a read leaves the state current", "git --no-pager log -1 && git push origin main",
			`[{"class":"read","state":"current","subcommand":"log"},` +
				`{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"yes","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"log:read,push:remote",
		},
		{
			"state is unknown after a cd that cannot be followed", "cd $DIR && git reset --hard && git push origin main",
			`[{"class":"discard","state":"unknown","subcommand":"reset","uncommitted_files":"unknown","untracked_files":"unknown"},` +
				`{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"reset:discard,push:remote",
		},
		{
			"--git-dir aims at another repository", "git --git-dir=../other/.git push origin trunk",
			`[{"class":"remote","deletes_ref":false,"destination":"trunk","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"push:remote",
		},
		{
			"GIT_DIR aims at another repository", "GIT_DIR=../other/.git git reset --hard",
			`[{"class":"discard","state":"unknown","subcommand":"reset","uncommitted_files":"unknown","untracked_files":"unknown"}]`,
			"reset:discard",
		},
		{
			"config override", "git -c core.hooksPath=/dev/null commit -m x",
			`[{"class":"exec","config_override":true,"state":"current","subcommand":"commit"}]`,
			"commit:exec",
		},
		{
			"amend that skips hooks", "git commit --amend --no-verify -m x",
			`[{"amend":true,"class":"local","no_verify":true,"state":"current","subcommand":"commit"}]`,
			"commit:local",
		},
		{
			"alias", "git co main",
			`[{"class":"unknown","state":"current","subcommand":"co"}]`,
			"co:unknown",
		},
		{
			"more git commands than the cap", "git add a; git add b; git add c; git add d; git add e; git add f",
			`[{"class":"local","state":"current","subcommand":"add"}` +
				strings.Repeat(`,{"class":"local","state":"current","subcommand":"add"}`, maxGitCommands-1) + `]`,
			"add:local,add:local,add:local,add:local,add:local",
		},
		{
			"add and commit leave a push's facts current", "git add -A && git commit -m x && git push",
			`[{"class":"local","state":"current","subcommand":"add"},{"class":"local","state":"current","subcommand":"commit"},` +
				`{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"yes","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"add:local,commit:local,push:remote",
		},
		{
			"commit leaves the current branch in place", "git commit -m x && git push origin HEAD",
			`[{"class":"local","state":"current","subcommand":"commit"},` +
				`{"class":"remote","deletes_ref":false,"destination":"feature","destination_is_default":"no","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"commit:local,push:remote",
		},
		{
			"a new upstream makes a push's facts unknown", "git branch -u origin/other && git push",
			`[{"class":"local","state":"current","subcommand":"branch"},` +
				`{"class":"remote","deletes_ref":false,"destination":"unknown","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"branch:local,push:remote",
		},
		{
			"an unknown command makes a push's facts unknown", "git co main && git push origin main",
			`[{"class":"unknown","state":"current","subcommand":"co"},` +
				`{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"co:unknown,push:remote",
		},
		{
			"a stash makes a discard's counts unknown", "git stash && git reset --hard",
			`[{"class":"local","state":"current","subcommand":"stash"},` +
				`{"class":"discard","state":"unknown","subcommand":"reset","uncommitted_files":"unknown","untracked_files":"unknown"}]`,
			"stash:local,reset:discard",
		},
		{
			"a cd leaves a discard's counts current", "cd ../repo && git reset --hard",
			`[{"class":"discard","state":"current","subcommand":"reset","uncommitted_files":1,"untracked_files":1}]`,
			"reset:discard",
		},
		{
			"a git read leaves a discard's counts current", "git status && git reset --hard",
			`[{"class":"read","state":"current","subcommand":"status"},` +
				`{"class":"discard","state":"current","subcommand":"reset","uncommitted_files":1,"untracked_files":1}]`,
			"status:read,reset:discard",
		},
		{
			"a write before a discard makes its counts unknown", "echo x > f && git reset --hard",
			`[{"class":"discard","state":"unknown","subcommand":"reset","uncommitted_files":"unknown","untracked_files":"unknown"}]`,
			"reset:discard",
		},
		{
			"a deleted branch last set by a fetch", "git branch -D pr/7",
			`[{"class":"local","deleted_refs":[{"ref":"refs/heads/pr/7","tip_fetched":true,"unique_commits":1}],"state":"current","subcommand":"branch"}]`,
			"branch:local",
		},
		{
			"a deleted branch whose commits other refs hold", "git branch -d merged",
			`[{"class":"local","deleted_refs":[{"ref":"refs/heads/merged","unique_commits":0}],"state":"current","subcommand":"branch"}]`,
			"branch:local",
		},
		{
			"refs deleted together do not hold each other's commits", "git branch -D pr/7 merged main",
			`[{"class":"local","deleted_refs":[{"ref":"refs/heads/pr/7","tip_fetched":true,"unique_commits":1},` +
				`{"ref":"refs/heads/merged","unique_commits":0},{"ref":"refs/heads/main","unique_commits":0}],"state":"current","subcommand":"branch"}]`,
			"branch:local",
		},
		{
			"a missing ref leaves its count unknown", "git tag -d v9",
			`[{"class":"local","deleted_refs":[{"ref":"refs/tags/v9","unique_commits":"unknown"}],"state":"current","subcommand":"tag"}]`,
			"tag:local",
		},
		{
			"a remote-tracking deletion names refs/remotes", "git branch -d -r origin/topic",
			`[{"class":"local","deleted_refs":[{"ref":"refs/remotes/origin/topic","unique_commits":0}],"state":"current","subcommand":"branch"}]`,
			"branch:local",
		},
		{
			"a commit before a deletion makes its facts unknown", "git commit -m x && git branch -D pr/7",
			`[{"class":"local","state":"current","subcommand":"commit"},` +
				`{"class":"local","deleted_refs":[{"ref":"refs/heads/pr/7","unique_commits":"unknown"}],"state":"unknown","subcommand":"branch"}]`,
			"commit:local,branch:local",
		},
		{
			"a new file before a clean makes its counts unknown", "touch n && git clean -fd",
			`[{"class":"discard","forced":true,"state":"unknown","subcommand":"clean","uncommitted_files":"unknown","untracked_files":"unknown"}]`,
			"clean:discard",
		},
		{
			"any other command before a discard makes its counts unknown", "make build; git checkout -- .",
			`[{"class":"discard","state":"unknown","subcommand":"checkout","uncommitted_files":"unknown","untracked_files":"unknown"}]`,
			"checkout:discard",
		},
		{
			"a redirected git read makes a discard's counts unknown", "git status > out.txt && git reset --hard",
			`[{"class":"read","state":"current","subcommand":"status"},` +
				`{"class":"discard","state":"unknown","subcommand":"reset","uncommitted_files":"unknown","untracked_files":"unknown"}]`,
			"status:read,reset:discard",
		},
		{
			"a push's facts survive a discard, the counts do not survive a push", "git reset --hard && git push origin main && git clean -fd",
			`[{"class":"discard","state":"current","subcommand":"reset","uncommitted_files":1,"untracked_files":1},` +
				`{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"yes","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"},` +
				`{"class":"discard","forced":true,"state":"unknown","subcommand":"clean","uncommitted_files":"unknown","untracked_files":"unknown"}]`,
			"reset:discard,push:remote,clean:discard",
		},
		{
			"checkout of a local branch is local", "git checkout main",
			`[{"class":"local","state":"current","subcommand":"checkout"}]`,
			"checkout:local",
		},
		{
			"checkout of a branch on exactly one remote is local", "git checkout topic",
			`[{"class":"local","state":"current","subcommand":"checkout"}]`,
			"checkout:local",
		},
		{
			"checkout of a path is a discard", "git checkout staged.txt",
			`[{"class":"discard","state":"current","subcommand":"checkout","uncommitted_files":1,"untracked_files":1}]`,
			"checkout:discard",
		},
		{
			"checkout of neither a branch nor a path stays unknown", "git checkout nothing",
			`[{"class":"unknown","state":"current","subcommand":"checkout"}]`,
			"checkout:unknown",
		},
		{
			"checkout in a directory that does not resolve stays unknown", "cd $DIR && git checkout main",
			`[{"class":"unknown","state":"unknown","subcommand":"checkout"}]`,
			"checkout:unknown",
		},
		{
			"checkout of a branch leaves a pull as it is", "git checkout main && git pull",
			`[{"class":"local","state":"current","subcommand":"checkout"},` +
				`{"class":"remote","deletes_ref":false,"forced":false,"state":"current","subcommand":"pull"}]`,
			"checkout:local,pull:remote",
		},
		{
			"checkout of a branch makes a push that goes by the branch unknown", "git checkout main && git push",
			`[{"class":"local","state":"current","subcommand":"checkout"},` +
				`{"class":"remote","deletes_ref":false,"destination":"unknown","destination_is_default":"unknown","forced":false,"remote":"unknown","state":"unknown","subcommand":"push"}]`,
			"checkout:local,push:remote",
		},
		{
			"checkout of a branch leaves a push that names its remote and branch current", "git checkout main && git push origin main",
			`[{"class":"local","state":"current","subcommand":"checkout"},` +
				`{"class":"remote","deletes_ref":false,"destination":"main","destination_is_default":"yes","forced":false,"remote":"github.com/owner/repo","state":"current","subcommand":"push"}]`,
			"checkout:local,push:remote",
		},
		{"gh command gets facts and no record", "gh pr create --fill", "", ""},
		{"non-git command", "terraform plan", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.90})
			v := decide(cfg, tt.command, filepath.Join(root, "repo"), testLogger)
			raw, req := capture.request()

			got := ""
			if commands, ok := req.State.Git["commands"]; ok {
				data, err := json.Marshal(commands)
				if err != nil {
					t.Fatal(err)
				}
				got = string(data)
			}
			if got != tt.want {
				t.Fatalf("git.commands =\n%s\nwant\n%s", got, tt.want)
			}
			instructions := req.Questions["decision"].Instructions
			if strings.Contains(instructions, gitCommandsInstruction) != (tt.want != "") {
				t.Fatalf("record instruction does not follow the record: %s", instructions)
			}
			capped := strings.Count(tt.command, "git add") > maxGitCommands
			if _, ok := req.State.Git["commands_truncated"]; ok != capped || strings.Contains(instructions, gitTruncatedInstruction) != capped {
				t.Fatalf("truncation marked = %v, want %v: %s", ok, capped, raw)
			}

			var buf strings.Builder
			logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), v, tt.command)
			var rec struct {
				Git *string `json:"git"`
			}
			if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
				t.Fatalf("log not JSON: %v: %s", err, buf.String())
			}
			if (rec.Git == nil) != (tt.logged == "") || (rec.Git != nil && *rec.Git != tt.logged) {
				t.Fatalf("log git field = %v, want %q: %s", rec.Git, tt.logged, buf.String())
			}
		})
	}

	t.Run("git status out of time leaves the counts unknown", func(t *testing.T) {
		gitFactsTimeout = time.Nanosecond
		t.Cleanup(func() { gitFactsTimeout = 10 * time.Second })
		cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.90})
		decide(cfg, "git reset --hard", filepath.Join(root, "repo"), testLogger)
		_, req := capture.request()
		data, err := json.Marshal(req.State.Git)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"commands":[{"class":"discard","state":"current","subcommand":"reset","uncommitted_files":"unknown","untracked_files":"unknown"}]}`
		if string(data) != want {
			t.Fatalf("git state = %s, want %s", data, want)
		}
		decide(cfg, "git clean -fx", filepath.Join(root, "repo"), testLogger)
		_, req = capture.request()
		if data, _ = json.Marshal(req.State.Git); !strings.Contains(string(data), `"ignored_files":"unknown"`) {
			t.Fatalf("git state = %s, want ignored_files unknown", data)
		}
	})

	// Last: the file it adds would change the counts above.
	t.Run("checkout of a word that is both a branch and a path stays unknown", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(root, "repo", "main"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.90})
		v := decide(cfg, "git checkout main && git push origin main", filepath.Join(root, "repo"), testLogger)
		_, req := capture.request()
		push, _ := json.Marshal(req.State.Git["commands"])
		if v.Git != "checkout:unknown,push:remote" || !strings.Contains(string(push), `"remote":"unknown","state":"unknown","subcommand":"push"`) {
			t.Fatalf("records = %q, commands = %s", v.Git, push)
		}
	})
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

func TestGitMoves(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command string
		moves   bool
	}{
		{"git switch main", true},
		{"git switch -c feat/x", true},
		{"git checkout main", true},
		{"git checkout -b feat/x", true},
		{"git checkout -- frisk.go", true},
		{"git branch feat/x", true},
		{"git branch -u origin/other", true},
		{"git branch -D feat/x", true},
		{"git worktree add ../wt", true},
		{"git bisect start", true},
		{"git push -u origin feat/x", true},
		{"git push --set-upstream origin feat/x", true},
		{"git pull --set-upstream origin main", true},
		{"git fetch --set-upstream origin main", true},
		{"git stash branch feat/y", true},
		{"git rebase main feat/x", true},

		{"git remote set-url origin https://example.com/o/r.git", false},
		{"git clone https://example.com/o/r.git", false},
		{"git branch", false},
		{"git branch -avv", false},
		{"git remote -v", false},
		{"git worktree list", false},
		{"git add -A", false},
		{"git commit -m x", false},
		{"git tag v1.0.0", false},
		{"git stash", false},
		{"git stash pop", false},
		{"git merge feat/x", false},
		{"git rebase main", false},
		{"git reset --hard", false},
		{"git restore frisk.go", false},
		{"git rm -f frisk.go", false},
		{"git cherry-pick abc123", false},
		{"git revert HEAD", false},
		{"git fetch origin", false},
		{"git pull", false},
		{"git push origin main", false},
		{"git status", false},
	}
	for _, tt := range tests {
		g, ok := describeGit(strings.Fields(tt.command))
		if !ok || g.moves != tt.moves {
			t.Errorf("describeGit(%q).moves = %v, want %v", tt.command, g.moves, tt.moves)
		}
	}
	for command, rewires := range map[string]bool{
		"git remote set-url origin https://example.com/o/r.git": true,
		"git remote add up https://example.com/o/r.git":         true,
		"git remote remove up":                                  true,
		"git clone https://example.com/o/r.git":                 true,
		"git init":                                              true,
		"git remote -v":                                         false,
		"git remote get-url origin":                             false,
		"git switch -c feat/x":                                  false,
		"git fetch origin":                                      false,
		"git commit -m x":                                       false,
	} {
		if g, ok := describeGit(strings.Fields(command)); !ok || g.rewires != rewires {
			t.Errorf("describeGit(%q).rewires = %v, want %v", command, g.rewires, rewires)
		}
	}
}

// gitSummary renders a description on one line: subcommand, class, then only
// the flags and fields that are set.
func gitSummary(g gitCommand) string {
	parts := []string{g.subcommand, g.class}
	for _, flag := range []struct {
		name string
		on   bool
	}{
		{"override", g.override},
		{"retargeted", g.retargeted},
		{"forced", g.forced},
		{"no-verify", g.noVerify},
		{"deletes", g.deletesRef},
		{"hard", g.hard},
		{"amend", g.amend},
		{"ignored", g.ignored},
	} {
		if flag.on {
			parts = append(parts, flag.name)
		}
	}
	if len(g.dirs) > 0 {
		parts = append(parts, "dirs="+strings.Join(g.dirs, ","))
	}
	if g.remote != "" {
		parts = append(parts, "remote="+g.remote)
	}
	if g.destination != "" {
		parts = append(parts, "dest="+g.destination)
	}
	return strings.Join(parts, " ")
}

func TestDescribeGit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command string
		want    string // "" means not a git invocation
	}{
		// class read
		{"git status", "status read"},
		{"git log --oneline -5", "log read"},
		{"git diff HEAD~1", "diff read"},
		{"git show HEAD", "show read"},
		{"git blame frisk.go", "blame read"},
		{"git ls-files", "ls-files read"},
		{"git rev-parse --abbrev-ref HEAD", "rev-parse read"},
		{"git grep -n TODO", "grep read"},
		{"git shortlog -sn --all", "shortlog read"},
		{"git for-each-ref refs/heads", "for-each-ref read"},
		{"git count-objects -v", "count-objects read"},
		{"git name-rev HEAD", "name-rev read"},
		{"git diff-tree --no-commit-id -r HEAD", "diff-tree read"},
		{"git check-ignore -v build", "check-ignore read"},
		{"git verify-commit HEAD", "verify-commit read"},
		{"git branch", "branch read"},
		{"git branch -avv", "branch read"},
		{"git branch --list 'feat/*'", "branch read"},
		{"git branch --contains abc123", "branch read"},
		{"git tag", "tag read"},
		{"git tag -l 'v*'", "tag read"},
		{"git stash list", "stash read"},
		{"git stash show -p", "stash read"},
		{"git config --get user.name", "config read"},
		{"git config -l", "config read"},
		{"git config user.name", "config read"},
		{"git config get user.name", "config read"},
		{"git worktree list", "worktree read"},
		{"git remote -v", "remote read"},
		{"git remote get-url origin", "remote read"},
		{"git reflog", "reflog read"},
		{"git clean -n", "clean read"},
		{"git clean --dry-run -d", "clean read"},

		// class local
		{"git add -A", "add local"},
		{"git commit -m msg", "commit local"},
		{"git merge feat/x", "merge local"},
		{"git rebase main", "rebase local"},
		{"git cherry-pick abc123", "cherry-pick local"},
		{"git revert HEAD", "revert local"},
		{"git branch feat/x", "branch local"},
		{"git branch -m old new", "branch local"},
		{"git branch -u origin/main", "branch local"},
		{"git switch main", "switch local"},
		{"git switch -c feat/x", "switch local"},
		{"git checkout -b feat/x", "checkout local"},
		{"git checkout -b feat/x origin/main", "checkout local"},
		{"git checkout --orphan fresh start", "checkout local"},
		{"git checkout -t origin/feat/x", "checkout local"},
		{"git checkout main --", "checkout local"},
		{"git stash", "stash local"},
		{"git stash push -m wip", "stash local"},
		{"git stash -m wip", "stash local"},
		{"git stash -u", "stash local"},
		{"git stash pop", "stash local"},
		{"git tag v1.0.0", "tag local"},
		{"git tag -a v1.0.0 -m release", "tag local"},
		{"git reset HEAD~1", "reset local"},
		{"git reset --soft HEAD~1", "reset local"},
		{"git restore --staged frisk.go", "restore local"},
		{"git rm --cached big.bin", "rm local"},
		{"git worktree add ../wt feat/x", "worktree local"},
		{"git worktree remove ../wt", "worktree local"},
		{"git bisect start", "bisect local"},
		{"git mv old.go new.go", "mv local"},
		{"git mv -f old.go new.go", "mv local forced"},
		{"git init", "init local"},

		// class discard
		{"git reset --hard", "reset discard hard"},
		{"git reset --hard origin/main", "reset discard hard"},
		{"git clean -fd", "clean discard forced"},
		{"git clean -fdx", "clean discard forced ignored"},
		{"git clean -fX", "clean discard forced ignored"},
		{"git clean -e '*.log' -f", "clean discard forced"},
		{"git clean -nx", "clean read ignored"},
		{"git checkout -- frisk.go", "checkout discard"},
		{"git checkout .", "checkout discard"},
		{"git checkout ./frisk.go", "checkout discard"},
		{"git checkout HEAD~1 frisk.go", "checkout discard"},
		{"git checkout main -- frisk.go", "checkout discard"},
		{"git checkout -f main", "checkout discard forced"},
		{"git checkout -p", "checkout discard"},
		{"git restore frisk.go", "restore discard"},
		{"git restore --staged --worktree frisk.go", "restore discard"},
		{"git restore -s HEAD~1 frisk.go", "restore discard"},
		{"git switch --discard-changes main", "switch discard"},
		{"git switch -f main", "switch discard forced"},
		{"git stash drop", "stash discard"},
		{"git stash clear", "stash discard"},
		{"git worktree remove --force ../wt", "worktree discard forced"},
		{"git rm -f frisk.go", "rm discard forced"},

		// class remote
		{"git fetch origin", "fetch remote"},
		{"git fetch origin +refs/heads/*:refs/remotes/origin/*", "fetch remote forced"},
		{"git pull", "pull remote"},
		{"git pull --rebase origin main", "pull remote"},
		{"git clone https://example.com/o/r.git", "clone remote"},
		{"git ls-remote origin", "ls-remote remote"},
		{"git remote add up https://example.com/o/r.git", "remote remote"},
		{"git remote set-url origin https://example.com/o/r.git", "remote remote"},
		{"git remote remove up", "remote remote"},

		// class exec
		{"git rebase --exec 'make test' main", "rebase exec"},
		{"git rebase -x 'make test' main", "rebase exec"},
		{"git bisect run ./test.sh", "bisect exec"},
		{"git submodule foreach 'git pull'", "submodule exec"},
		{"git difftool HEAD~1", "difftool exec"},
		{"git mergetool", "mergetool exec"},
		{"git filter-branch --tree-filter 'rm -f x' HEAD", "filter-branch exec"},
		{"git config user.name someone", "config exec"},
		{"git config --global --unset user.name", "config exec"},
		{"git config set user.name someone", "config exec"},
		{"git config -e", "config exec"},
		{"git credential fill", "credential exec"},
		{"git credential-store get", "credential-store exec"},
		{"git daemon --export-all", "daemon exec"},
		{"git push --receive-pack=/tmp/x origin main", "push exec remote=unknown dest=unknown"},
		{"git fetch --upload-pack /tmp/x origin", "fetch exec"},
		{"git clone -c core.fsmonitor=/tmp/x https://example.com/o/r.git", "clone exec"},
		{"git clone --template=/tmp/t https://example.com/o/r.git", "clone exec"},
		{"git grep -O TODO", "grep exec"},
		{"GIT_SSH_COMMAND='ssh -i k' git fetch", "fetch exec override"},
		{"env GIT_EXTERNAL_DIFF=/tmp/x git diff", "diff exec override"},

		// class unknown
		{"git checkout main", "checkout unknown"},
		{"git checkout", "checkout unknown"},
		{"git reset --keep HEAD~1", "reset unknown"},
		{"git stash frob", "stash unknown"},
		{"git config", "config unknown"},
		{"git worktree", "worktree unknown"},
		{"git submodule update --init", "submodule unknown"},
		{"git reflog expire --expire=now --all", "reflog unknown"},
		{"git diff --output=/tmp/x", "diff unknown"},
		{"git bisect visualize", "bisect unknown"},
		{"git remote frob", "remote unknown"},

		// global options
		{"git -C /repo status", "status read dirs=/repo"},
		{"git -C a -C b status", "status read dirs=a,b"},
		{"git -c user.name=x commit -m y", "commit exec override"},
		{"git --config-env=core.pager=HOME log", "log exec override"},
		{"git --config-env core.pager=HOME log", "log exec override"},
		{"git --exec-path=/tmp/x status", "status exec override"},
		{"git --git-dir=/x/.git status", "status read retargeted"},
		{"git --git-dir /x/.git status", "status read retargeted"},
		{"git --work-tree=/x status", "status read retargeted"},
		{"git --namespace=n push", "push remote retargeted"},
		{"git --bare rev-parse HEAD", "rev-parse read retargeted"},
		{"GIT_DIR=/x/.git git status", "status read retargeted"},
		{"env GIT_WORK_TREE=/x git status", "status read retargeted"},
		{"git --no-pager log", "log read"},
		{"git -P log", "log read"},
		{"git -p log", "log read"},
		{"git --paginate log", "log read"},
		{"git --no-optional-locks --no-replace-objects --literal-pathspecs status", "status read"},
		{"git --attr-source HEAD status", "status read"},
		{"git --no-pager -C /repo -c a.b=c push -f", "push exec override forced dirs=/repo"},
		{"git --frobnicate status", "unknown unknown"},
		{"git -C", "unknown unknown"},
		{"git -C=/repo status", "unknown unknown"},
		{"git --no-pager=1 status", "unknown unknown"},
		{"git --version", "unknown unknown"},

		// flags, short and long spellings unified
		{"git push --force", "push remote forced"},
		{"git push -f", "push remote forced"},
		{"git push --force-with-lease", "push remote forced"},
		{"git push --force-with-lease=main:abc123 origin main", "push remote forced remote=origin dest=main"},
		{"git push -uf origin feat/x", "push remote forced remote=origin dest=feat/x"},
		{"git branch -f feat/x HEAD~1", "branch local forced"},
		{"git branch -D feat/x", "branch local forced deletes"},
		{"git branch -d feat/x", "branch local deletes"},
		{"git branch --delete feat/x", "branch local deletes"},
		{"git branch -rd origin/feat/x", "branch local deletes"},
		{"git tag -d v1.0.0", "tag local deletes"},
		{"git tag -f v1.0.0", "tag local forced"},
		{"git commit --no-verify -m msg", "commit local no-verify"},
		{"git commit -n -m msg", "commit local no-verify"},
		{"git commit -nm msg", "commit local no-verify"},
		{"git commit -anm msg", "commit local no-verify"},
		{"git commit -m -n", "commit local"},
		{"git commit --amend --no-edit", "commit local amend"},
		{"git push --no-verify origin feat/x", "push remote no-verify remote=origin dest=feat/x"},
		{"git push -n origin feat/x", "push remote remote=origin dest=feat/x"},
		{"git merge --no-verify feat/x", "merge local no-verify"},
		{"git log -f", "log read"},

		// push shapes
		{"git push", "push remote"},
		{"git push origin", "push remote remote=origin"},
		{"git push origin main", "push remote remote=origin dest=main"},
		{"git push origin feat/x:main", "push remote remote=origin dest=main"},
		{"git push -u origin feat/x", "push remote remote=origin dest=feat/x"},
		{"git push --set-upstream origin feat/x", "push remote remote=origin dest=feat/x"},
		{"git push -u", "push remote"},
		{"git push origin HEAD", "push remote remote=origin dest=HEAD"},
		{"git push origin @", "push remote remote=origin dest=HEAD"},
		{"git push origin HEAD:refs/heads/main", "push remote remote=origin dest=main"},
		{"git push origin +main", "push remote forced remote=origin dest=main"},
		{"git push origin :old", "push remote deletes remote=origin dest=old"},
		{"git push origin --delete old", "push remote deletes remote=origin dest=old"},
		{"git push -d origin old", "push remote deletes remote=origin dest=old"},
		{"git push -o ci.skip origin main", "push remote remote=origin dest=main"},
		{"git push -- origin main", "push remote remote=origin dest=main"},
		{"git push https://example.com/o/r.git main", "push remote remote=https://example.com/o/r.git dest=main"},
		{"git push --all origin", "push remote remote=origin dest=unknown"},
		{"git push --mirror origin", "push remote forced deletes remote=origin dest=unknown"},
		{"git push origin --tags", "push remote remote=origin dest=unknown"},
		{"git push --prune origin main", "push remote deletes remote=origin dest=unknown"},
		{"git push origin main dev", "push remote remote=origin dest=unknown"},
		{"git push origin main +dev", "push remote forced remote=origin dest=unknown"},
		{`git push origin "$BRANCH"`, "push remote remote=origin dest=unknown"},
		{`git push "$REMOTE" main`, "push remote remote=unknown dest=main"},
		{"git push origin 'main; rm -rf x'", "push remote remote=origin dest=unknown"},
		{"git push --repo=up", "push remote remote=unknown dest=unknown"},
		{"git push --push-option ci.skip origin main", "push remote remote=unknown dest=unknown"},

		// adversarial
		{"git -c alias.status='!sh' status", "status exec override"},
		{"git status -- --hard", "status read"},
		{"git reset -- --hard", "reset local"},
		{"git commit -m x -- --amend", "commit local"},
		{"git commit -m '--amend --no-verify'", "commit local"},
		{"git -- status", "unknown unknown"},
		{"git --no-pager -- push", "unknown unknown"},
		{"git status -- push", "status read"},
		{"git frobnicate", "frobnicate unknown"},
		{"git co main", "co unknown"},
		{"git 'push now'", "unknown unknown"},
		{"git $SUB origin main", "unknown unknown"},
		{"git", "unknown unknown"},
		{"time git push -f", "push remote forced"},
		{"/usr/bin/git status", "status read"},
		{"ls -la", ""},
		{"gh pr list", ""},
		{"echo git push -f", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			t.Parallel()
			var seg []string
			for _, w := range tokenize(tt.command).stmts[0].words {
				seg = append(seg, w.text)
			}
			g, ok := describeGit(seg)
			got := ""
			if ok {
				got = gitSummary(g)
			}
			if got != tt.want {
				t.Fatalf("describeGit(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestGitRuleNormalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rule, command string
		allow, want   bool
	}{
		{"git status *", "git -C /x --no-pager status -s", true, true},
		{"git status *", "git -c core.pager=x status", true, false},
		{"git log *", "git --config-env=core.pager=CMD log", true, false},
		{"git log *", "git -C /x commit", true, false},
		{"git -c * *", "git -c alias.st=!sh st", false, true},
		{"git commit --no-verify", "git commit -m x --no-verify", false, false},
		{"git commit --no-verify *", "git commit -m x --no-verify", false, true},
		{"git commit --no-verify *", "git commit -n -m x", false, true},
		{"git commit --no-verify *", "git commit -m --no-verify", false, false},
		{"git commit --no-verify *", "git commit --message=--no-verify", false, false},
		{"git commit --no-verify *", "git commit --no-ver -m x", false, true},
		{"git commit -m *", "git commit -qam x", true, true},
		{"git commit -m *", "git commit --message=x --quiet", true, true},
		{"git commit -m *", "git commit -m x --no-verify", true, false},
		{"git commit -m *", "git commit -m x --amend", true, false},
		{"git commit -m *", "git commit -m x --unknown y", true, false},
		// A missing value leaves the old positional reading; git refuses the command itself.
		{"git commit -m *", "git commit -m", true, true},
		{"git status *", "git status -sb", true, true},
		{"git status *", "git -C /x status -sb", true, true},
		{"git status *", "git -c core.fsmonitor=/x status -sb", true, false},
		{"git push *", "git push -xf origin main", true, false},
		{"git commit -m *", "git commit -Snm x", true, false},
		{"git commit -F *", "git commit --file f -q", true, true},
		{"git commit -C *", "git commit --reuse-message HEAD", true, true},
		{"git push --force *", "git push origin main -fu", false, true},
		{"git push -f *", "git push --force-with-lease=main origin", false, true},
		{"git push *", "git push -f origin main", true, false},
		{"git push --force-with-lease *", "git push --force origin main", true, false},
		{"git push --force-with-lease=main:abc *", "git push --force-with-lease=main:def origin main", true, false},
		{"git push --force-with-lease=main:abc *", "git push --force-with-lease=main:abc origin main", true, true},
		{"git push --force *", "git push --force-with-lease=main:abc origin main", true, true},
		{"git push --force-with-lease *", "git push -f origin main", false, true},
		{"git push *", "git push origin +main", true, false},
		{"git push *", "git push origin :main", true, false},
		{"git push --delete *", "git push origin -d main", false, true},
		{"git branch --delete *", "git branch topic -d", false, true},
		{"git push -u *", "git push origin main --set-upstream", false, true},
		{"git commit --no-verify *", "git commit -- --no-verify", false, false},
		{"git st *", "git -C /x st", false, false},
		{"git st *", "git st --foo", false, true},
		{"git status *", "git --bogus status", true, false},
		{"git commit --no-verify *", "git commit --no-verify -xyz", false, true},
		{"git commit --no-verify *", "git commit --no-verify -xyz", true, false},
		{"echo -n *", "echo x -n", false, false},
	}
	for _, tt := range tests {
		if got := matchRule(tt.rule, strings.Fields(tt.command), tt.allow); got != tt.want {
			t.Errorf("%q against %q (allow %v) = %v, want %v", tt.rule, tt.command, tt.allow, got, tt.want)
		}
	}
}

func TestGitRuleCleanup(t *testing.T) {
	t.Parallel()
	oldAsk := make([]string, 0, 8)
	for _, flag := range []string{"--no-verify", "-n"} {
		for i := range 4 {
			oldAsk = append(oldAsk, "git commit "+strings.Repeat("* ", i)+flag+" *")
		}
	}
	oldAllow := []string{"git commit -m *", "git commit -q -m *", "git commit -F *", "git commit -q -F *", "git add *", "git stash", "git stash push *", "git stash pop *", "git stash apply *", "git stash list *", "git stash show *", "git switch -c *", "git checkout -b *"}
	newAllow := slices.DeleteFunc(slices.Clone(oldAllow), func(rule string) bool { return strings.Contains(rule, "commit -q") })
	literalMatch := func(rules []string, command string) bool {
		for _, rule := range rules {
			pattern, words := strings.Fields(rule), strings.Fields(command)
			matched := true
			for i, token := range pattern {
				if token == "*" && i == len(pattern)-1 {
					return matched
				}
				if i >= len(words) || token != "*" && token != words[i] {
					matched = false
					break
				}
			}
			if matched && len(pattern) == len(words) {
				return true
			}
		}
		return false
	}
	commands := []string{"git commit -m x", "git commit -q -m x", "git commit -F f", "git commit -q -F f", "git add a", "git stash", "git stash push x", "git stash pop x", "git stash apply x", "git stash list x", "git stash show x", "git switch -c topic", "git checkout -b topic", "git push origin main", "git commit --amend -m x"}
	for _, flag := range []string{"--no-verify", "-n"} {
		for _, args := range []string{flag + " -m x", "-m x " + flag, "-q -m x " + flag} {
			commands = append(commands, "git commit "+args)
		}
	}
	for _, command := range commands {
		words := strings.Fields(command)
		old := literalMatch(oldAsk, command)
		if got := matchAny([]string{"git commit --no-verify *"}, [][]string{words}) != ""; got != old {
			t.Errorf("ask cleanup %q: old %v, new %v", command, old, got)
		}
		old = !old && literalMatch(oldAllow, command)
		got := matchAny([]string{"git commit --no-verify *"}, [][]string{words}) == "" && matchAny(newAllow, [][]string{words}, true) != ""
		if got != old {
			t.Errorf("allow cleanup %q: old %v, new %v", command, old, got)
		}
	}
	data, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, rule := range cfg.Permissions.Allow {
		if !strings.HasPrefix(rule, "git ") {
			continue
		}
		if strings.Contains(rule, "-C *") {
			t.Fatalf("duplicate remains: %s", rule)
		}
		command := strings.TrimSuffix(rule, " *")
		command = strings.ReplaceAll(command, "*", "x")
		directed := strings.Replace(command, "git ", "git -C /x ", 1)
		oldRules := []string{rule, strings.Replace(rule, "git ", "git -C * ", 1)}
		for _, candidate := range []string{command, directed} {
			if !literalMatch(oldRules, candidate) || !matchRule(rule, strings.Fields(candidate), true) {
				t.Errorf("read cleanup %q against %q", rule, candidate)
			}
		}
	}
}

func TestGitRuleGlobals(t *testing.T) {
	t.Parallel()
	for _, global := range []string{"-C /x", "--no-pager", "-P", "--git-dir=/x", "--work-tree=/x", "--namespace x", "--bare", "--no-optional-locks", "--attr-source HEAD", "--literal-pathspecs"} {
		command := strings.Fields("git " + global + " status -s")
		for _, allow := range []bool{false, true} {
			if !matchRule("git status *", command, allow) {
				t.Errorf("global %q, allow %v", global, allow)
			}
		}
	}
	for _, global := range []string{"-c core.pager=x", "--config-env core.pager=CMD", "--exec-path=/x"} {
		if matchRule("git log *", strings.Fields("git "+global+" log"), true) {
			t.Errorf("override %q matched", global)
		}
	}
}
