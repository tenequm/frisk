package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDescribeGH(t *testing.T) {
	tests := []struct {
		command string
		want    string // subcommand, class, scoped, repo from the words
	}{
		{"gh pr checks 998", "pr checks read scoped"},
		{"gh pr view 12 --json state -q .state", "pr view read scoped"},
		{"gh pr view 12 --jq env.GH_TOKEN", "pr view exec scoped"},
		{"gh pr checkout 12", "pr checkout local scoped"},
		{"gh pr create --fill", "pr create collaborate scoped"},
		{"gh pr review 12 --comment -b ok", "pr review collaborate scoped"},
		{"gh pr review 12 --approve", "pr review merge scoped"},
		{"gh pr merge 12 --squash -R acme/widget", "pr merge merge scoped github.com/acme/widget"},
		{"gh pr list -Racme/widget", "pr list read scoped github.com/acme/widget"},
		{"gh pr list --repo=ghe.example.com/acme/widget", "pr list read scoped ghe.example.com/acme/widget"},
		{"GH_REPO=acme/widget gh issue list", "issue list read scoped github.com/acme/widget"},
		{"gh run rerun 42 --failed", "run rerun collaborate scoped"},
		{"gh workflow run deploy.yml", "workflow run remote scoped"},
		{"gh secret set TOKEN", "secret set remote scoped"},
		{"gh release create v1.0.0", "release create remote scoped"},
		{"gh repo clone acme/widget", "repo clone local github.com/acme/widget"},
		{"gh repo create acme/new --private", "repo create remote"},
		{"gh search prs --author @me", "search read"},
		{"gh auth status", "auth status read"},
		{"gh auth token", "auth token exec"},
		{"gh extension install owner/gh-x", "extension install exec"},
		{"gh api repos/acme/widget/pulls/1", "api read scoped github.com/acme/widget"},
		{"gh api /repos/{owner}/{repo}/pulls", "api read scoped"},
		{"gh api -X POST repos/acme/widget/issues -f title=x", "api remote scoped github.com/acme/widget"},
		{"gh api user", "api read"},
		{"gh api graphql -f query='query { viewer { login } }'", "api read"},
		{"gh api graphql -f query='mutation { addStar }'", "api remote"},
		{"gh api graphql -F query=@q.graphql", "api unknown"},
		{"gh co 12", "unknown unknown"},
		{"gh pr frobnicate", "unknown unknown"},
		{"gh --version", "unknown unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			var words []string
			for _, w := range tokenize(tt.command).stmts[0].words {
				words = append(words, w.text)
			}
			g, ok := describeGH(words)
			if !ok {
				t.Fatal("not read as gh")
			}
			got := g.subcommand + " " + g.class
			if g.scoped {
				got += " scoped"
			}
			if g.repo != "" {
				got += " " + g.repo
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
	if _, ok := describeGH([]string{"git", "status"}); ok {
		t.Fatal("git read as gh")
	}
}

func TestGHRecords(t *testing.T) {
	root := gitRepo(t)
	repo := filepath.Join(root, "repo")
	prev := gitFactsTimeout
	gitFactsTimeout = 10 * time.Second
	t.Cleanup(func() { gitFactsTimeout = prev })

	tests := []struct {
		name    string
		command string
		want    string // state.gh.commands as JSON, "" when gh is absent
		logged  string
	}{
		{
			"a read on the checkout's repository", "gh pr checks 998 2>&1 | rg -c fail; git commit -m x",
			`[{"class":"read","repo":"github.com/owner/repo","subcommand":"pr checks"}]`,
			"commit:local,gh pr checks:read",
		},
		{
			"-R names the repository", "gh pr merge 1 -R acme/widget",
			`[{"class":"merge","repo":"github.com/acme/widget","subcommand":"pr merge"}]`,
			"gh pr merge:merge",
		},
		{
			"a command on no repository has none", "gh search prs x",
			`[{"class":"read","subcommand":"search"}]`,
			"gh search:read",
		},
		{
			"git and gh records log together", "git branch -D feature-x && gh pr checks 1",
			`[{"class":"read","repo":"github.com/owner/repo","subcommand":"pr checks"}]`,
			"branch:local,gh pr checks:read",
		},
		{
			"a changed remote leaves the checkout's repository unknown", "git remote set-url origin https://example.com/o/r.git && gh pr view 1",
			`[{"class":"read","repo":"unknown","subcommand":"pr view"}]`,
			"remote:remote,gh pr view:read",
		},
		{
			"more gh commands than the cap", "gh pr view 1; gh pr view 2; gh pr view 3; gh pr view 4; gh pr view 5; gh pr view 6; git commit -m x",
			`[` + strings.TrimSuffix(strings.Repeat(`{"class":"read","repo":"github.com/owner/repo","subcommand":"pr view"},`, maxGitCommands), ",") + `]`,
			"commit:local," + strings.TrimSuffix(strings.Repeat("gh pr view:read,", maxGitCommands), ","),
		},
		{"no gh command", "git commit -m x", "", "commit:local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.90})
			v := decide(cfg, tt.command, repo, testLogger)
			raw, req := capture.request()
			got := ""
			if commands, ok := req.State.GH["commands"]; ok {
				data, err := json.Marshal(commands)
				if err != nil {
					t.Fatal(err)
				}
				got = string(data)
			}
			if got != tt.want {
				t.Fatalf("gh.commands =\n%s\nwant\n%s", got, tt.want)
			}
			instructions := req.Questions["decision"].Instructions
			if strings.Contains(instructions, ghCommandsInstruction) != (tt.want != "") {
				t.Fatalf("record instruction does not follow the record: %s", instructions)
			}
			capped := strings.Count(tt.command, "gh pr view") > maxGitCommands
			if _, ok := req.State.GH["commands_truncated"]; ok != capped || strings.Contains(instructions, ghTruncatedInstruction) != capped {
				t.Fatalf("truncation marked = %v, want %v: %s", ok, capped, raw)
			}
			if v.Git != tt.logged {
				t.Fatalf("logged %q, want %q", v.Git, tt.logged)
			}
		})
	}
}

func TestGHRepoFromSetDefault(t *testing.T) {
	root := gitRepo(t)
	repo := filepath.Join(root, "repo")
	gitDo(t, "-C", repo, "remote", "add", "upstream", "git@github.com:acme/widget.git")
	git := newGitRunner(t.Context())
	if got := ghCheckoutRepo(repo, git); got != "" {
		t.Fatalf("two remotes and no default: got %q, want none", got)
	}
	gitDo(t, "-C", repo, "config", "remote.upstream.gh-resolved", "base")
	if got := ghCheckoutRepo(repo, git); got != "github.com/acme/widget" {
		t.Fatalf("set-default remote: got %q", got)
	}
}
