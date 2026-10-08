package main

import (
	"cmp"
	"context"
	"path/filepath"
	"slices"
	"strings"
)

// gh classes reuse the git ones where the meaning carries over (read, local,
// remote, exec, unknown) and add the two a forge has that git does not.
const (
	ghCollaborate = "collaborate" // pull requests, issues, comments, reviews and CI reruns
	ghMerge       = "merge"       // merges or approves a pull request
)

const ghAPI = "api"

const (
	ghCommandsInstruction = " `gh.commands` lists each gh command in `untrusted.command`, in order, as read from its " +
		"words and checked against its repository: `subcommand`, `class` (read, local, collaborate, merge, remote, " +
		"exec or unknown) and `repo`, the host/owner/repo it acts on. It is trusted. A field whose value is " +
		"`unknown` could not be determined."
	ghTruncatedInstruction = " `gh.commands_truncated` means the command holds more gh commands than are listed."
)

type ghSub struct {
	class string
	repo  bool // acts on one repository: -R, GH_REPO or the checkout's remote
}

// ghSubs classes gh by "group verb", or by group alone where every verb
// shares a class. Anything missing, a user alias or an extension, is unknown.
var ghSubs = func() map[string]ghSub {
	subs := map[string]ghSub{}
	add := func(class string, repo bool, names ...string) {
		for _, name := range names {
			subs[name] = ghSub{class: class, repo: repo}
		}
	}
	add(gitRead, true,
		"pr view", "pr list", "pr checks", "pr diff", "pr status", "issue view", "issue list", "issue status",
		"run view", "run list", "run watch", "release view", "release list", "repo view", "workflow view",
		"workflow list", "label list", "secret list", "variable list", "variable get", "cache list",
		"ruleset list", "ruleset view", "ruleset check", "browse")
	add(gitRead, false,
		"search", "status", "org list", "repo list", "gist view", "gist list", "auth status", "config get",
		"config list", "alias list", "extension list", "extension search", "extension browse", "completion",
		"version", "help")
	add(gitLocal, true, "pr checkout", "run download", "release download", "repo set-default")
	add(gitLocal, false, "repo clone", "gist clone", "config set", "config clear-cache")
	add(ghCollaborate, true,
		"pr create", "pr edit", "pr comment", "pr review", "pr ready", "pr close", "pr reopen", "pr lock",
		"pr unlock", "pr update-branch", "pr revert", "issue create", "issue edit", "issue comment",
		"issue close", "issue reopen", "issue lock", "issue unlock", "issue pin", "issue unpin",
		"issue transfer", "issue develop", "run rerun", "run cancel")
	add(ghMerge, true, "pr merge")
	add(gitRemote, true,
		"repo edit", "repo delete", "repo archive", "repo unarchive", "repo rename", "repo sync",
		"repo deploy-key", "release create", "release edit", "release delete", "release delete-asset",
		"release upload", "workflow run", "workflow enable", "workflow disable", "label create", "label edit",
		"label delete", "label clone", "secret set", "secret delete", "variable set", "variable delete",
		"cache delete", "run delete", "issue delete")
	add(gitRemote, false, "repo create", "repo fork", "gist create", "gist edit", "gist delete", "gist rename")
	add(gitExec, false,
		"auth login", "auth logout", "auth refresh", "auth setup-git", "auth switch", "auth token",
		"extension install", "extension upgrade", "extension remove", "extension exec", "extension create",
		"alias set", "alias delete", "alias import")
	return subs
}()

// ghValueFlags take the next word as their value when it is not attached:
// the repository flag and the flags of the two commands whose operand names
// a repository, api and repo clone. A short flag means another thing in other
// commands, so the list stops there.
var ghValueFlags = []string{
	"-R", "--repo", "-q", "--jq", "-t", "--template", "-X", "--method", "-H", "--header", "-f", "--raw-field",
	"-F", "--field", "--input", "-p", "--preview", "--cache", "--hostname", "-u", "--upstream-remote-name",
}

type ghCommand struct {
	subcommand string
	class      string
	scoped     bool   // acts on one repository, named or the checkout's
	repo       string // from the words: -R, GH_REPO or an api endpoint; "" when they name none
}

// describeGH reads one segment as a gh invocation. Like describeGit it opens
// nothing; the repository a command leaves to the checkout is read later.
func describeGH(seg []string) (ghCommand, bool) {
	inner, _, err := unwrap(seg)
	if err != nil || len(inner) == 0 || filepath.Base(inner[0]) != verbGH {
		return ghCommand{}, false
	}
	g := ghCommand{subcommand: gitUnknown, class: gitUnknown}
	for _, w := range seg[:len(seg)-len(inner)] {
		if value, ok := strings.CutPrefix(w, "GH_REPO="); ok {
			g.repo = ghRepoSlug(value)
		}
	}
	args := inner[1:]
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return g, true
	}
	name, rest := args[0], args[1:]
	sub, known := ghSubs[name]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		if row, ok := ghSubs[name+" "+rest[0]]; ok {
			name, rest, sub, known = name+" "+rest[0], rest[1:], row, true
		}
	}
	if name == ghAPI {
		sub, known = ghSub{class: ghAPIClass(rest)}, true
	}
	if !known {
		return g, true
	}
	g.subcommand, g.class, g.scoped = name, sub.class, sub.repo
	flags, operands := ghWords(rest)
	if r, ok := flags["-R"]; ok {
		g.repo = ghRepoSlug(r)
	} else if r, ok := flags["--repo"]; ok {
		g.repo = ghRepoSlug(r)
	}
	switch {
	case name == "pr review" && (flags["-a"] != "" || flags["--approve"] != ""):
		g.class = ghMerge
	case name == ghAPI && len(operands) > 0:
		endpoint := strings.TrimPrefix(operands[0], "/")
		if owner, rest, ok := strings.Cut(strings.TrimPrefix(endpoint, "repos/"), "/"); ok && strings.HasPrefix(endpoint, "repos/") {
			repo, _, _ := strings.Cut(rest, "/")
			// {owner} and {repo} are filled from the checkout, like no -R.
			g.scoped = true
			if !strings.Contains(owner+repo, "{") {
				g.repo = "github.com/" + owner + "/" + repo
			}
		}
	case name == "repo clone" && len(operands) > 0:
		g.repo = ghRepoSlug(operands[0])
	default:
	}
	for _, flag := range []string{"-q", "--jq"} {
		if jqProgram.MatchString(flags[flag]) {
			g.class = gitExec
		}
	}
	return g, true
}

// ghWords splits a gh command's words into flag values and operands. A flag
// without a value maps to "true".
func ghWords(words []string) (map[string]string, []string) {
	flags := map[string]string{}
	var operands []string
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "--":
			return flags, append(operands, words[i+1:]...)
		case strings.HasPrefix(w, "-"):
			name, value, attached := strings.Cut(w, "=")
			if !attached && len(name) > 2 && name[1] != '-' && slices.Contains(ghValueFlags, name[:2]) {
				name, value, attached = name[:2], name[2:], true // -Rowner/repo
			}
			if !attached && slices.Contains(ghValueFlags, name) && i+1 < len(words) {
				i++
				value, attached = words[i], true
			}
			if !attached {
				value = "true"
			}
			flags[name] = value
		default:
			operands = append(operands, w)
		}
	}
	return flags, operands
}

// ghAPIClass reads gh api: a GET, or a GraphQL query with no mutation and no
// query file, only reads.
func ghAPIClass(args []string) string {
	graphql := slices.Contains(args, "graphql")
	switch {
	case !graphql && ghAPIReads(args):
		return gitRead
	case graphql && slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "=@") }):
		return gitUnknown
	case graphql && !slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "mutation") }):
		return gitRead
	default:
		return gitRemote
	}
}

// ghRepoSlug reduces a -R or GH_REPO value (OWNER/REPO, HOST/OWNER/REPO or a
// URL) to host/owner/repo.
func ghRepoSlug(value string) string {
	if strings.Contains(value, "://") || strings.Contains(value, "@") {
		return remoteSlug(value)
	}
	switch parts := strings.Split(strings.TrimSuffix(value, ".git"), "/"); len(parts) {
	case 2:
		return "github.com/" + strings.Join(parts, "/")
	case 3:
		return strings.Join(parts, "/")
	default:
		return ""
	}
}

// ghFacts records each gh segment for the judge, reading the repository a
// command leaves to the checkout the way gh picks it: the remote that
// `gh repo set-default` marked, else the only remote. The string is the
// records in short, for the log.
func ghFacts(segments, env [][]string, cwd string) (map[string]any, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), gitFactsTimeout)
	defer cancel()
	git := newGitRunner(ctx)
	resolved := map[string]string{}
	dir := shellDir{path: cwd, known: cwd != ""}
	var commands []map[string]any
	var summary []string
	truncated, rewired := false, false
	for i, seg := range segments {
		if len(seg) > 0 && dir.step(seg) {
			continue
		}
		words := slices.Concat(env[i], seg)
		if g, isGit := describeGit(words); isGit {
			rewired = rewired || g.rewires || g.class == gitExec || g.class == gitUnknown
			continue
		}
		g, isGH := describeGH(words)
		if !isGH {
			continue
		}
		if len(commands) == maxGitCommands {
			truncated = true
			break
		}
		rec := map[string]any{"subcommand": g.subcommand, "class": g.class}
		if g.scoped || g.repo != "" {
			repo := g.repo
			if repo == "" && dir.known && !rewired {
				if _, seen := resolved[dir.path]; !seen {
					resolved[dir.path] = ghCheckoutRepo(dir.path, git)
				}
				repo = resolved[dir.path]
			}
			rec["repo"] = cmp.Or(repo, gitUnknown)
		}
		commands = append(commands, rec)
		summary = append(summary, "gh "+g.subcommand+":"+g.class)
		rewired = rewired || g.subcommand == "repo set-default" || g.class == gitExec || g.class == gitUnknown
	}
	if len(commands) == 0 {
		return nil, nil
	}
	facts := map[string]any{"commands": commands}
	if truncated {
		facts["commands_truncated"] = true
	}
	return facts, summary
}

// ghCheckoutRepo is the repository gh acts on in dir when the words name
// none, or "" when gh would have to ask.
func ghCheckoutRepo(dir string, git gitRunner) string {
	name := ""
	if out, ok := git(dir, "config", "--get-regexp", `^remote\..*\.gh-resolved$`); ok {
		key, _, _ := strings.Cut(out, " ")
		name = strings.TrimSuffix(strings.TrimPrefix(key, "remote."), ".gh-resolved")
	} else if out, ok := git(dir, "remote"); ok && out != "" && !strings.Contains(out, "\n") {
		name = out
	}
	if name == "" {
		return ""
	}
	url, ok := git(dir, "remote", "get-url", name)
	if !ok {
		return ""
	}
	return remoteSlug(url)
}
