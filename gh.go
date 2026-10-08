package main

import (
	"cmp"
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

const (
	ghAPI                 = "api"
	ghSetDefault          = "repo set-default"
	ghDefaultHost         = "github.com"
	ghPRReview            = "pr review"
	ghCommandsInstruction = " `gh.commands` lists each gh command in `untrusted.command`, in order, as read from its " +
		"words and checked against its repository: `subcommand`, `class` (read, local, collaborate, merge, remote, " +
		"exec or unknown) and `repo`, the host/owner/repo it acts on, which for a gh command outranks `git.remote`. " +
		"It is trusted. A field whose value is `unknown` could not be determined."
	ghTruncatedInstruction = " `gh.commands_truncated` means the command holds more gh commands than are listed."
)

type ghSub struct {
	class  string
	scoped bool // acts on one repository: named in the words, or the checkout's
}

// ghSubs classes gh by "group verb", or by group alone where every verb
// shares a class. Anything missing, a user alias or an extension, is unknown.
var ghSubs = func() map[string]ghSub {
	subs := map[string]ghSub{}
	add := func(class string, scoped bool, names ...string) {
		for _, name := range names {
			subs[name] = ghSub{class: class, scoped: scoped}
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
	add(gitLocal, true, "pr checkout", "run download", "release download", ghSetDefault)
	add(gitLocal, false, "repo clone", "gist clone", "config set", "config clear-cache")
	add(ghCollaborate, true,
		"pr create", "pr edit", "pr comment", ghPRReview, "pr ready", "pr close", "pr reopen", "pr lock",
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

// ghValueFlags names, per gh command, the flags beyond ghTextFlags that take
// a value. Every command shares -R/--repo, -q/--jq, --template and --json. The
// lists are complete where a value hides what the record reads: api's
// endpoint and fields, the approve flag of pr review, the key of config set.
var ghValueFlags = map[string][]string{
	ghAPI: {
		"-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field", "--input", "-p", "--preview",
		"--cache", "--hostname", "-t",
	},
	ghPRReview:   {"-F", "--body-file"},
	"pr merge":   {"-F", "--body-file", "-A", "--author-email", "--match-head-commit"},
	"repo clone": {"-u", "--upstream-remote-name"},
	"config set": {"-h", "--host"},
}

var ghSharedValueFlags = []string{"-R", "--repo", "-q", "--jq", "--template", "--json"}

// ghProgramKeys are gh config keys that name a program gh runs later.
var ghProgramKeys = []string{"editor", "pager", "browser"}

type ghCommand struct {
	subcommand string
	class      string
	scoped     bool
	// repos are the repositories the words name, which must all agree.
	// checkout adds the checkout's repository to them: the words name none
	// for certain, or name one where a misread flag could have put it.
	repos    []string
	checkout bool
}

// ghArgs is a gh command's words after the subcommand, as gh's flag parser
// splits them: short flags unbundled, a value flag taking the rest of its
// word or the next one.
type ghArgs struct {
	values   map[string][]string // every value of each flag, in order; a flag without one maps to "true"
	operands []string
	repoFlag string // the last -R or --repo value, which is the one gh keeps
}

func (a ghArgs) has(names ...string) bool {
	return slices.ContainsFunc(names, func(name string) bool { return len(a.values[name]) > 0 })
}

func parseGHArgs(sub string, words []string) ghArgs {
	takes := slices.Concat(ghSharedValueFlags, ghTextFlags[sub], ghValueFlags[sub])
	a := ghArgs{values: map[string][]string{}}
	set := func(name, value string) {
		a.values[name] = append(a.values[name], value)
		if name == "-R" || name == "--repo" {
			a.repoFlag = value
		}
	}
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "--":
			a.operands = append(a.operands, words[i+1:]...)
			return a
		case strings.HasPrefix(w, "--"):
			name, value, attached := strings.Cut(w, "=")
			if !attached && slices.Contains(takes, name) && i+1 < len(words) {
				i++
				value, attached = words[i], true
			}
			if !attached {
				value = "true"
			}
			set(name, value)
		case len(w) > 1 && w[0] == '-':
			for j := 1; j < len(w); j++ {
				name := "-" + w[j:j+1]
				if !slices.Contains(takes, name) {
					set(name, "true")
					continue
				}
				value := strings.TrimPrefix(w[j+1:], "=")
				if value == "" && i+1 < len(words) {
					i++
					value = words[i]
				}
				set(name, value)
				break
			}
		default:
			a.operands = append(a.operands, w)
		}
	}
	return a
}

// describeGH reads one segment as a gh invocation. Like describeGit it opens
// nothing; the repository a command leaves to the checkout is read later.
func describeGH(seg []string) (ghCommand, bool) {
	inner, _, err := unwrap(seg)
	if err != nil || len(inner) == 0 || filepath.Base(inner[0]) != verbGH {
		return ghCommand{}, false
	}
	g := ghCommand{subcommand: gitUnknown, class: gitUnknown}
	host, envRepo := ghDefaultHost, ""
	for _, w := range seg[:len(seg)-len(inner)] {
		if value, ok := strings.CutPrefix(w, "GH_HOST="); ok {
			host = value
		}
		if value, ok := strings.CutPrefix(w, "GH_REPO="); ok {
			envRepo = value
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
		sub, known = ghSub{}, true
	}
	if !known {
		return g, true
	}
	g.subcommand, g.class, g.scoped = name, sub.class, sub.scoped
	a := parseGHArgs(name, rest)
	if hostnames := a.values["--hostname"]; len(hostnames) > 0 {
		host = hostnames[len(hostnames)-1]
	}
	slug := func(value string) string { return ghRepoSlug(value, host) }

	switch {
	case name == ghAPI:
		g.class = ghAPIClass(rest, a)
		if endpoint, ok := strings.CutPrefix(strings.TrimPrefix(firstOf(a.operands), "/"), "repos/"); ok {
			owner, repo, _ := strings.Cut(endpoint, "/")
			repo, _, _ = strings.Cut(repo, "/")
			g.scoped = true
			// {owner} and {repo} are filled from the checkout, like no -R.
			if strings.Contains(owner+repo, "{") {
				g.checkout = true
			} else {
				g.repos = append(g.repos, slug(owner+"/"+repo))
			}
		}
	case name == ghPRReview && a.has("-a", "--approve"):
		g.class = ghMerge
	case name == "pr close" && a.has("-d", "--delete-branch"):
		g.class = gitRemote
	case name == "auth status" && a.has("-t", "--show-token"):
		g.class = gitExec
	case name == "config set" && slices.Contains(ghProgramKeys, firstOf(a.operands)):
		g.class = gitExec
	default:
	}
	for _, filter := range slices.Concat(a.values["-q"], a.values["--jq"]) {
		if jqProgram.MatchString(filter) {
			g.class = gitExec
		}
	}

	// gh keeps the last -R, which outranks GH_REPO; a pull request, issue or
	// repository given right after the subcommand outranks both.
	named := false
	if a.repoFlag != "" {
		g.repos, named = append(g.repos, slug(a.repoFlag)), true
	} else if envRepo != "" {
		g.repos, named = append(g.repos, slug(envRepo)), true
	}
	if len(rest) > 0 && ghRepoShaped(name, rest[0]) {
		g.repos, named = append(g.repos, slug(rest[0])), true
	}
	// A repository-shaped word anywhere else may be a selector behind a flag
	// frisk reads as taking no value, or a value frisk reads as a selector.
	for _, w := range rest[min(1, len(rest)):] {
		if ghRepoShaped(name, w) {
			g.repos = append(g.repos, slug(w))
			g.checkout = g.checkout || !named
		}
	}
	g.checkout = g.checkout || g.scoped && len(g.repos) == 0
	return g, true
}

func firstOf(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

// ghRepoShaped reports a word that names a repository for this command: a
// URL anywhere, and OWNER/REPO where a repo or clone command takes one.
func ghRepoShaped(sub, w string) bool {
	if strings.HasPrefix(w, "https://") || strings.HasPrefix(w, "http://") {
		return !strings.ContainsAny(w, " \t\n")
	}
	return strings.HasPrefix(sub, "repo ") && !strings.HasPrefix(w, "-") && strings.Count(w, "/") >= 1 && strings.Count(w, "/") <= 2 &&
		!strings.ContainsAny(w, " \t\n:")
}

// ghAPIClass reads gh api: only a GET reads. GraphQL needs a POST whether it
// queries or mutates, so it stays unknown.
func ghAPIClass(rest []string, a ghArgs) string {
	switch {
	case firstOf(a.operands) == "graphql":
		return gitUnknown
	case ghAPIReads(rest):
		return gitRead
	default:
		return gitRemote
	}
}

// ghAPIReads reports a gh api call that can only send a GET. gh switches to
// POST as soon as a field or an input body is given, and GraphQL needs one.
func ghAPIReads(args []string) bool {
	for i, a := range args {
		name, value, attached := strings.Cut(a, "=")
		short := len(a) > 1 && a[0] == '-' && a[1] != '-'
		switch {
		case a == "graphql", abbreviates(name, "--field"), abbreviates(name, "--raw-field"),
			abbreviates(name, "--input"), short && strings.ContainsAny(a, "fF"):
			return false
		case abbreviates(name, "--method"):
		case short && strings.Contains(a, "X"):
			// Bundled or attached: -iX GET, -XGET, -X=GET.
			value = strings.TrimPrefix(a[strings.IndexByte(a, 'X')+1:], "=")
			attached = value != ""
		default:
			continue
		}
		if !attached && i+1 < len(args) {
			value = args[i+1]
		}
		if value != "GET" {
			return false
		}
	}
	return true
}

// ghRepoSlug reduces a -R, GH_REPO or selector value (OWNER/REPO,
// HOST/OWNER/REPO or a URL) to host/owner/repo; OWNER/REPO takes host.
func ghRepoSlug(value, host string) string {
	if strings.Contains(value, "://") || strings.Contains(value, "@") {
		u := remoteSlug(value)
		h, path, _ := strings.Cut(u, "/")
		owner, repo, _ := strings.Cut(path, "/")
		repo, _, _ = strings.Cut(repo, "/") // a pull request or issue URL goes on past the repository
		if h == "" || owner == "" || repo == "" {
			return ""
		}
		return h + "/" + owner + "/" + repo
	}
	switch parts := strings.Split(strings.TrimSuffix(value, ".git"), "/"); len(parts) {
	case 2:
		return host + "/" + strings.Join(parts, "/")
	case 3:
		return strings.Join(parts, "/")
	default:
		return ""
	}
}

// ghTarget is one gh segment and the directory it runs in.
type ghTarget struct {
	cmd ghCommand
	dir string
	// current: the checkout's repository read in dir still holds when the
	// segment runs: no earlier segment can have changed the remotes, the gh
	// default or GH_REPO and GH_HOST.
	current bool
}

// ghEnvWord matches a word that sets or unsets GH_REPO or GH_HOST for the
// segments after it.
func ghEnvWord(w string) bool {
	return strings.HasPrefix(w, "GH_REPO") || strings.HasPrefix(w, "GH_HOST")
}

// ghRecords renders the gh segments for the judge, reading each checkout's
// repository once with the git runner gitFacts shares.
func ghRecords(targets []ghTarget, git gitRunner) (map[string]any, []string) {
	if len(targets) == 0 {
		return nil, nil
	}
	resolved := map[string]string{}
	commands := make([]map[string]any, 0, min(len(targets), maxGitCommands))
	summary := make([]string, 0, cap(commands))
	facts := map[string]any{}
	for i, t := range targets {
		if i == maxGitCommands {
			facts["commands_truncated"] = true
			break
		}
		c := t.cmd
		rec := map[string]any{"subcommand": c.subcommand, "class": c.class}
		if c.scoped || len(c.repos) > 0 {
			rec["repo"] = t.repo(git, resolved)
		}
		commands = append(commands, rec)
		summary = append(summary, "gh "+c.subcommand+":"+c.class)
	}
	facts["commands"] = commands
	return facts, summary
}

// repo is the repository every source agrees on, or unknown. resolved
// caches the checkout's repository per directory.
func (t ghTarget) repo(git gitRunner, resolved map[string]string) string {
	repos := t.cmd.repos
	if t.cmd.checkout {
		checkout := ""
		if t.current {
			if _, seen := resolved[t.dir]; !seen {
				resolved[t.dir] = ghCheckoutRepo(t.dir, git)
			}
			checkout = resolved[t.dir]
		}
		repos = append(slices.Clone(repos), checkout)
	}
	if len(repos) == 0 || repos[0] == "" || slices.ContainsFunc(repos, func(r string) bool { return r != repos[0] }) {
		return gitUnknown
	}
	return repos[0]
}

// ghRemoteScore is gh's preference among remotes: upstream, then github,
// then origin, then the rest in config order.
func ghRemoteScore(name string) int {
	return map[string]int{"upstream": 3, "github": 2, "origin": 1}[strings.ToLower(name)]
}

// ghCheckoutRepo is the repository gh acts on in dir when the words name
// none: the one `gh repo set-default` recorded on a remote ("base" for the
// remote's own, else OWNER/REPO on its host), else the only remote. "" when gh
// would have to choose. One git call reads every remote's URL and mark.
func ghCheckoutRepo(dir string, git gitRunner) string {
	out, ok := git(dir, "config", "--get-regexp", `^remote\.`)
	if !ok {
		return ""
	}
	var names []string
	urls, marks := map[string]string{}, map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		key, value, _ := strings.Cut(line, " ")
		key = strings.TrimPrefix(key, "remote.")
		if name, ok := strings.CutSuffix(key, ".url"); ok {
			names, urls[name] = append(names, name), value
		} else if name, ok := strings.CutSuffix(key, ".gh-resolved"); ok {
			marks[name] = value
		}
	}
	slices.SortStableFunc(names, func(a, b string) int { return ghRemoteScore(b) - ghRemoteScore(a) })
	for _, name := range names {
		slug := remoteSlug(urls[name])
		switch mark := marks[name]; {
		case mark == "base":
			return slug
		case mark != "":
			host, _, _ := strings.Cut(slug, "/")
			return ghRepoSlug(mark, cmp.Or(host, ghDefaultHost))
		default:
		}
	}
	if len(names) == 1 {
		return remoteSlug(urls[names[0]])
	}
	return ""
}
