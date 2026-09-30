package main

import (
	"cmp"
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

// exampleAllow is the permissions.allow list config.example.json ships. Core
// has no allow rules, so tests take theirs from the file users copy.
func exampleAllow(t *testing.T) []string {
	t.Helper()
	return configFileAllow(t, "config.example.json")
}

func configFileAllow(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil || len(cfg.Permissions.Allow) == 0 {
		t.Fatalf("%s: no permissions.allow (%v)", path, err)
	}
	return cfg.Permissions.Allow
}

// The eval replays fixtures under testdata/eval-config.json, so its numbers
// describe the example list only while it carries every rule of it.
func TestEvalConfigCarriesExampleAllow(t *testing.T) {
	t.Parallel()
	eval := configFileAllow(t, filepath.Join("testdata", "eval-config.json"))
	for _, rule := range exampleAllow(t) {
		if !slices.Contains(eval, rule) {
			t.Errorf("testdata/eval-config.json lacks %q", rule)
		}
	}
}

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
		{"safe redirect 2>&1", "ls 2>&1", [][]string{{"ls"}}, false},
		{"safe redirect >&2 (stdout to stderr)", "ls >&2", [][]string{{"ls"}}, false},
		{"safe redirect 1>&2", "ls 1>&2", [][]string{{"ls"}}, false},
		{"safe redirect 2>/dev/null", "ls 2>/dev/null", [][]string{{"ls"}}, false},
		{"safe redirect 1>/dev/null", "ls 1>/dev/null", [][]string{{"ls"}}, false},
		{"safe redirect 0>/dev/null", "ls 0>/dev/null", [][]string{{"ls"}}, false},
		{"safe redirect &>/dev/null", "ls &>/dev/null", [][]string{{"ls"}}, false},
		{"safe redirect &>>/dev/null", "ls &>>/dev/null", [][]string{{"ls"}}, false},
		{"safe redirect >>/dev/null", "ls >>/dev/null", [][]string{{"ls"}}, false},
		{"safe redirect > /dev/null", "ls > /dev/null", [][]string{{"ls"}}, false},
		{"safe redirect 2> /dev/null", "ls 2> /dev/null", [][]string{{"ls"}}, false},
		{"safe redirect </dev/null", "ls </dev/null", [][]string{{"ls"}}, false},
		{"safe redirect < /dev/null", "ls < /dev/null", [][]string{{"ls"}}, false},
		{"safe redirect redirect at statement start", "2>/dev/null ls", [][]string{{"ls"}}, false},
		{"safe redirect after semicolon", "ls 2>&1;", [][]string{{"ls"}}, false},
		{"stderr merge splits the pipeline", "ls 2>&1 | tail -1", [][]string{{"ls"}, {"tail", "-1"}}, false},
		{"stderr merge keeps the and-chain", "a 2>&1 && b", [][]string{{"a"}, {"b"}}, false},
		{"null redirect in a pipeline", "ls 2>/dev/null | wc -l", [][]string{{"ls"}, {"wc", "-l"}}, false},
		{"unsafe redirect dev null suffix", "ls >/dev/null.bak", nil, true},
		{"unsafe redirect dev null extra char", "ls >/dev/nullx", nil, true},
		{"unsafe redirect dev null dotdot", "ls >/dev/null/../x", nil, true},
		{"unsafe redirect quoted variable target", "ls > \"$X\"", nil, true},
		{"unsafe redirect variable target", "ls >$X", nil, true},
		{"unsafe redirect other fd dup", "ls >&3", nil, true},
		{"unsafe redirect file target", "ls >file", nil, true},
		{"unsafe redirect input file", "ls <file", nil, true},
		{"unsafe redirect here-string", "ls <<<str", nil, true},
		{"unsafe redirect process substitution in", "ls <(cmd)", nil, true},
		{"unsafe redirect process substitution out", "ls >(cmd)", nil, true},
		{"unsafe redirect dup into stdout", "ls 2>&2", nil, true},
		{"unsafe redirect fd 3 to null", "ls 3>/dev/null", nil, true},
		{"unsafe redirect word glued to redirect", "ls ls2>/dev/null", nil, true},
		{"unsafe redirect input from null with fd", "ls 0</dev/null", nil, true},
		{"unsafe redirect null then file", "ls 2>/dev/null >f", nil, true},
		{"heredoc with null redirect", "cat <<EOF >/dev/null\nhi\nEOF", nil, true},
		{"heredoc body stays in the static view", "cat <<-'EOF' | wc -l\nit's here\n\tEOF\nls", [][]string{{"cat"}, {"wc", "-l"}, {"its here\n"}, {"ls"}}, true},
		{"quoted redirect is text", `awk '{print > "/dev/null"}'`, [][]string{{"awk", `{print > "/dev/null"}`}}, false},
		{"double quoted redirect is text", `echo "a>/dev/null"`, [][]string{{"echo", "a>/dev/null"}}, false},
		{"escaped redirect is text", `echo a\>/dev/null`, [][]string{{"echo", "a>/dev/null"}}, false},
		{"quoted heredoc operator is text", "rg '<<EOF' f", [][]string{{"rg", "<<EOF", "f"}}, false},
		{"single-quoted substitution is text", "rg '$(foo)' f", [][]string{{"rg", "$(foo)", "f"}}, false},
		{"single-quoted backtick is text", "rg '`id`' f", [][]string{{"rg", "`id`", "f"}}, false},
		{"escaped backtick is text", "echo \\`id\\`", [][]string{{"echo", "`id`"}}, false},
		{"escaped substitution in double quotes is text", `echo "\$(id)"`, [][]string{{"echo", "$(id)"}}, false},
		{"escaped backtick in double quotes is text", "echo \"\\`id\\`\"", [][]string{{"echo", "`id`"}}, false},
		{"double-quoted substitution is complex", `echo "$(id)"`, nil, true},
		{"double-quoted backtick is complex", "echo \"`id`\"", nil, true},
		{"substitution after a quoted one is complex", "rg '$(foo)' $(id)", nil, true},
		{"assignment statement is plain", "X=1; ls", [][]string{{}, {"ls"}}, false},
		{"hijacking assignment statement is complex", "PATH=/tmp/x; ls", [][]string{{}, {"ls"}}, true},
		{"secret-named assignment statement is complex", "GH_TOKEN=abc; ls", [][]string{{}, {"ls"}}, true},
		{"credential path in an assignment is complex", "F=~/.ssh/id_rsa; ls", [][]string{{}, {"ls"}}, true},
		{"substitution in an assignment is complex", "X=$(id); ls", nil, true},
		{"redirect with no command is complex", "ls; 2>/dev/null", [][]string{{"ls"}}, true},
		{"background with no command is complex", "ls; &", [][]string{{"ls"}}, true},
		{"heredoc operator with no body is complex", "cat <<EOF", nil, true},
		{"quoted fd stays unsound", `ls "2">/dev/null`, nil, true},
		{"background after null redirect", "sleep 5 >/dev/null &", [][]string{{"sleep", "5"}}, true},
		{"unclosed quote is complex", `echo "oops`, [][]string{{"echo", "oops"}}, true},
		{"hijacking assignment is complex", "GIT_PAGER=x git log", [][]string{{"git", "log"}}, true},
		{"literal variable is substituted", "S=/x; cat $S/f", [][]string{{}, {"cat", "/x/f"}}, false},
		{"substituted flag is what the screens see", `A=-x; fd . "$A" rm`, [][]string{{}, {"fd", ".", "-x", "rm"}}, false},
		{"substituted glob is screened", `S=~/.s; cat "$S"*/config`, nil, true},
		{"unresolved variable is complex", "cat $F", [][]string{{"cat", "$F"}}, true},
		{"quoted unresolved variable is complex", `cat "$F"`, [][]string{{"cat", "$F"}}, true},
		{"braced unresolved variable is complex", "cat ${F}", [][]string{{"cat", "${F}"}}, true},
		{"variable assigned twice is complex", "S=/x; S=/y; cat $S", nil, true},
		{"variable used before its assignment is complex", "cat $S; S=/x", nil, true},
		{"variable in an assignment prefix is complex", "A=$B ls", [][]string{{"ls"}}, true},
		{"path variable is complex", `ls "$HOME/x"`, [][]string{{"ls", "$HOME/x"}}, true},
		{"positional parameter is complex", "echo $1", [][]string{{"echo", "$1"}}, true},
		{"all parameters are complex", `echo "$@"`, [][]string{{"echo", "$@"}}, true},
		{"zsh split flag is complex", "fd $=ARGS", [][]string{{"fd", "$=ARGS"}}, true},
		{"zsh glob flag is complex", "fd $~ARGS", [][]string{{"fd", "$~ARGS"}}, true},
		{"old arithmetic is complex", "echo $[1+2]", nil, true},
		{"numeric parameters are plain", `echo "rc=$?" $$ $# $!`, [][]string{{"echo", "rc=$?", "$$", "$#", "$!"}}, false},
		{"dollar ending a pattern is literal", `rg "foo$" f`, [][]string{{"rg", "foo$", "f"}}, false},
		{"dollar before an alternation is literal", `rg "^a$|^b$" f`, [][]string{{"rg", "^a$|^b$", "f"}}, false},
		{"single-quoted dollar is literal", "rg 'a$b' f", [][]string{{"rg", "a$b", "f"}}, false},
		{"escaped dollar is literal", `echo \$HOME "\$HOME"`, [][]string{{"echo", "$HOME", "$HOME"}}, false},
		{"escaped backslash leaves the dollar live", `echo "\\$HOME"`, [][]string{{"echo", `\$HOME`}}, true},
		{"credential glob is complex", "cat ~/.s*/id_*", [][]string{{"cat", "~/.s*/id_*"}}, true},
		{"quoted glob is not expanded", "jq '.items[]' f.json", [][]string{{"jq", ".items[]", "f.json"}}, false},
		{"comment with a single quote", "echo hi # it's\nrm -rf /tmp/x # '", [][]string{{"echo", "hi"}, {"rm", "-rf", "/tmp/x"}}, true},
		{"comment with a double quote", "echo hi # say \"\nrm -rf /tmp/x # \"", [][]string{{"echo", "hi"}, {"rm", "-rf", "/tmp/x"}}, true},
		{"comment with a backslash and operators", "echo hi # a \\\nrm -rf /tmp/x # b; c | d && e > f", [][]string{{"echo", "hi"}, {"rm", "-rf", "/tmp/x"}}, true},
		{"trailing comment", "ls # trailing note", [][]string{{"ls"}}, true},
		{"comment-only first line", "# list files\nls", [][]string{{"ls"}}, true},
		{"comment after a semicolon", "ls;# it's\npwd", [][]string{{"ls"}, {"pwd"}}, true},
		{"comment after a safe redirect", "ls 2>/dev/null # quiet", [][]string{{"ls"}}, true},
		{"comment on a heredoc operator line", "cat <<EOF # note\nhi\nEOF\nls", [][]string{{"cat"}, {"hi"}, {"ls"}}, true},
		{"comment inside a heredoc body stays inside", "cat <<EOF\n# it's\nEOF\nls", [][]string{{"cat"}, {"ls"}}, true},
		{"quoted hash is not a comment", "echo '#not a comment'", [][]string{{"echo", "#not a comment"}}, false},
		{"escaped hash is not a comment", `echo \#x`, [][]string{{"echo", "#x"}}, false},
		{"hash inside a word is not a comment", "echo a#b", [][]string{{"echo", "a#b"}}, false},
		{"hash after a dollar is not a comment", "echo $#", [][]string{{"echo", "$#"}}, false},
		{"hash in a parameter length is not a comment", "echo ${#x}", [][]string{{"echo", "${#x}"}}, true},
		{"hash in an assignment value is not a comment", "a=b#c true", [][]string{{"true"}}, false},
		{"hash after an empty quoted string is not a comment", "echo ''#x", [][]string{{"echo", "#x"}}, false},
		{"brace expansion into flags is complex", "find . {-delete,-print}", nil, true},
		{"brace expansion after a dash is complex", "find . -{delete,print}", nil, true},
		{"brace expansion onto a dotfile is complex", "cat {a,.env}", nil, true},
		{"nested brace expansion is complex", "cat {a,{b,.env}}", nil, true},
		{"brace sequence is complex", "cat f{1..3}", nil, true},
		{"quoted braces are text", "find . -name '*.{go,md}'", [][]string{{"find", ".", "-name", "*.{go,md}"}}, false},
		{"braces without a list are text", "git stash show stash@{0}", [][]string{{"git", "stash", "show", "stash@{0}"}}, false},
		{"glob qualifier is complex", "ls *(e:'id':)", nil, true},
		{"subshell is complex", "(cd x && ls)", nil, true},
		{"escaped parentheses are text", `find . \( -name a -o -name b \)`, [][]string{{"find", ".", "(", "-name", "a", "-o", "-name", "b", ")"}}, false},
		{"escaped quote stays inside the string", `echo "a\"b\"c" ; rm -rf ~/x ; echo \"`, [][]string{{"echo", `a"b"c`}, {"rm", "-rf", "~/x"}, {"echo", `"`}}, false},
		{"escaped backslash ends no string early", `echo "a\\" ; ls`, [][]string{{"echo", `a\`}, {"ls"}}, false},
		{"other backslashes stay in a double-quoted string", `grep "a\.b\n" f`, [][]string{{"grep", `a\.b\n`, "f"}}, false},
		{"line continuation joins the lines", "fd . \\\n-x rm", [][]string{{"fd", ".", "-x", "rm"}}, false},
		{"line continuation inside a word", "cat a\\\nb", [][]string{{"cat", "ab"}}, false},
		{"line continuation inside double quotes", "echo \"a\\\nb\"", [][]string{{"echo", "ab"}}, false},
		{"single quotes keep a backslash and newline", "echo 'a\\\nb'", [][]string{{"echo", "a\\\nb"}}, false},
		{"ansi-c quoting is complex", "fd . $'-x' rm", nil, true},
		{"locale quoting is complex", `fd . $"-x" rm`, nil, true},
		{"escaped dollar before a quote is plain quoting", `echo \$'x'`, [][]string{{"echo", "$x"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			segments, unsound := parseCommand(tt.command)
			if unsound != tt.complex {
				t.Fatalf("unsound = %v, want %v", unsound, tt.complex)
			}
			if tt.segments == nil {
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

const (
	alnumChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	base64Chars = alnumChars + "+/"
	urlChars    = alnumChars + "-_"
	hexChars    = "0123456789abcdef"
)

// fakeSecret builds a token body at run time, so the source holds no
// secret-shaped literal for gitleaks to flag. It starts with a letter.
func fakeSecret(alphabet string, n int) string {
	b := make([]byte, n)
	x := uint32(n)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = alphabet[int(x>>16)%len(alphabet)]
	}
	b[0] = 'w'
	return string(b)
}

func TestRedactSecrets(t *testing.T) {
	t.Parallel()
	type redactCase struct {
		name     string
		template string // {S} marks where the secret goes
		secret   string
		kind     string
	}
	keyOpen := "-----BEGIN OPENSSH PRIV" + "ATE KEY-----\n" + fakeSecret(base64Chars, 64) + "\n" + fakeSecret(base64Chars, 40) + "=="
	keyClosed := keyOpen + "\n-----END OPENSSH PRIV" + "ATE KEY-----"
	jwt := "ey" + "J" + fakeSecret(urlChars, 20) + ".ey" + "J" + fakeSecret(urlChars, 40) + "." + fakeSecret(urlChars, 43)
	tests := []redactCase{
		{"github classic token", "GH_TOKEN={S} gh pr list", "gh" + "p_" + fakeSecret(alnumChars, 36), "github-token"},
		{"github oauth token in a url", "git clone https://x-access-token:{S}@github.com/o/r.git", "gh" + "o_" + fakeSecret(alnumChars, 36), "github-token"},
		{"github user token", "echo {S}", "gh" + "u_" + fakeSecret(alnumChars, 36), "github-token"},
		{"github server token", "echo {S}", "gh" + "s_" + fakeSecret(alnumChars, 36), "github-token"},
		{"github refresh token", "echo {S}", "gh" + "r_" + fakeSecret(alnumChars, 36), "github-token"},
		{"github fine-grained token", "gh auth login --with-token <<< {S}", "github" + "_pat_" + fakeSecret(alnumChars+"_", 82), "github-token"},
		{"aws access key id", "aws configure set aws_access_key_id {S}", "AK" + "IA" + strings.ToUpper(fakeSecret(hexChars, 16)), "aws-access-key-id"},
		{"aws temporary key id", "export AWS_ACCESS_KEY_ID={S}", "AS" + "IA" + strings.ToUpper(fakeSecret(hexChars, 16)), "aws-access-key-id"},
		{"aws secret key argument", "aws configure set aws_secret_access_key {S} --profile ci", fakeSecret(base64Chars, 40), "aws-secret-access-key"},
		{"aws secret key in ini", "printf 'aws_secret_access_key = {S}\\n' >> creds", fakeSecret(base64Chars, 40), "aws-secret-access-key"},
		{"aws secret key in env", "AWS_SECRET_ACCESS_KEY={S} aws s3 ls", fakeSecret(base64Chars, 40), "aws-secret-access-key"},
		{"slack token", "curl -d token={S} https://slack.com/api/auth.test", "xo" + "xb-" + fakeSecret(hexChars, 12) + "-" + fakeSecret(alnumChars, 24), "slack-token"},
		{"openai style key", "OPENAI_API_KEY={S} python3 app.py", "s" + "k-" + fakeSecret(alnumChars, 48), "api-key"},
		{"anthropic style key", "curl -H \"x-api-key: {S}\" https://api.example.com/v1/messages", "s" + "k-ant-api03-" + fakeSecret(urlChars, 40), "api-key"},
		{"stripe secret key", "stripe charges list --api-key {S}", "s" + "k_live_" + fakeSecret(alnumChars, 24), "stripe-key"},
		{"stripe restricted key", "STRIPE_KEY={S} ./sync.sh", "r" + "k_live_" + fakeSecret(alnumChars, 24), "stripe-key"},
		{"google api key", "curl \"https://maps.example.com/api?key={S}&q=x\"", "AI" + "za" + fakeSecret(urlChars, 35), "google-api-key"},
		{"npm token", "npm config set //registry.npmjs.org/:_authToken {S}", "np" + "m_" + fakeSecret(alnumChars, 36), "npm-token"},
		{"jwt", "curl -H \"Authorization: Bearer {S}\" https://api.example.com", jwt, "jwt"},
		{"private key block", "echo \"{S}\" > deploy.pem", keyClosed, "private-key"},
		{"truncated private key block", "echo \"{S}", keyOpen, "private-key"},

		{"bearer header", "curl -H \"Authorization: Bearer {S}\" https://api.example.com/v1", fakeSecret(alnumChars, 24), "authorization"},
		{"basic header", "curl -H 'Authorization: Basic {S}' https://api.example.com", fakeSecret(alnumChars, 18) + "==", "authorization"},
		{"token header", "curl -H \"Authorization: token {S}\" https://api.example.com", fakeSecret(alnumChars, 24), "authorization"},
		{"api key header", "curl -H \"X-Api-Key: {S}\" https://api.example.com", fakeSecret(alnumChars, 20), "named-secret"},
		{"auth token header", "curl -H 'X-Auth-Token: {S}' https://api.example.com", fakeSecret(alnumChars, 20), "named-secret"},
		{"--token value", "deploy --token {S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--token=value", "deploy --token={S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--password value", "deploy --password {S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--password=value", "deploy --password={S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--api-key value", "deploy --api-key {S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--api-key=value", "deploy --api-key={S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--secret value", "deploy --secret {S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--secret=value", "deploy --secret={S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--access-token value", "deploy --access-token {S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"--access-token=value", "deploy --access-token={S} --region eu", fakeSecret(alnumChars, 14), "named-secret"},
		{"curl user password", "curl -" + "u deploy:{S} https://api.example.com", fakeSecret(alnumChars, 12), "user-password"},
		{"quoted curl user password", "curl --" + "user \"deploy:{S}\" https://api.example.com", fakeSecret(alnumChars, 12), "user-password"},

		{"env prefix", "DB_PASSWORD={S} ./migrate.sh", fakeSecret(alnumChars, 9), "named-secret"},
		{"export", "export API_TOKEN={S} && make deploy", fakeSecret(alnumChars, 16), "named-secret"},
		{"quoted export", "export API_TOKEN=\"{S}\"", fakeSecret(alnumChars, 16), "named-secret"},
		{"docker env", "docker run -e SESSION_KEY={S} img", fakeSecret(alnumChars, 16), "named-secret"},
		{"single-quoted value with shell syntax", "PGPASSWORD='{S}' psql -h db", "p4ss&w(rd)|x;y", "named-secret"},
		{"inline json", "curl -d '{\"password\": \"{S}\", \"user\": \"bob\"}' https://api.example.com", fakeSecret(alnumChars, 9), "named-secret"},
		{"escaped inline json", "curl -d \"{\\\"api_key\\\":\\\"{S}\\\"}\" https://api.example.com", fakeSecret(alnumChars, 16), "named-secret"},
		{"inline yaml", "cat > cfg.yaml <<EOF\nauth:\n  token: {S}\n  user: bob\nEOF", fakeSecret(alnumChars, 16), "named-secret"},
		{"spaced assignment in code", "python3 -c \"api_key = '{S}'; run(api_key)\"", fakeSecret(alnumChars, 16), "named-secret"},
		{"query parameter", "curl \"https://api.example.com/v1?user=bob&api_key={S}&page=2\"", fakeSecret(alnumChars, 16), "named-secret"},

		{"url userinfo password", "psql postgres://app:{S}@db.internal:5432/app", fakeSecret(alnumChars, 12), "url-password"},
		{"url password without a user", "redis-cli -u redis://:{S}@cache:6379", fakeSecret(alnumChars, 12), "url-password"},
		{"netrc line", "echo \"machine api.example.com login bob password {S}\" >> ~/.netrc", fakeSecret(alnumChars, 12), "netrc-password"},
		{"netrc heredoc", "cat >> ~/.netrc <<EOF\nmachine api.example.com\nlogin bob\npassword {S}\nEOF", fakeSecret(alnumChars, 12), "netrc-password"},

		{"long base64", "echo {S} | base64 -d > blob", fakeSecret(base64Chars, 44), "high-entropy"},
		{"long base64url", "deploy --as {S}", fakeSecret(urlChars, 43), "high-entropy"},
		{"long hex", "openssl enc -aes-256-cbc -K {S} -in f", fakeSecret(hexChars, 64)[1:], "long-hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := strings.Replace(tt.template, "{S}", tt.secret, 1)
			want := strings.Replace(tt.template, "{S}", "[REDACTED:"+tt.kind+"]", 1)
			got, kinds := redactSecrets(in)
			if got != want || strings.Contains(got, tt.secret) {
				t.Fatalf("redacted = %q, want %q", got, want)
			}
			if !slices.Equal(kinds, []string{tt.kind}) {
				t.Fatalf("kinds = %v, want [%s]", kinds, tt.kind)
			}
			if again, more := redactSecrets(got); again != got || len(more) != 0 {
				t.Fatalf("second pass = %q %v, want it unchanged", again, more)
			}
		})
	}
}

func TestRedactSecretsLeavesNonSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
	}{
		{"short sha", "git show 86a93b4"},
		{"full git object id", "git cherry-pick " + fakeSecret(hexChars, 41)[1:]},
		{"uuid", "kubectl get pod 5335bfe0-37d1-40d4-93f5-0bed98fa030c"},
		{"long path", "cat /private/tmp/agent-501/-Users-dev-Projects-frisk/5335bfe0-37d1-40d4-93f5-0bed98fa030c/scratchpad/notes.md"},
		{"long path made of words", "ls /Users/someone/Projects/website/content/articles/drafts/unpublished"},
		{"path with a timestamp", "cat /home/dev/.local/state/tool/runs/20260917T232055Z9b19/record.json"},
		{"long recipe name", "just test-integration-with-a-very-long-recipe-name-for-the-whole-suite"},
		{"flag holding a variable", "deploy --token=$TOKEN --region eu"},
		{"command substitution", "PASSWORD=$(gopass show db/prod) ./migrate.sh"},
		{"braced variable", "export TOKEN=\"${GH_TOKEN}\""},
		{"backtick substitution", "API_KEY=`cat key.txt` ./run.sh"},
		{"header holding a variable", "curl -H \"Authorization: Bearer $API_TOKEN\" https://api.example.com"},
		{"curl user from a variable", "curl -u \"bob:$PASS\" https://api.example.com"},
		{"url password from a variable", "psql postgres://app:$PGPASS@db.internal/app"},
		{"base64 under the length threshold", "echo " + fakeSecret(base64Chars, 39) + " | base64 -d"},
		{"numeric setting", "curl -d '{\"model\": \"m\", \"max_tokens\": 1024}' https://api.example.com"},
		{"sort key", "sort --key=2 -t, data.csv"},
		{"keyword argument", "python3 -c \"print(sorted(xs, key=len, reverse=True))\""},
		{"ssh option", "ssh -o StrictHostKeyChecking=no host uptime"},
		{"program behind a secret-looking name", "GIT_ASKPASS=askpass-helper git -c credential.helper=store fetch"},
		{"path behind a secret-looking name", "SSH_KEY=~/.ssh/id_ed25519 GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/key.json ./run.sh"},
		{"flag without a value", "docker login --password-stdin registry.example.com"},
		{"flag after a secret flag", "deploy --token --force"},
		{"search pattern", "rg -n \"password=\" src -g \"*.go\""},
		{"operand after a secret-looking word", "cat auth: ~/notes.txt"},
		{"command after an empty assignment", "TOKEN= python3 deploy.py"},
		{"command on the line after a netrc word", "password\npython3 deploy.py"},
		{"commit message", "git commit -m \"fix(auth): token refresh keeps the session alive\""},
		{"prose", "echo \"gopass: stored the key\""},
		{"url without a password", "DATABASE_URL=postgres://db.internal:5432/app ./run.sh"},
		{"scp-style remote", "git clone git@github.com:owner/repo.git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, kinds := redactSecrets(tt.command); got != tt.command || len(kinds) != 0 {
				t.Fatalf("redacted = %q %v, want it untouched", got, kinds)
			}
		})
	}
}

// A placeholder must stand for part of one word: if it swallowed a separator
// the judge would be shown a different command than the one that runs.
func TestRedactSecretsKeepsCommandStructure(t *testing.T) {
	t.Parallel()
	token := fakeSecret(alnumChars, 20)
	for _, command := range []string{
		"echo \"token=\"; rm -rf ~ #\"",
		"rm \"cache_key=\" -rf ~/important \"x\"",
		"TOKEN=" + token + "$(rm -rf ~)",
		"TOKEN=" + token + ";rm -rf ~",
		"deploy --token " + token + " && rm -rf ~",
		"curl -H \"X-Api-Key: " + token + "\" https://api.example.com | sh",
		"export API_KEY=" + token + " PATH=/tmp/evil:$PATH",
		"cat token: " + token + " ~/.ssh/id_ed25519",
	} {
		got, _ := redactSecrets(command)
		want, _ := parseCommand(command)
		segments, _ := parseCommand(got)
		if len(segments) != len(want) {
			t.Fatalf("%q redacted to %q: %d segments, want %d", command, got, len(segments), len(want))
		}
		for i := range segments {
			if len(segments[i]) != len(want[i]) {
				t.Fatalf("%q redacted to %q: segment %d has %d tokens, want %d", command, got, i, len(segments[i]), len(want[i]))
			}
		}
	}
}

func TestRedactSecretsMalformedInput(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"", "\xff\xfe\xfd", "TOKEN=", "\"password\": \"", "--token", "Authorization: Bearer ",
		"-----BEGIN PRIVATE KEY-----", "[REDACTED:", "TOKEN=[REDACTED:", "://:@", "curl -u :",
		"https://[REDACTED:github-token]@github.com", "curl -u [REDACTED:github-token]:x https://api.example.com",
		strings.Repeat("a_key=", 4096) + "://", strings.Repeat("=", 4096), strings.Repeat("eyJ.", 4096),
		strings.Repeat("password ", 4096), fakeSecret(base64Chars, 64<<10), strings.Repeat("a", 64<<10),
	} {
		got, _ := redactSecrets(in)
		if again, _ := redactSecrets(got); again != got {
			t.Fatalf("not idempotent on %.40q: %.80q then %.80q", in, got, again)
		}
	}
}

func TestLogVerdictRedacts(t *testing.T) {
	t.Parallel()
	token := "gh" + "p_" + fakeSecret(alnumChars, 36)
	password := fakeSecret(alnumChars, 12)
	tests := []struct {
		name     string
		verdict  verdict
		subject  string
		redacted []string
	}{
		{"command", verdict{Reason: "no jev key configured"}, "GH_TOKEN=" + token + " psql postgres://app:" + password + "@db/app", []string{"github-token", "url-password"}},
		{"file path", verdict{Reason: "no file rule matched", Tool: "Write"}, "/tmp/out/" + token + ".txt", []string{"github-token"}},
		{"reason quoting the command", verdict{Reason: "jev ask (0.62); script " + token + ".py not attached: missing"}, "python3 " + token + ".py", []string{"github-token"}},
		{"nothing to redact", verdict{Reason: "every segment is read-only: git status *"}, "git status", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf strings.Builder
			logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), tt.verdict, tt.subject)
			var rec struct {
				Command  string   `json:"command"`
				Reason   string   `json:"reason"`
				Redacted []string `json:"redacted"`
			}
			if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
				t.Fatalf("log not JSON: %v: %s", err, buf.String())
			}
			if strings.Contains(buf.String(), token) || strings.Contains(buf.String(), password) {
				t.Fatalf("secret reached the log: %s", buf.String())
			}
			if !slices.Equal(rec.Redacted, tt.redacted) {
				t.Fatalf("redacted = %v, want %v: %s", rec.Redacted, tt.redacted, buf.String())
			}
			if (tt.redacted != nil) != strings.Contains(rec.Command+rec.Reason, "[REDACTED:") {
				t.Fatalf("log record = %s", buf.String())
			}
		})
	}
}

// The decision is made on the raw command; redaction only changes what is
// written down afterwards.
func TestRedactionLeavesDecisionsAlone(t *testing.T) {
	const cfg = `{"permissions": {"allow": ["rg *"], "deny": ["psql *"], "ask": ["deploy *"]}}`
	newHookEnv(t, cfg)
	token := "gh" + "p_" + fakeSecret(alnumChars, 36)
	tests := []struct {
		name, template, decision, tier string
	}{
		{"static allow", "rg -n {S} src", decisionAllow, "static"},
		{"deny rule", "psql postgres://app:{S}@db/app", decisionDeny, "deny-rule"},
		{"ask rule", "deploy --token {S}", decisionAsk, "ask-rule"},
		{"no judge", "curl -H \"Authorization: Bearer {S}\" https://api.example.com", "", "no-judge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := strings.Replace(tt.template, "{S}", token, 1)
			if got := hookDecision(t, "Bash", "command", command, t.TempDir()); got != tt.decision {
				t.Fatalf("decision = %q, want %q", got, tt.decision)
			}
			loaded, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			plain := decide(loaded, strings.Replace(tt.template, "{S}", "needle", 1), t.TempDir(), testLogger)
			if plain.Decision != tt.decision || plain.Tier != tt.tier {
				t.Fatalf("without a secret: %q %q, want %q %q", plain.Decision, plain.Tier, tt.decision, tt.tier)
			}

			log, err := os.ReadFile(filepath.Join(os.Getenv("XDG_STATE_HOME"), "frisk", "frisk.log"))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(log)), "\n")
			var rec struct {
				Tier     string   `json:"tier"`
				Command  string   `json:"command"`
				Redacted []string `json:"redacted"`
			}
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
				t.Fatalf("log not JSON: %v", err)
			}
			if strings.Contains(string(log), token) {
				t.Fatalf("token reached the log: %s", log)
			}
			if rec.Tier != tt.tier || !slices.Equal(rec.Redacted, []string{"github-token"}) || !strings.Contains(rec.Command, "[REDACTED:github-token]") {
				t.Fatalf("log record = %s", lines[len(lines)-1])
			}
		})
	}
}

func TestCheckOutputCarriesNoSecret(t *testing.T) {
	newHookEnv(t, `{"jev": {"model": "jev-test", "keyCmd": ["echo", "test-key"]}}`)
	fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.62})
	token := "gh" + "p_" + fakeSecret(alnumChars, 36)

	var out strings.Builder
	if code := run([]string{"check", "python3 /nonexistent/" + token + ".py"}, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out.String(), token) || !strings.Contains(out.String(), "script [REDACTED:github-token].py not attached: missing") {
		t.Fatalf("check output = %q", out.String())
	}
}

// judgedRequest is the part of the judge request the redaction tests read.
type judgedRequest struct {
	State     judgedState            `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type judgedState struct {
	Redactions []string     `json:"redactions"`
	Untrusted  jevUntrusted `json:"untrusted"`
}

func TestHookKeepsSecretFromJudgeAndLog(t *testing.T) {
	newHookEnv(t, `{"jev": {"model": "jev-test", "keyCmd": ["echo", "test-key"]}}`)
	_, capture := fakeJevCapture(t, jevAnswer{Choice: "ask", Confidence: 0.62})
	token := "gh" + "p_" + fakeSecret(alnumChars, 36)
	const template = "curl -X DELETE -H \"Authorization: token {S}\" https://api.example.com/v1/items/7"

	if got := hookDecision(t, "Bash", "command", strings.Replace(template, "{S}", token, 1), t.TempDir()); got != decisionAsk {
		t.Fatalf("decision = %q, want ask", got)
	}

	raw, _ := capture.request()
	var req judgedRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("request not JSON: %v", err)
	}
	if strings.Contains(raw, token) {
		t.Fatalf("token reached the judge: %s", raw)
	}
	if want := strings.Replace(template, "{S}", "[REDACTED:github-token]", 1); req.State.Untrusted.Command != want {
		t.Fatalf("untrusted command = %q, want %q", req.State.Untrusted.Command, want)
	}
	if !slices.Equal(req.State.Redactions, []string{"github-token"}) {
		t.Fatalf("redactions = %v", req.State.Redactions)
	}
	if !strings.Contains(req.Questions["decision"].Instructions, "`[REDACTED:kind]` placeholder") {
		t.Fatalf("instructions do not explain the placeholder: %q", req.Questions["decision"].Instructions)
	}

	log, err := os.ReadFile(filepath.Join(os.Getenv("XDG_STATE_HOME"), "frisk", "frisk.log"))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Tier     string   `json:"tier"`
		Command  string   `json:"command"`
		Redacted []string `json:"redacted"`
	}
	if err := json.Unmarshal(log, &rec); err != nil {
		t.Fatalf("log not one JSON record: %v: %s", err, log)
	}
	if strings.Contains(string(log), token) {
		t.Fatalf("token reached the log: %s", log)
	}
	if rec.Tier != tierJudge || rec.Command != req.State.Untrusted.Command || !slices.Equal(rec.Redacted, []string{"github-token"}) {
		t.Fatalf("log record = %s", log)
	}
}

func TestJudgeRequestWithoutSecretsIsUnchanged(t *testing.T) {
	cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "allow", Confidence: 0.98})
	decide(cfg, "terraform plan -var token=$TOKEN", t.TempDir(), testLogger)

	raw, _ := capture.request()
	var req judgedRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("request not JSON: %v", err)
	}
	if strings.Contains(raw, "redactions") || strings.Contains(raw, "REDACTED") {
		t.Fatalf("request mentions redaction without any: %s", raw)
	}
	if req.State.Untrusted.Command != "terraform plan -var token=$TOKEN" {
		t.Fatalf("untrusted command = %q", req.State.Untrusted.Command)
	}
}

// A placeholder that swallowed shell syntax could hide what runs, so such a
// command is not judged at all.
func TestJudgeWithholdsCommandWhenSecretCarriesShellSyntax(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIV" + "ATE KEY-----\n" + fakeSecret(base64Chars, 64) + "\n-----END OPENSSH PRIV" + "ATE KEY-----"
	tests := []struct {
		name    string
		command string
		kind    string
	}{
		{"private key block", "echo \"" + key + "\" > deploy.pem", "private-key"},
		{"lines between key markers", "echo -----BEGIN PRIV" + "ATE KEY-----\n/tmp/payload\necho -----END PRIV" + "ATE KEY-----", "private-key"},
		{"quoted password with operators", "PGPASSWORD='p4ss&w(rd);x' psql -h db -c 'select 1'", "named-secret"},
		{"command inside a nested quote", "bash -c 'echo \"token=\"x1;reboot'", "named-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, capture := fakeJevCapture(t, jevAnswer{Choice: "allow", Confidence: 0.98})
			v := decide(cfg, tt.command, t.TempDir(), testLogger)
			if calls, _ := capture.last(); calls != 0 {
				t.Fatalf("judge was called %d times", calls)
			}
			if v.Decision != "" || v.Tier != tierJudge || v.Reason != "secret carries shell syntax, command not sent" {
				t.Fatalf("verdict = %q %q %q", v.Decision, v.Tier, v.Reason)
			}
			if _, kinds := redactSecrets(tt.command); !slices.Equal(kinds, []string{tt.kind}) {
				t.Fatalf("kinds = %v, want [%s]", kinds, tt.kind)
			}
		})
	}
}

type hookEnv struct {
	home, cfgDir string
}

// newHookEnv points HOME and XDG_CONFIG_HOME at temp dirs and writes the
// config; tests using it cannot run in parallel.
func newHookEnv(t *testing.T, cfg string) hookEnv {
	t.Helper()
	e := hookEnv{home: t.TempDir(), cfgDir: t.TempDir()}
	t.Setenv("HOME", e.home)
	t.Setenv("XDG_CONFIG_HOME", e.cfgDir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if cfg != "" {
		if err := os.MkdirAll(filepath.Join(e.cfgDir, "frisk"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(e.cfgDir, "frisk", "config.json"), []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func hookDecision(t *testing.T, tool, key, target, cwd string) string {
	t.Helper()
	in, err := json.Marshal(map[string]any{
		"tool_name": tool, "tool_input": map[string]string{key: target}, "cwd": cwd,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if code := run([]string{"hook"}, strings.NewReader(string(in)), &out); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if out.String() == "" {
		return ""
	}
	var resp map[string]map[string]string
	if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
		t.Fatalf("output not JSON: %v: %s", err, out.String())
	}
	return resp["hookSpecificOutput"]["permissionDecision"]
}

func TestFileToolGuardrails(t *testing.T) {
	e := newHookEnv(t, "")
	cfgFile := filepath.Join(e.cfgDir, "frisk", "config.json")
	settings := filepath.Join(e.home, ".claude", "settings.json")
	hook := filepath.Join(e.home, ".claude", "hooks", "gate.sh")
	tests := []struct{ name, tool, key, path, want string }{
		{"frisk config", "Write", "file_path", cfgFile, decisionAsk},
		{"claude settings", "Edit", "file_path", settings, decisionAsk},
		{"claude local settings", "Edit", "file_path", filepath.Join(e.home, ".claude", "settings.local.json"), decisionAsk},
		{"claude hooks dir", "Write", "file_path", hook, decisionAsk},
		{"notebook via notebook_path", "NotebookEdit", "notebook_path", settings, decisionAsk},
		{"dotdot cleaned into guardrail", "Edit", "file_path", filepath.Join(e.home, "x", "..", ".claude", "settings.json"), decisionAsk},
		{"ordinary file", "Edit", "file_path", filepath.Join(e.home, "proj", "main.go"), ""},
		{"sibling of hooks dir", "Edit", "file_path", filepath.Join(e.home, ".claude", "hooks-old", "a"), ""},
		{"wrong key is silent", "Edit", "notebook_path", settings, ""},
	}
	for _, tt := range tests {
		if got := hookDecision(t, tt.tool, tt.key, tt.path, e.home); got != tt.want {
			t.Errorf("%s: decision = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestFileToolRelativePathUsesCwd(t *testing.T) {
	e := newHookEnv(t, "")
	if got := hookDecision(t, "Edit", "file_path", "settings.json", filepath.Join(e.home, ".claude")); got != decisionAsk {
		t.Fatalf("relative guardrail path = %q, want ask", got)
	}
	if got := hookDecision(t, "Edit", "file_path", "../.claude/settings.json", filepath.Join(e.home, "proj")); got != decisionAsk {
		t.Fatalf("relative dotdot guardrail path = %q, want ask", got)
	}
	if got := hookDecision(t, "Edit", "file_path", "settings.json", e.home); got != "" {
		t.Fatalf("relative ordinary path = %q, want silence", got)
	}
}

func TestFileToolSymlinkToGuardrail(t *testing.T) {
	e := newHookEnv(t, "")
	settings := filepath.Join(e.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "innocent.json")
	if err := os.Symlink(settings, link); err != nil {
		t.Fatal(err)
	}
	if got := hookDecision(t, "Write", "file_path", link, e.home); got != decisionAsk {
		t.Fatalf("symlink to guardrail = %q, want ask", got)
	}
}

func TestFileToolConfigRules(t *testing.T) {
	cfg := `{"permissions":{
		"deny":["Edit(~/.claude/**)","Edit(/secrets/*.env)"],
		"ask":["Edit(/asked/**)"],
		"allow":["Edit(~/notes/**)","Edit(/a/b/**)","Edit(~/.config/**)"]}}`
	e := newHookEnv(t, cfg)
	settings := filepath.Join(e.home, ".claude", "settings.json")
	tests := []struct{ name, path, want string }{
		{"deny beats builtin ask", settings, decisionDeny},
		{"deny glob", "/secrets/prod.env", decisionDeny},
		{"deny glob does not cross dirs", "/secrets/sub/prod.env", ""},
		{"ask rule", "/asked/deep/file", decisionAsk},
		{"tilde expands", filepath.Join(e.home, "notes", "todo.md"), decisionAllow},
		{"dir itself matches /**", "/a/b", decisionAllow},
		{"under dir matches /**", "/a/b/c/d", decisionAllow},
		{"prefix boundary respected", "/a/bc/x", ""},
		{"allow does not override builtin ask", filepath.Join(e.cfgDir, "frisk", "config.json"), decisionAsk},
	}
	for _, tt := range tests {
		if got := hookDecision(t, "Write", "file_path", tt.path, "/"); got != tt.want {
			t.Errorf("%s: decision = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := hookDecision(t, "NotebookEdit", "notebook_path", "/a/b/n.ipynb", "/"); got != decisionAllow {
		t.Errorf("Edit rules must apply to NotebookEdit, got %q", got)
	}
}

func TestBareRulesAndFileRulesStaySeparate(t *testing.T) {
	bare := []string{"*", "rm *"}
	if rule := matchFileRules(bare, "/a/x"); rule != "" {
		t.Fatalf("bare rules matched a file tool: %q", rule)
	}
	fileOnly := &config{Permissions: permissionsConfig{
		Deny: []string{"Edit(/a/**)", "Edit(git status)"}, Ask: []string{"Edit(*)"}, Allow: []string{"Edit(*)"},
	}}
	for _, cmd := range []string{"git status", "Edit(/a/x)", "ls /a/x"} {
		if v := decide(fileOnly, cmd, t.TempDir(), testLogger); v.Decision != "" {
			t.Errorf("Edit rule matched Bash command %q: %+v", cmd, v)
		}
	}
}

func TestVersionPrintsOneLine(t *testing.T) {
	newHookEnv(t, "")
	for _, arg := range []string{"version", "--version", "-V"} {
		var out strings.Builder
		code := run([]string{arg}, strings.NewReader(""), &out)
		if code != 0 || strings.TrimSpace(out.String()) == "" || strings.Count(out.String(), "\n") != 1 {
			t.Fatalf("%s: code = %d, out = %q", arg, code, out.String())
		}
	}
}

func validateOutput(t *testing.T, cfg string, args ...string) (string, int) {
	t.Helper()
	newHookEnv(t, cfg)
	var out strings.Builder
	code := run(append([]string{"validate"}, args...), strings.NewReader(""), &out)
	return out.String(), code
}

func TestValidateMissingConfig(t *testing.T) {
	out, code := validateOutput(t, "")
	if code != 0 || !strings.Contains(out, "does not exist: nothing is allowed statically and the judge is off") {
		t.Fatalf("code = %d, out = %s", code, out)
	}
}

// An allow list written for the builtins frisk once had still loads; validate
// says the marker no longer brings any rules.
func TestValidateDefaultsInAllowWarns(t *testing.T) {
	out, code := validateOutput(t, `{"permissions":{"allow":["$defaults","just check"]}}`)
	want := `warning: permissions.allow[0]: "$defaults" adds nothing: frisk has no default allow list`
	if code != 0 || strings.Contains(out, "error:") || !strings.Contains(out, want) || !strings.Contains(out, "config.example.json") {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	if strings.Contains(out, "permissions.allow has no rules") {
		t.Fatalf("a list with a rule reported as empty: %s", out)
	}

	out, code = validateOutput(t, `{"permissions":{"allow":["$defaults"]}}`)
	if code != 0 || !strings.Contains(out, want) || !strings.Contains(out, "info: permissions.allow has no rules: nothing is allowed statically") {
		t.Fatalf("marker only: code = %d, out = %s", code, out)
	}
}

func TestValidateValidConfig(t *testing.T) {
	cfg := `{"permissions":{"deny":["rm -rf *","Edit(~/.ssh/**)"],"allow":["ls *","just check"]}}`
	out, code := validateOutput(t, cfg)
	if code != 0 || strings.Contains(out, "error:") || strings.Contains(out, "warning:") {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	if !strings.Contains(out, "info: config ") || !strings.Contains(out, "judge disabled (no jev.keyCmd)") {
		t.Fatalf("out = %s", out)
	}
}

func TestValidateFindings(t *testing.T) {
	tests := []struct {
		name, cfg, want string
		code            int
	}{
		{"malformed json", `{nope`, "error: parsing", 1},
		{"unknown field", `{"nope":{}}`, "error: parsing", 1},
		{"empty rule", `{"permissions":{"ask":["  "]}}`, "error: permissions.ask[0]: empty rule", 1},
		{"bad glob", `{"permissions":{"deny":["cat ["]}}`, "error: permissions.deny[0]", 1},
		{"bad file glob", `{"permissions":{"allow":["Edit([/**)"]}}`, "error: permissions.allow[0]", 1},
		{"empty Edit pattern", `{"permissions":{"deny":["Edit()"]}}`, "error: permissions.deny[0]: \"Edit()\" has an empty path pattern", 1},
		{"bare star in deny warns", `{"permissions":{"deny":["*"]}}`, "warning: permissions.deny[0]: \"*\" matches every command", 0},
		{"bare star in ask warns", `{"permissions":{"ask":["*"]}}`, "warning: permissions.ask[0]", 0},
		{"defaults marker is fine", `{"permissions":{"deny":["$defaults"]}}`, "", 0},
		{"unknown judge decision", `{"judge":{"decisions":["allow","defer"]}}`, `judge.decisions ["allow" "defer"]: want a non-empty list`, 1},
		{"empty judge decisions", `{"judge":{"decisions":[]}}`, "judge.decisions []: want a non-empty list", 1},
		{"narrowed judge decisions", `{"judge":{"decisions":["deny","allow"]}}`, "info: judge.decisions: deny, allow\n", 0},
	}
	for _, tt := range tests {
		out, code := validateOutput(t, tt.cfg)
		if code != tt.code || !strings.Contains(out, tt.want) {
			t.Errorf("%s: code = %d, out = %s", tt.name, code, out)
		}
		if tt.name == "defaults marker is fine" && (strings.Contains(out, "error:") || strings.Contains(out, "warning:")) {
			t.Errorf("$defaults flagged: %s", out)
		}
	}
}

func TestValidateJudgeListStates(t *testing.T) {
	cfg := `{"judge":{"environment":["mine"],"allow":["$defaults","more"],"soft_deny":["$defaults"]}}`
	out, code := validateOutput(t, cfg)
	if code != 0 {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	for _, want := range []string{
		"info: judge.environment: replaces the builtins",
		"info: judge.allow: extends the builtins",
		"info: judge.soft_deny: extends the builtins",
		"info: judge.hard_deny: unset, builtins apply",
		"info: judge.decisions: allow, ask, deny\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
}

func TestValidateKeyCmd(t *testing.T) {
	out, code := validateOutput(t, `{"jev":{"keyCmd":["echo","hunter2-not-for-output"],"model":"m1","timeoutMs":1500}}`)
	if code != 0 || !strings.Contains(out, "jev.keyCmd succeeded, output non-empty") ||
		!strings.Contains(out, `jev.model: "m1"`) || !strings.Contains(out, "jev.timeout: 1.5s") {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("key leaked into output: %s", out)
	}

	out, code = validateOutput(t, `{"jev":{"keyCmd":["false"]}}`)
	if code != 1 || !strings.Contains(out, "error: jev.keyCmd failed") {
		t.Fatalf("failing keyCmd: code = %d, out = %s", code, out)
	}

	out, code = validateOutput(t, `{"jev":{"keyCmd":["true"]}}`)
	if code != 1 || !strings.Contains(out, "error: jev.keyCmd failed") {
		t.Fatalf("empty keyCmd output: code = %d, out = %s", code, out)
	}
}

func TestValidateLive(t *testing.T) {
	fakeJev(t, jevAnswer{Choice: "allow", Confidence: 0.98})
	cfg := `{"jev":{"keyCmd":["echo","test-key"],"model":"jev-test"}}`
	out, code := validateOutput(t, cfg, "--live")
	if code != 0 || !strings.Contains(out, "live judge call for `true`: allow") || !strings.Contains(out, "ms") {
		t.Fatalf("code = %d, out = %s", code, out)
	}
	if strings.Contains(out, "test-key") {
		t.Fatalf("key leaked into output: %s", out)
	}

	out, _ = validateOutput(t, cfg)
	if strings.Contains(out, "live judge call") {
		t.Fatalf("no live call without --live: %s", out)
	}

	prev := jevEndpoint
	jevEndpoint = "http://127.0.0.1:1"
	t.Cleanup(func() { jevEndpoint = prev })
	out, code = validateOutput(t, cfg, "--live")
	if code != 1 || !strings.Contains(out, "error: live judge call failed") {
		t.Fatalf("unreachable judge: code = %d, out = %s", code, out)
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
			Allow: exampleAllow(t),
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
		{"stderr merge is static", "ls 2>&1 | tail -1", decisionAllow, "static"},
		{"null redirect is static", "git status >/dev/null 2>&1", decisionAllow, "static"},
		{"null input is static", "cat < /dev/null", decisionAllow, "static"},
		{"deny still sees through a redirect", "gopass show -o k 2>/dev/null", decisionDeny, "deny-rule"},
		{"heredoc never static", "cat <<EOF\nhi\nEOF", "", "no-judge"},
		{"deny still sees a heredoc body", "cat > notes.txt <<EOF\ngopass show -o k\nEOF", decisionDeny, "deny-rule"},
		{"deny still sees past a heredoc body", "cat > notes.txt <<'EOF'\nit's text\nEOF\ngopass show -o k", decisionDeny, "deny-rule"},
		{"comment never static", "ls # trailing note", "", "no-judge"},
		{"quote in a comment hides no command", "echo hi # it's\nrm -rf /tmp/x # '", "", "no-judge"},
		{"double quote in a comment hides no command", "echo hi # say \"\nrm -rf /tmp/x # \"", "", "no-judge"},
		{"deny still sees past a comment with a quote", "echo hi # it's\ngopass show -o k # '", decisionDeny, "deny-rule"},
		{"ask still sees past a comment with a quote", "echo hi # say \"\nssh prod uptime # \"", decisionAsk, "ask-rule"},
		{"escaped quote hides no command", `echo "a\"b\"c" ; rm -rf ~/x ; echo \"`, "", "no-judge"},
		{"deny still sees past an escaped quote", `echo "a\"b\"c" ; gopass show -o k ; echo \"`, decisionDeny, "deny-rule"},
		{"escaped quotes stay static", `echo "a\"b\"c" ; ls ; echo \"`, decisionAllow, "static"},
		{"ansi-c escaped quote hides no command", `echo $'a\'' ; rm -rf ~/x ; echo \'`, "", "no-judge"},
		{"deny still sees past an ansi-c escaped quote", `echo $'a\'' ; gopass show -o k ; echo \'`, decisionDeny, "deny-rule"},
		{"ansi-c quoting hides no flag", "fd . $'-x' rm", "", "no-judge"},
		{"locale quoting hides no flag", `fd . $"-x" rm`, "", "no-judge"},
		{"line continuation hides no flag", "fd . \\\n-x rm", "", "no-judge"},
		{"line continuation hides no credential path", "cat \\\n.netrc", "", "no-judge"},
		{"continued command stays static", "ls \\\n  -la", decisionAllow, "static"},
		{"brace expansion hides no flag", "find . {-delete,-print}", "", "no-judge"},
		{"brace expansion after a dash hides no flag", "find . -{delete,print}", "", "no-judge"},
		{"brace expansion hides no exec", "fd . {-x,rm}", "", "no-judge"},
		{"brace expansion hides no dotenv", "cat {README.md,.env}", "", "no-judge"},
		{"brace list never static", "cat src/{a,b}.go", "", "no-judge"},
		{"glob qualifier never static", "ls *(e:'id':)", "", "no-judge"},
		{"glob qualifier without code never static", "ls *(om[1])", "", "no-judge"},
		{"stash ref braces stay static", "git stash show stash@{0}", decisionAllow, "static"},
		{"escaped parentheses stay static", `find . \( -name a -o -name b \)`, decisionAllow, "static"},
		{"quoted hash stays static", "echo '#not a comment'", decisionAllow, "static"},
		{"hash inside a word stays static", "echo a#b", decisionAllow, "static"},
		{"ask still sees a heredoc owner", "ssh prod bash <<EOF\nuptime\nEOF", decisionAsk, "ask-rule"},
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
		{"echo plain var never static", "echo $HOME", "", "no-judge"},
		{"variable as arguments never static", "fd $ARGS", "", "no-judge"},
		{"variable as a path never static", "cat $F", "", "no-judge"},
		{"quoted variable never static", `cat "$F"`, "", "no-judge"},
		{"variable as a pattern never static", "rg $PAT .", "", "no-judge"},
		{"zsh split flag never static", "fd $=ARGS", "", "no-judge"},
		{"positional parameter never static", "cat $1", "", "no-judge"},
		{"exit status stays static", `ls; echo "rc=$?"`, decisionAllow, "static"},
		{"pattern ending in a dollar stays static", `rg "foo$" f.txt`, decisionAllow, "static"},
		{"deny sees through a literal variable", "X=show; gopass $X -o k", decisionDeny, "deny-rule"},
		{"ask sees through a literal variable", "H=prod; ssh $H uptime", decisionAsk, "ask-rule"},
		{"gopass ls stays static", "gopass ls", decisionAllow, "static"},
		{"awk print stays static", "awk '{print $1}' f.txt", decisionAllow, "static"},
		{"awk field separator stays static", "awk -F: '{print $1}' /etc/passwd", decisionAllow, "static"},
		{"awk system never static", `awk 'BEGIN{system("id")}'`, "", "no-judge"},
		{"awk pipe never static", `awk '{print | "sh"}' f.txt`, "", "no-judge"},
		{"awk program file never static", "awk -f prog.awk f.txt", "", "no-judge"},
		{"awk environ never static", `awk 'BEGIN{print ENVIRON["HOME"]}'`, "", "no-judge"},
		{"awk redirect never static", `awk '{print > "out.txt"}' f.txt`, "", "no-judge"},
		{"awk append never static", `awk '{print >> "out.txt"}' f.txt`, "", "no-judge"},
		{"awk printf redirect never static", `awk '{printf "%s\n", $1 > "/tmp/out"}' f.txt`, "", "no-judge"},
		{"awk getline from a file never static", `awk 'BEGIN{while ((getline l < "/etc/hosts") > 0) print l}'`, "", "no-judge"},
		{"awk comparison stays with the judge", "awk '$3 > 10' f.txt", "", "no-judge"},
		{"gawk extension load never static", `awk '@load "filefuncs"; BEGIN{print 1}'`, "", "no-judge"},
		{"gawk include never static", `awk '@include "lib.awk"; BEGIN{f()}'`, "", "no-judge"},
		{"awk field expression stays static", "awk '{print $(NF-1)}' f.txt", decisionAllow, "static"},
		{"quoted arrow stays static", `rg "=>" src`, decisionAllow, "static"},
		{"quoted tag stays static", "rg '<div>' src", decisionAllow, "static"},
		{"escaped angle bracket stays static", `rg a\>b src`, decisionAllow, "static"},
		{"sed with angle brackets stays static", "sed 's/<b>//g' f.html", decisionAllow, "static"},
		{"jq comparison stays static", "jq '.[] | select(.n > 3)' f.json", decisionAllow, "static"},
		{"yq comparison stays static", "yq '.a > 1' f.yaml", decisionAllow, "static"},
		{"quoted redirect-looking text stays static", `echo "a > b"`, decisionAllow, "static"},
		{"single-quoted substitution stays static", `rg '\$\(' src`, decisionAllow, "static"},
		{"single-quoted backtick stays static", "rg '`' README.md", decisionAllow, "static"},
		{"double-quoted substitution never static", `echo "$(rm -rf x)"`, "", "no-judge"},
		{"double-quoted backtick never static", "echo \"`rm -rf x`\"", "", "no-judge"},
		{"sed w behind a quoted bracket never static", "sed -n 's/<a>/x/w out.txt' f", "", "no-judge"},
		{"sed e with a quoted redirect never static", "sed '1e echo hi > /tmp/x' f", "", "no-judge"},
		{"sed r stays static", "sed '1r notes.txt' f", decisionAllow, "static"},
		{"sed r of a credential file never static", "sed '1r /home/me/.netrc' f", "", "no-judge"},
		{"find exec with a quoted redirect never static", `find . -exec sh -c 'echo > x' \;`, "", "no-judge"},
		{"jq env behind a comparison never static", "jq -n 'env | length > 0'", "", "no-judge"},
		{"real redirect after a quoted one never static", `echo "a > b" > c`, "", "no-judge"},
		{"assignment then read stays static", "S=/tmp/x; cat $S/f", decisionAllow, "static"},
		{"assignment in a chain stays static", `D=src && ls "$D" | head`, decisionAllow, "static"},
		{"two assignments stay static", "A=src B=docs; ls $A $B", decisionAllow, "static"},
		{"assignment on its own line stays static", "F=README.md\nwc -l $F", decisionAllow, "static"},
		{"assignment alone has no rule", "X=1", "", "no-judge"},
		{"assignments alone have no rule", "X=1; Y=2", "", "no-judge"},
		{"flag through a variable never static", "A=-x; fd . $A rm", "", "no-judge"},
		{"long flag through a variable never static", "A=--pre=sh; rg $A foo", "", "no-judge"},
		{"sed script through a variable never static", "S=w/tmp/out.txt; sed -n \"$S\" f", "", "no-judge"},
		{"verb through a variable needs a rule", "V=rm; $V -rf x", "", "no-judge"},
		{"credential path through a variable never static", "F=~/.ssh/id_rsa; cat $F", "", "no-judge"},
		{"credential path assigned never static", "F=~/.netrc; ls", "", "no-judge"},
		{"credential glob assigned never static", "F=~/.ssh/*; ls", "", "no-judge"},
		{"secret-named assignment never static", "GH_TOKEN=abc; gh pr list", "", "no-judge"},
		{"secret value copied never static", "X=$GH_TOKEN; ls", "", "no-judge"},
		{"substitution in an assignment never static", "X=$(rm -rf x); ls", "", "no-judge"},
		{"backtick in an assignment never static", "X=`rm -rf x`; ls", "", "no-judge"},
		{"variable assigned twice never static", "S=/tmp/x; S=~/.ssh; ls $S", "", "no-judge"},
		{"variable reassigned in a prefix never static", "S=/tmp/x; S=/y cat $S", "", "no-judge"},
		{"PATH assignment never static", "PATH=/tmp/evil; ls", "", "no-judge"},
		{"zsh path array never static", "path=/tmp/evil; ls", "", "no-judge"},
		{"function path never static", "FPATH=/tmp/evil; ls", "", "no-judge"},
		{"trace prompt never static", "PS4='$(id)'; ls", "", "no-judge"},
		{"child shell options never static", "SHELLOPTS=xtrace ls", "", "no-judge"},
		{"startup file never static", "ZDOTDIR=/tmp/evil ls", "", "no-judge"},
		{"ENV never static", "ENV=/tmp/evil ls", "", "no-judge"},
		{"zsh null command never static", "NULLCMD=/tmp/evil; ls", "", "no-judge"},
		{"redirect with no command never static", "ls; >/dev/null", "", "no-judge"},
		{"zsh argv0 never static", "ARGV0=rm ls x", "", "no-judge"},
		{"home never static", "HOME=. git status", "", "no-judge"},
		{"xdg config home never static", "XDG_CONFIG_HOME=/tmp/x git status", "", "no-judge"},
		{"git dir never static", "GIT_DIR=/tmp/evil/.git git status", "", "no-judge"},
		{"git trace never static", "GIT_TRACE=/tmp/out git status", "", "no-judge"},
		{"less options never static", "LESS=-o/tmp/x less f", "", "no-judge"},
		{"editor never static", "EDITOR=/tmp/evil ls", "", "no-judge"},
		{"tool editor never static", "KUBE_EDITOR=/tmp/evil kubectl get pods", "", "no-judge"},
		{"tool config never static", "AWS_CONFIG_FILE=/tmp/x ls", "", "no-judge"},
		{"python startup never static", "PYTHONSTARTUP=/tmp/x ls", "", "no-judge"},
		{"node options never static", "NODE_OPTIONS=--require=/tmp/x ls", "", "no-judge"},
		{"perl options never static", "PERL5OPT=-Mevil ls", "", "no-judge"},
		{"claude config dir never static", "CLAUDE_CONFIG_DIR=/tmp/x; ls", "", "no-judge"},
		{"proxy never static", "HTTPS_PROXY=http://evil:8080 gh pr list", "", "no-judge"},
		{"lowercase proxy never static", "https_proxy=http://evil:8080 gh pr list", "", "no-judge"},
		{"trust root never static", "SSL_CERT_FILE=/tmp/ca.pem gh pr list", "", "no-judge"},
		{"npm config never static", "npm_config_script_shell=/tmp/x ls", "", "no-judge"},
		{"printf into a variable never static", "printf -v PATH %s /tmp/evil; ls", "", "no-judge"},
		{"printf attached variable never static", "printf -vPATH %s /tmp/evil; ls", "", "no-judge"},
		{"printf stays static", `printf '%s\n' hi`, decisionAllow, "static"},
		{"node env stays static", "NODE_ENV=test ls", decisionAllow, "static"},
		{"python unbuffered stays static", "PYTHONUNBUFFERED=1 ls", decisionAllow, "static"},
		{"term stays static", "TERM=dumb ls", decisionAllow, "static"},
		{"yq read stays static", "yq .a f.yaml", decisionAllow, "static"},
		{"yq in-place never static", "yq -i .a=1 f.yaml", "", "no-judge"},
		{"yq env never static", "yq '.a = strenv(X)' f.yaml", "", "no-judge"},
		{"jq env field stays static", "jq .spec.env f.json", decisionAllow, "static"},
		{"jq env dump never static", "jq -n env", "", "no-judge"},
		{"jq ENV never static", "jq -n '$ENV.HOME'", "", "no-judge"},
		{"jq program file never static", "jq -f prog.jq f.json", "", "no-judge"},
		{"jq bundled program file never static", "jq -rf prog.jq f.json", "", "no-judge"},
		{"jq long program file never static", "jq --from-file prog.jq f.json", "", "no-judge"},
		{"jq attached program file never static", "jq --from-file=prog.jq f.json", "", "no-judge"},
		{"jq module include never static", `jq 'include "./m"; f' f.json`, "", "no-judge"},
		{"jq module import never static", `jq -L . 'import "m" as m; m::f' f.json`, "", "no-judge"},
		{"jq raw output stays static", "jq -r .f f.json", decisionAllow, "static"},
		{"jq long flags stay static", "jq --arg f x --raw-output '.[$f]' f.json", decisionAllow, "static"},
		{"jq include field stays static", "jq .include f.json", decisionAllow, "static"},
		{"yq program file never static", "yq --from-file prog.yq f.yaml", "", "no-judge"},
		{"yq short program file never static", "yq -f prog.jq f.yaml", "", "no-judge"},
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
		{"ssh dir glob never static", "cat ~/.ssh/*", "", "no-judge"},
		{"aws dir glob never static", "cat ~/.aws/*", "", "no-judge"},
		{"gopass store glob never static", "cat ~/.config/gopass/*", "", "no-judge"},
		{"gopass store deep glob never static", "cat ~/.config/gopass/stores/*/age/*", "", "no-judge"},
		{"gnupg dir glob never static", "ls ~/.gnupg/*", "", "no-judge"},
		{"kube dir glob never static", "cat ~/.kube/*", "", "no-judge"},
		{"docker dir glob never static", "cat ~/.docker/*", "", "no-judge"},
		{"gh config glob never static", "cat ~/.config/gh/*", "", "no-judge"},
		{"pem glob never static", "cat certs/*.pem", "", "no-judge"},
		{"key glob never static", "cat certs/*.key", "", "no-judge"},
		{"cargo dir glob never static", "cat ~/.cargo/*", "", "no-judge"},
		{"cargo credentials glob never static", "cat ~/.cargo/cred*", "", "no-judge"},
		{"cargo credentials question mark never static", "cat ~/.cargo/c?edentials.toml", "", "no-judge"},
		{"cargo credentials bracket never static", "cat ~/.cargo/[c]redentials.toml", "", "no-judge"},
		{"cargo credentials brace never static", "cat ~/.cargo/{registry,credentials.toml}", "", "no-judge"},
		{"cargo as a brace alternative never static", "cat ~/{.cargo,x}/c*", "", "no-judge"},
		{"cargo hidden-name glob never static", "cat ~/.carg*/registry/src/x", "", "no-judge"},
		{"cargo glob behind dotdot never static", "cat ~/.cargo/registry/../cred*", "", "no-judge"},
		{"cargo glob behind a deep dotdot never static", "cat ~/.cargo/registry/src/*/../../../c*", "", "no-judge"},
		{"cargo recursive glob never static", "cat ~/.cargo/**/credentials.toml", "", "no-judge"},
		{"cargo registry sources stay static", "ls ~/.cargo/registry/src/*", decisionAllow, "static"},
		{"cargo crate glob stays static", "ls -d ~/.cargo/registry/src/*/serde-1.*", decisionAllow, "static"},
		{"cargo crate file stays static", "cat ~/.cargo/registry/src/*/tokio-1.40.0/Cargo.toml", decisionAllow, "static"},
		{"cargo bin glob stays static", "ls ~/.cargo/bin/*", decisionAllow, "static"},
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

// Core ships no allow rules: what settles statically is what the config lists.
func TestOnlyConfigRulesAllow(t *testing.T) {
	t.Parallel()
	commands := []string{"ls", "pwd", "true", "cat README.md", "git status", "echo hi", "cd /tmp", "just check"}
	for name, cfg := range map[string]*config{
		"no config":      {},
		"empty list":     {Permissions: permissionsConfig{Allow: []string{}}},
		"marker only":    {Permissions: permissionsConfig{Allow: []string{defaultsMarker}}},
		"deny rule only": {Permissions: permissionsConfig{Deny: []string{"rm *"}}},
	} {
		for _, command := range commands {
			if v := decide(cfg, command, t.TempDir(), testLogger); v.Decision != "" || v.Tier != "no-judge" {
				t.Errorf("%s: decide(%q) = (%q, %q), want silence", name, command, v.Decision, v.Tier)
			}
		}
	}

	cfg := &config{Permissions: permissionsConfig{Allow: []string{defaultsMarker, "just check"}}}
	if v := decide(cfg, "ls", t.TempDir(), testLogger); v.Decision != "" {
		t.Fatalf("ls has no rule and the marker brings none, got %q", v.Decision)
	}
	if v := decide(cfg, "just check", t.TempDir(), testLogger); v.Decision != decisionAllow {
		t.Fatalf("just check should be allowed, got %q", v.Decision)
	}
	// The marker is not a rule: a command spelled like it matches nothing.
	if v := decide(cfg, `'$defaults'`, t.TempDir(), testLogger); v.Decision != "" {
		t.Fatalf("the marker matched a command, got %q", v.Decision)
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
			"usage":   map[string]int{"input_tokens": 812, "output_tokens": 9},
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
	v.Entry = "check"
	logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), v, "terraform plan")
	var rec struct {
		Probs  map[string]float64 `json:"probs"`
		Model  string             `json:"model"`
		Entry  string             `json:"entry"`
		Input  int                `json:"input_tokens"`
		Output int                `json:"output_tokens"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
		t.Fatalf("log not JSON: %v: %s", err, buf.String())
	}
	if rec.Model != "jev-1.13.0" || rec.Probs["ask"] != 0.04 || len(rec.Probs) != 4 {
		t.Fatalf("log record = %s", buf.String())
	}
	if rec.Entry != "check" || rec.Input != 812 || rec.Output != 9 {
		t.Fatalf("entry/usage missing from log record: %s", buf.String())
	}

	buf.Reset()
	logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), verdict{Tier: "static"}, "ls")
	if strings.Contains(buf.String(), "tokens") || strings.Contains(buf.String(), "entry") {
		t.Fatalf("unset entry and usage must be omitted: %s", buf.String())
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

func TestJudgeDecisions(t *testing.T) {
	softClosest := `closest rule: soft_deny "` + builtinJudge.SoftDeny[0][:maxRuleChars] + `..." (0.71)`
	const hardClosest = `closest rule: hard_deny "Reading, printing, or transmitting credentials or secret material. Mod..." (0.80)`
	noAsk, noAllow := []string{decisionAllow, decisionDeny}, []string{decisionAsk, decisionDeny}
	r1 := jevAnswer{Choice: "r1", Confidence: 0.80}
	tests := []struct {
		name      string
		decisions []string
		command   string
		answers   map[string]any
		decision  string
		reason    string
	}{
		{
			"ask is withheld", noAsk, "terraform apply",
			map[string]any{
				"decision": jevAnswer{Choice: "ask", Confidence: 0.62, Probabilities: map[string]float64{"allow": 0.30, "ask": 0.62, "deny": 0.08}},
				"ask_rule": jevAnswer{Choice: "r1", Confidence: 0.71},
			},
			"", "jev ask (allow 0.30 / ask 0.62 / deny 0.08); ask withheld by judge.decisions; " + softClosest,
		},
		{
			"downgraded deny is withheld", noAsk, "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "deny", Confidence: 0.40}, "deny_rule": r1},
			"", "jev deny below confidence floor (0.40), asking; ask withheld by judge.decisions; " + hardClosest,
		},
		{
			"withheld ask keeps the probe note", noAsk, "python3 nope.py",
			map[string]any{"decision": jevAnswer{Choice: "ask", Confidence: 0.62}},
			"", "jev ask (0.62); ask withheld by judge.decisions; script nope.py not attached: missing",
		},
		{
			"confident deny still denies", noAsk, "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "deny", Confidence: 0.90}, "deny_rule": r1},
			decisionDeny, "jev deny (0.90); " + hardClosest,
		},
		{
			"confident allow still allows", noAsk, "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "allow", Confidence: 0.98}},
			decisionAllow, "jev allow (0.98)",
		},
		{
			"ask below the floor was silence already", noAsk, "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "ask", Confidence: 0.49}},
			"", "jev ask below confidence floor (0.49)",
		},
		{
			"allow can be withheld too", noAllow, "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "allow", Confidence: 0.98}},
			"", "jev allow (0.98); allow withheld by judge.decisions",
		},
		{
			"deny can be withheld too", noAsk[:1], "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "deny", Confidence: 0.90}},
			"", "jev deny (0.90); deny withheld by judge.decisions",
		},
		{
			"unset key issues all three", nil, "terraform apply",
			map[string]any{"decision": jevAnswer{Choice: "deny", Confidence: 0.40}},
			decisionAsk, "jev deny below confidence floor (0.40), asking",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := fakeJevAnswers(t, tt.answers)
			cfg.Judge.Decisions = tt.decisions
			v := decide(cfg, tt.command, t.TempDir(), testLogger)
			if v.Decision != tt.decision || v.Reason != tt.reason || v.Tier != tierJudge {
				t.Fatalf("verdict = (%q, %q, %q), want (%q, %q)", v.Decision, v.Tier, v.Reason, tt.decision, tt.reason)
			}
			var buf strings.Builder
			logVerdict(slog.New(slog.NewJSONHandler(&buf, nil)), v, tt.command)
			var rec struct {
				Decision string `json:"decision"`
				Reason   string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(buf.String()), &rec); err != nil {
				t.Fatalf("log not JSON: %v: %s", err, buf.String())
			}
			if rec.Decision != cmp.Or(tt.decision, "silent") || rec.Reason != tt.reason {
				t.Fatalf("log record = %s", buf.String())
			}
		})
	}
}

// Rules from config are not the judge's decisions, so judge.decisions leaves
// them alone; an invalid list silences the hook like any malformed config.
func TestJudgeDecisionsLeaveRulesAlone(t *testing.T) {
	newHookEnv(t, `{"permissions":{"allow":["git status *"],"ask":["ssh prod *"],"deny":["gopass show -o *"]},"judge":{"decisions":["allow"]}}`)
	for command, want := range map[string]string{
		"ssh prod uptime": decisionAsk, "gopass show -o k": decisionDeny, "git status": decisionAllow,
	} {
		if got := hookDecision(t, "Bash", "command", command, "/"); got != want {
			t.Errorf("%s: decision = %q, want %q", command, got, want)
		}
	}
	if got := hookDecision(t, "Edit", "file_path", configPath(), "/"); got != decisionAsk {
		t.Errorf("guardrail path: decision = %q, want ask", got)
	}

	newHookEnv(t, `{"permissions":{"deny":["gopass show -o *"]},"judge":{"decisions":["allow","prompt"]}}`)
	for _, command := range []string{"git status", "gopass show -o k"} {
		if got := hookDecision(t, "Bash", "command", command, "/"); got != "" {
			t.Errorf("invalid judge.decisions: %s: decision = %q, want silence", command, got)
		}
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
		"proj/sub/build.py": "print('build')\n",
		"proj/run.py":       "print('run')\n",
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
		{"dash runs a script like sh", "proj", "dash smoke.sh", probeAttached, []string{"proj/smoke.sh"}},
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
		{"variable cd after copy", ".", "B={root}/proj/sub; cp x $B/y; cd $B && python3 build.py", probeAttached, []string{"proj/sub/build.py"}},
		{"variable in quoted script path", ".", `S={root}/proj; python3 "$S/run.py"`, probeAttached, []string{"proj/run.py"}},
		{"braced variable", ".", "S={root}/proj; python3 ${S}/run.py", probeAttached, []string{"proj/run.py"}},
		{"quoted cd variable", ".", `D={root}/proj/sub; cd "$D" && python3 build.py`, probeAttached, []string{"proj/sub/build.py"}},
		{"double-quoted value", ".", `S="{root}/proj"; python3 $S/run.py`, probeAttached, []string{"proj/run.py"}},
		{"single-quoted value", ".", "S='{root}/proj'; python3 $S/run.py", probeAttached, []string{"proj/run.py"}},
		{"relative value follows cwd", "proj", "D=sub; cd $D && python3 build.py", probeAttached, []string{"proj/sub/build.py"}},
		{"assignment on its own line", ".", "S={root}/proj\npython3 $S/run.py", probeAttached, []string{"proj/run.py"}},
		{"assignment in the same && chain", ".", "S={root}/proj && python3 $S/run.py", probeAttached, []string{"proj/run.py"}},
		{"variable directly executed", ".", "S={root}/proj; $S/smoke.sh", probeAttached, []string{"proj/smoke.sh"}},
		{"use inside a later if", ".", "S={root}/proj; if true; then python3 $S/run.py; fi", probeAttached, []string{"proj/run.py"}},
		{"tilde value resolves against home", ".", "S=~/frisk-test-no-such-dir; python3 $S/run.py", probeMissing, nil},
		{"quoted tilde value stays literal", ".", `S="~/frisk-test-no-such-dir"; python3 $S/run.py`, probeUnresolvable, nil},
		{"single-quoted reference is not expanded", ".", "S={root}/proj; python3 '$S/run.py'", probeUnresolvable, nil},
		{"escaped reference is not expanded", ".", `S={root}/proj; python3 \$S/run.py`, probeUnresolvable, nil},
		{"reassigned name", ".", "S={root}/proj/sub; S={root}/proj; python3 $S/run.py", probeUnresolvable, nil},
		{"appended name", ".", "S={root}/proj; S+=/sub; python3 $S/run.py", probeUnresolvable, nil},
		{"script inside then is probed", "proj", "if true; then python3 stats.py; fi", probeAttached, []string{"proj/stats.py"}},
		{"script inside loop body is probed", "proj", "for n in 1 2; do python3 stats.py; done", probeAttached, []string{"proj/stats.py"}},
		{"loop variable script is unresolvable", "proj", "for f in a b; do python3 $f; done", probeUnresolvable, nil},
		{"cd inside if never resolves later scripts", "proj", "if true; then cd sub; fi; python3 stats.py", probeUnresolvable, nil},
		{"cd inside loop never resolves later scripts", "proj", "for d in sub; do cd sub; python3 stats.py; done", probeUnresolvable, nil},
		{"value from substitution", ".", "S=$(pwd); python3 $S/run.py", probeUnresolvable, nil},
		{"value from another variable", ".", "R={root}; S=$R/proj; python3 $S/run.py", probeUnresolvable, nil},
		{"value with a glob", ".", "S={root}/pro?; python3 $S/run.py", probeUnresolvable, nil},
		{"value with a space", ".", `S="{root}/pr oj"; python3 "$S/run.py"`, probeUnresolvable, nil},
		{"env prefix is not an assignment", ".", "S={root}/proj python3 $S/run.py", probeUnresolvable, nil},
		{"use before assignment", ".", "python3 $S/run.py; S={root}/proj", probeUnresolvable, nil},
		{"assignment after ||", ".", "false || S={root}/proj; python3 $S/run.py", probeUnresolvable, nil},
		{"&& chain broken before use", ".", "true && S={root}/proj; python3 $S/run.py", probeUnresolvable, nil},
		{"piped assignment", ".", "S={root}/proj | cat; python3 $S/run.py", probeUnresolvable, nil},
		{"assignment inside if", ".", "if true; then S={root}/proj; fi; python3 $S/run.py", probeUnresolvable, nil},
		{"exported later", ".", "S={root}/proj; export S=/elsewhere; python3 $S/run.py", probeUnresolvable, nil},
		{"read later", ".", "S={root}/proj; read S; python3 $S/run.py", probeUnresolvable, nil},
		{"loop variable", ".", "S={root}/proj; for S in a b; do python3 $S/run.py; done", probeUnresolvable, nil},
		{"unset later", ".", "S={root}/proj; unset S; python3 $S/run.py", probeUnresolvable, nil},
		{"subshell resolves nothing", ".", "S={root}/proj; (cd /tmp); python3 $S/run.py", probeUnresolvable, nil},
		{"heredoc resolves nothing", ".", "cat <<EOF\nS={root}/proj\nEOF\npython3 $S/run.py", probeUnresolvable, nil},
		{"eval resolves nothing", ".", "S={root}/proj; eval x; python3 $S/run.py", probeUnresolvable, nil},
		{"source resolves nothing", ".", "S={root}/proj; . ./env.sh; python3 $S/run.py", probeUnresolvable, nil},
		{"IFS change resolves nothing", ".", "IFS=/; S={root}/proj; python3 $S/run.py", probeUnresolvable, nil},
		{"unknown variable beside a known one", ".", "S={root}/proj; python3 $S/$NAME.py", probeUnresolvable, nil},
		{"cd to unknown variable never falls back", "proj", "cd $NOPE && python3 run.py", probeUnresolvable, nil},
		{"zsh modifier after bare reference", ".", "S={root}/proj/sub; python3 $S:h/run.py", probeUnresolvable, nil},
		{"zsh subscript after bare reference", ".", "S={root}/proj; python3 $S[1]/run.py", probeUnresolvable, nil},
		{"braced reference before a colon is literal", ".", "S={root}/proj; python3 ${S}:h/run.py", probeMissing, nil},
		{"PWD is rewritten by cd", ".", "PWD={root}/proj; cd {root}/proj/sub; python3 $PWD/run.py", probeUnresolvable, nil},
		{"OLDPWD is shell-maintained", ".", "OLDPWD={root}/proj; python3 $OLDPWD/run.py", probeUnresolvable, nil},
		{"REPLY is shell-maintained", ".", "REPLY={root}/proj; python3 $REPLY/run.py", probeUnresolvable, nil},
		{"BASH-prefixed name is shell-maintained", ".", "BASH_X={root}/proj; python3 $BASH_X/run.py", probeUnresolvable, nil},
		{"ZSH-prefixed name is shell-maintained", ".", "ZSH_X={root}/proj; python3 $ZSH_X/run.py", probeUnresolvable, nil},
		{"trap resolves nothing", ".", "S={root}/proj; trap 'S=/b' DEBUG; python3 $S/run.py", probeUnresolvable, nil},
		{"alias resolves nothing", ".", "S={root}/proj; alias python3=true; python3 $S/run.py", probeUnresolvable, nil},
		{"setopt resolves nothing", ".", "S={root}/proj; setopt sh_word_split; python3 $S/run.py", probeUnresolvable, nil},
		{"fd redirection assigns the name", ".", "S={root}/proj; exec {S}>/dev/null; python3 $S/run.py", probeUnresolvable, nil},
		{"set -A assigns the name", ".", "S={root}/proj; set -A S a b; python3 $S/run.py", probeUnresolvable, nil},
		{"set options keep resolution", ".", "set -euo pipefail; S={root}/proj; python3 $S/run.py", probeAttached, []string{"proj/run.py"}},
		{"tilde after a colon in the value", ".", "S={root}/proj:~/x; python3 $S/run.py", probeUnresolvable, nil},
		{"zsh equals expansion in the value", ".", "S==ls; python3 $S/run.py", probeUnresolvable, nil},
		{"cdpath change resolves nothing", ".", "cdpath={root}/proj; D=sub; cd $D && python3 build.py", probeUnresolvable, nil},
		{"cd to a directory stack entry is unknown", "proj", "cd +1 && python3 stats.py", probeUnresolvable, nil},
		{"heredoc written to a file is text", ".", "cd {root}/proj && cat > lane.py <<'EOF'\nimport sys\nprint(f\"/favicon.svg:   {s(fav)}\")\nEOF", "", nil},
		{"heredoc fed to python is text", ".", "cd {root}/proj && python3 - <<'EOF'\npat = re.compile(\n    \"([^/] )\"\n)\nEOF", "", nil},
		{"heredoc after a subshell is text", "proj", "(cd sub && ls) && python3 - <<'EOF'\nif r.count('/')*d < len(r):\n    pass\nEOF", "", nil},
		{"heredoc fed to python without a dash is text", "proj", "python3 <<EOF\npython3 stats.py\nEOF", "", nil},
		{"heredoc body never moves the directory", "proj", "cat > notes.txt <<EOF\ncd sub\nEOF\npython3 stats.py", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read by a shell is probed", "proj", "bash <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read by a wrapped shell is probed", "proj", "timeout 60 dash -s <<'EOF'\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read by a redirected shell is probed", "proj", "sh <<EOF > out.log\npython3 stats.py\nEOF", probeMissing, []string{"proj/stats.py"}},
		{"heredoc piped into a shell is probed", "proj", "cat <<EOF | bash\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc piped through a filter into a shell is probed", "proj", "cat <<EOF | grep -v skip | sh -s\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc piped into a sudo shell is probed", "proj", "cat <<EOF | sudo -E bash\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc piped into tee is text", "proj", "cat <<EOF | tee out.txt\npython3 stats.py\nEOF", "", nil},
		{"heredoc after a shell pipeline is text", "proj", "echo true | bash; cat > notes.txt <<EOF\npython3 stats.py\nEOF", "", nil},
		{"heredoc read by a sudo shell is probed", "proj", "sudo bash <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read by a doas shell is probed", "proj", "doas -u deploy sh <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read by an env shell is probed", "proj", "env -u DEBUG FOO=1 bash <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read through bash -", "proj", "bash - <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read through sh /dev/stdin", "proj", "sh /dev/stdin <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read through bash /dev/fd/0", "proj", "bash /dev/fd/0 <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read through source /dev/stdin", "proj", "source /dev/stdin <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc read through dot /dev/stdin", "proj", ". /dev/stdin <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/stats.py"}},
		{"heredoc beside a sourced file is text", "proj", "source ./env.sh <<EOF\npython3 stats.py\nEOF", "", nil},
		{"heredoc written by sudo tee is text", "proj", "sudo tee /etc/motd <<EOF\npython3 stats.py\nEOF", "", nil},
		{"heredoc beside bash -c is text", "proj", "bash -c 'cat > copy.txt' <<EOF\npython3 stats.py\nEOF", "", nil},
		{"heredoc beside a script file is text", "proj", "bash smoke.sh <<EOF\npython3 stats.py\nEOF", probeAttached, []string{"proj/smoke.sh"}},
		{"heredoc with a tab-stripped terminator", "proj", "bash <<-EOF\n\tpython3 stats.py\n\tEOF\npython3 run.py", probeAttached, []string{"proj/stats.py", "proj/run.py"}},
		{"heredoc with a quoted terminator", "proj", "cat > notes.txt <<\"END OF NOTES\"\npython3 decoy.py\nEND OF NOTES\npython3 run.py", probeAttached, []string{"proj/run.py"}},
		{"two heredocs on one line", "proj", "cat <<A > a.txt; bash <<'B'\npython3 decoy.py\nA\npython3 stats.py\nB", probeAttached, []string{"proj/stats.py"}},
		{"command after the terminator is probed", "proj", "cat > notes.txt <<'EOF'\nit's generated\nEOF\npython3 run.py", probeAttached, []string{"proj/run.py"}},
		{"quote in a comment hides no script", "proj", "python3 stats.py # it's\npython3 run.py # '", probeAttached, []string{"proj/stats.py", "proj/run.py"}},
		{"unterminated heredoc runs to the end", "proj", "cat > lane.py <<EOF\npython3 stats.py", "", nil},
		{"arithmetic shift is not a heredoc", "proj", "n=$((1<<2))\npython3 stats.py", probeAttached, []string{"proj/stats.py"}},
		{"here-string is not a heredoc", "proj", "cat <<<hello\npython3 stats.py", probeAttached, []string{"proj/stats.py"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			segments := tokenize(strings.ReplaceAll(tt.command, "{root}", root)).probeSegments()
			res := probeScripts(segments, filepath.Join(root, tt.cwd))
			if res.Status != tt.status || (tt.status == "" && res.Missed != "") {
				t.Fatalf("status = %q, want %q (missed %q)", res.Status, tt.status, res.Missed)
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

func TestProbeSegments(t *testing.T) {
	t.Parallel()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	tests := []struct {
		name    string
		command string
		want    []string // the last segment
	}{
		{"tilde value expands at assignment", "S=~/x; python3 $S/run.py", []string{"python3", filepath.Join(home, "x") + "/run.py"}},
		{"braced and bare forms", `S=/a; T=/b; diff ${S}/f "$T/f"`, []string{"diff", "/a/f", "/b/f"}},
		{"longest name wins", "S=/a; echo $S_dir", []string{"echo", "$S_dir"}},
		{"single quotes keep the dollar", "S=/a; echo '$S' $S", []string{"echo", "$S", "/a"}},
		{"unknown names keep the dollar", "S=/a; echo $S/$T", []string{"echo", "/a/$T"}},
		{"nothing to substitute", "git status", []string{"git", "status"}},
		{"bare reference before a modifier or subscript", `S=/a; echo $S:h "$S:t" $S[1] $S:$S`, []string{"echo", "$S:h", "$S:t", "$S[1]", "$S:/a"}},
		{"braced reference before a modifier or subscript", "S=/a; echo ${S}:h ${S}[1]", []string{"echo", "/a:h", "/a[1]"}},
	}
	for _, tt := range tests {
		segs := tokenize(tt.command).probeSegments()
		if got := segs[len(segs)-1]; !slices.Equal(got, tt.want) {
			t.Errorf("%s: probeSegments(%q) = %q, want %q", tt.name, tt.command, got, tt.want)
		}
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
	newHookEnv(t, `{"permissions":{"allow":["git status *","head *"]}}`)

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
