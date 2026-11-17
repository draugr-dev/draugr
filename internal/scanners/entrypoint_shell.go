package scanners

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

// An entrypoint script is read for one question: does every path a start as root takes through it
// end by handing the process to another user, and run nothing as root before that but setup? The
// reading covers the shell an entrypoint is written in, if/elif/else, case, loops, groups, && and ||,
// and refuses everything else. A refusal is never a finding; it leaves the DS-0002 finding as Trivy
// reported it.

// shellDrop is where a script hands its process to another user.
type shellDrop struct {
	command, user string
	line          int
}

// scriptDrop reads a shell script and returns the line its start as root ends in a drop of root. False
// where any path a start as root takes does something else, or the script cannot be read.
func scriptDrop(src string) (shellDrop, bool) {
	if !shellShebang(src) {
		return shellDrop{}, false
	}
	toks, err := lexShell(src)
	if err != nil {
		return shellDrop{}, false
	}
	p := &shellParser{toks: toks, funcs: map[string]bool{}}
	prog, err := p.list()
	if err != nil || !p.at(shEOF, "") {
		return shellDrop{}, false
	}
	out := (&rootPath{funcs: p.funcs}).list(prog)
	if out.bad || out.continues || out.drop == nil {
		return shellDrop{}, false
	}
	return *out.drop, true
}

// shellShebang reports whether the script names a Bourne-family shell as its interpreter. A script
// without a shebang does not run as an image's entrypoint at all.
func shellShebang(src string) bool {
	first, _, _ := strings.Cut(src, "\n")
	interp, ok := strings.CutPrefix(first, "#!")
	if !ok {
		return false
	}
	fields := strings.Fields(interp)
	if len(fields) == 0 {
		return false
	}
	name := path.Base(fields[0])
	if name == "env" && len(fields) > 1 {
		name = fields[1]
	}
	switch name {
	case "sh", "bash", "ash", "dash":
		return true
	}
	return false
}

// shKind is what a token of the script is.
type shKind int

const (
	shWord shKind = iota
	shOp
	shRedir
	shNewline
	shEOF
)

// shToken is one token of a script. value is a word with its quotes removed and expansions left as
// written.
type shToken struct {
	kind  shKind
	text  string
	value string
	line  int
}

// errShell is a script this reading does not follow.
var errShell = errors.New("script not followed")

// lexShell splits a script into tokens, skipping comments and the bodies of heredocs.
func lexShell(src string) ([]shToken, error) {
	l := &shellLexer{src: src, line: 1}
	return l.run()
}

type shellLexer struct {
	src      string
	i, line  int
	toks     []shToken
	heredocs []heredoc
	// brackets is set inside `[[ … ]]`, where && and < are part of the test.
	brackets bool
}

type heredoc struct {
	delim string
	tabs  bool
}

func (l *shellLexer) emit(kind shKind, text, value string) {
	l.toks = append(l.toks, shToken{kind: kind, text: text, value: value, line: l.line})
}

func (l *shellLexer) run() ([]shToken, error) {
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			l.i++
		case c == '\\' && l.i+1 < len(l.src) && l.src[l.i+1] == '\n':
			l.i += 2
			l.line++
		case c == '#':
			for l.i < len(l.src) && l.src[l.i] != '\n' {
				l.i++
			}
		case c == '\n':
			l.emit(shNewline, "\n", "")
			l.i++
			l.line++
			if err := l.skipHeredocs(); err != nil {
				return nil, err
			}
		case strings.ContainsRune(";&|()", rune(c)) && (!l.brackets || c == ';'):
			l.operator()
		case c == '<' || c == '>':
			if !l.brackets {
				if err := l.redirect(""); err != nil {
					return nil, err
				}
				continue
			}
			l.word()
		default:
			l.word()
		}
	}
	if len(l.heredocs) > 0 {
		return nil, errShell
	}
	l.emit(shEOF, "", "")
	return l.toks, nil
}

// operator reads ;, ;;, &, &&, |, ||, ( or ), and &> as a redirection.
func (l *shellLexer) operator() {
	rest := l.src[l.i:]
	for _, op := range []string{"&&", "||", ";;", "&>", ";", "&", "|", "(", ")"} {
		if strings.HasPrefix(rest, op) {
			if op == "&>" {
				_ = l.redirect("")
				return
			}
			l.emit(shOp, op, op)
			l.i += len(op)
			return
		}
	}
}

// redirect reads a redirection operator, with the file descriptor written before it, and records a
// heredoc's delimiter so its body is skipped.
func (l *shellLexer) redirect(fd string) error {
	start := l.i
	for l.i < len(l.src) && strings.ContainsRune("<>&|-", rune(l.src[l.i])) {
		if l.src[l.i] == '-' && !strings.HasSuffix(l.src[start:l.i], "<<") {
			break
		}
		l.i++
	}
	op := l.src[start:l.i]
	l.emit(shRedir, fd+op, op)
	if strings.HasPrefix(op, "<<") && !strings.HasPrefix(op, "<<<") {
		for l.i < len(l.src) && (l.src[l.i] == ' ' || l.src[l.i] == '\t') {
			l.i++
		}
		raw, value, err := l.readWord()
		if err != nil || raw == "" {
			return errShell
		}
		l.heredocs = append(l.heredocs, heredoc{delim: value, tabs: strings.HasSuffix(op, "-")})
		l.emit(shWord, raw, value)
	}
	return nil
}

// skipHeredocs skips the bodies of the heredocs opened on the line just ended.
func (l *shellLexer) skipHeredocs() error {
	for _, h := range l.heredocs {
		for {
			if l.i >= len(l.src) {
				return errShell
			}
			end := strings.IndexByte(l.src[l.i:], '\n')
			var line string
			if end < 0 {
				line, l.i = l.src[l.i:], len(l.src)
			} else {
				line, l.i = l.src[l.i:l.i+end], l.i+end+1
			}
			l.line++
			line = strings.TrimRight(line, "\r")
			if h.tabs {
				line = strings.TrimLeft(line, "\t")
			}
			if line == h.delim {
				break
			}
		}
	}
	l.heredocs = nil
	return nil
}

// word reads one word, or a redirection where the word is a file descriptor written against one.
func (l *shellLexer) word() {
	raw, value, err := l.readWord()
	if err != nil {
		l.i = len(l.src)
		l.toks = append(l.toks, shToken{kind: shOp, text: "\x00", line: l.line})
		return
	}
	if raw != "" && isDigits(raw) && l.i < len(l.src) && (l.src[l.i] == '<' || l.src[l.i] == '>') && !l.brackets {
		_ = l.redirect(raw)
		return
	}
	if raw == "" {
		// A character no rule reads: take it as a word of its own rather than loop on it.
		raw, value = l.src[l.i:l.i+1], l.src[l.i:l.i+1]
		l.i++
	}
	switch raw {
	case "[[":
		l.brackets = true
	case "]]":
		l.brackets = false
	}
	l.emit(shWord, raw, value)
}

// readWord reads a word up to the first unquoted blank or operator, returning it as written and with
// its quotes removed.
func (l *shellLexer) readWord() (raw, value string, err error) {
	start := l.i
	var v strings.Builder
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			return l.src[start:l.i], v.String(), nil
		case strings.ContainsRune(";&|()<>", rune(c)) && (!l.brackets || c == ';'):
			return l.src[start:l.i], v.String(), nil
		case l.brackets && strings.HasPrefix(l.src[l.i:], "]]") && l.i > start:
			return l.src[start:l.i], v.String(), nil
		case c == '\\':
			if l.i+1 < len(l.src) {
				v.WriteByte(l.src[l.i+1])
			}
			l.i += 2
		case c == '\'':
			end := strings.IndexByte(l.src[l.i+1:], '\'')
			if end < 0 {
				return "", "", errShell
			}
			body := l.src[l.i+1 : l.i+1+end]
			v.WriteString(body)
			l.line += strings.Count(body, "\n")
			l.i += end + 2
		case c == '"':
			end, err := skipDoubleQuoted(l.src, l.i+1)
			if err != nil {
				return "", "", err
			}
			body := l.src[l.i+1 : end]
			v.WriteString(body)
			l.line += strings.Count(body, "\n")
			l.i = end + 1
		case c == '$' && l.i+1 < len(l.src) && (l.src[l.i+1] == '(' || l.src[l.i+1] == '{'):
			end, err := skipExpansion(l.src, l.i+1)
			if err != nil {
				return "", "", err
			}
			v.WriteString(l.src[l.i:end])
			l.line += strings.Count(l.src[l.i:end], "\n")
			l.i = end
		case c == '`':
			end := strings.IndexByte(l.src[l.i+1:], '`')
			if end < 0 {
				return "", "", errShell
			}
			v.WriteString(l.src[l.i : l.i+end+2])
			l.i += end + 2
		default:
			v.WriteByte(c)
			l.i++
		}
	}
	return l.src[start:l.i], v.String(), nil
}

// skipDoubleQuoted returns the index of the quote closing a double-quoted string that starts at i.
func skipDoubleQuoted(s string, i int) (int, error) {
	for i < len(s) {
		switch s[i] {
		case '\\':
			i += 2
		case '"':
			return i, nil
		case '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				return 0, errShell
			}
			i += end + 2
		case '$':
			if i+1 < len(s) && (s[i+1] == '(' || s[i+1] == '{') {
				end, err := skipExpansion(s, i+1)
				if err != nil {
					return 0, err
				}
				i = end
				continue
			}
			i++
		default:
			i++
		}
	}
	return 0, errShell
}

// skipExpansion returns the index after the bracket closing the $( or ${ whose bracket is at i.
func skipExpansion(s string, i int) (int, error) {
	open := s[i]
	closing := byte(')')
	if open == '{' {
		closing = '}'
	}
	depth := 0
	for i < len(s) {
		switch s[i] {
		case open:
			depth++
			i++
		case closing:
			depth--
			i++
			if depth == 0 {
				return i, nil
			}
		case '\\':
			i += 2
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return 0, errShell
			}
			i += end + 2
		case '"':
			end, err := skipDoubleQuoted(s, i+1)
			if err != nil {
				return 0, err
			}
			i = end + 1
		default:
			i++
		}
	}
	return 0, errShell
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// The script as a tree, of the shapes this reading follows.
type (
	// shList is commands run one after another.
	shList []shAndOr
	// shAndOr is pipelines joined by && and ||, run in the background where it ends in &.
	shAndOr struct {
		pipelines []shPipeline
		// ops are the && and || between the pipelines.
		ops        []string
		background bool
	}
	shPipeline struct {
		commands []shCommand
		negated  bool
	}
	// shCommand is one of the fields set.
	shCommand struct {
		simple *shSimple
		ifs    *shIf
		cases  []shList
		// caseAll is set where a case has a `*` pattern, so one of its branches always runs.
		caseAll bool
		loop    *shLoop
		group   shList
		// subshell is set for ( … ) and grouped is set for { … }; group holds either's commands.
		subshell, grouped bool
		// funcDef is set for a function definition, whose body runs only where it is called.
		funcDef bool
	}
	shSimple struct {
		words []shToken
		line  int
	}
	shIf struct {
		conds, bodies []shList
		elseBody      shList
		hasElse       bool
	}
	shLoop struct{ cond, body shList }
)

type shellParser struct {
	toks  []shToken
	i     int
	funcs map[string]bool
}

func (p *shellParser) peek() shToken { return p.toks[p.i] }

func (p *shellParser) next() shToken {
	t := p.toks[p.i]
	if t.kind != shEOF {
		p.i++
	}
	return t
}

// at reports whether the next token is of kind and, for a word or an operator, reads text.
func (p *shellParser) at(kind shKind, text string) bool {
	t := p.peek()
	return t.kind == kind && (text == "" || t.text == text)
}

func (p *shellParser) skipNewlines() {
	for p.at(shNewline, "") || p.at(shOp, ";") {
		p.next()
	}
}

// reserved are the words that end a list where they stand at the start of a command.
var reserved = map[string]bool{"then": true, "elif": true, "else": true, "fi": true, "do": true,
	"done": true, "esac": true, "}": true}

// list reads commands up to a reserved word, a closing parenthesis, ;; or the end.
func (p *shellParser) list() (shList, error) {
	var out shList
	for {
		p.skipNewlines()
		t := p.peek()
		if t.kind == shEOF || (t.kind == shWord && reserved[t.text]) || (t.kind == shOp && (t.text == ")" || t.text == ";;")) {
			return out, nil
		}
		ao, err := p.andOr()
		if err != nil {
			return nil, err
		}
		if p.at(shOp, "&") {
			p.next()
			ao.background = true
		}
		out = append(out, ao)
	}
}

func (p *shellParser) andOr() (shAndOr, error) {
	var ao shAndOr
	for {
		pl, err := p.pipeline()
		if err != nil {
			return ao, err
		}
		ao.pipelines = append(ao.pipelines, pl)
		if !p.at(shOp, "&&") && !p.at(shOp, "||") {
			return ao, nil
		}
		ao.ops = append(ao.ops, p.next().text)
		for p.at(shNewline, "") {
			p.next()
		}
	}
}

func (p *shellParser) pipeline() (shPipeline, error) {
	var pl shPipeline
	if p.at(shWord, "!") {
		p.next()
		pl.negated = true
	}
	for {
		c, err := p.command()
		if err != nil {
			return pl, err
		}
		pl.commands = append(pl.commands, c)
		if !p.at(shOp, "|") {
			return pl, nil
		}
		p.next()
		for p.at(shNewline, "") {
			p.next()
		}
	}
}

// expect reads the reserved word w, or fails.
func (p *shellParser) expect(w string) error {
	if !p.at(shWord, w) {
		return errShell
	}
	p.next()
	return nil
}

func (p *shellParser) command() (shCommand, error) {
	t := p.peek()
	var c shCommand
	var err error
	switch {
	case t.kind == shOp && t.text == "(":
		p.next()
		c.subshell = true
		if c.group, err = p.list(); err != nil {
			return c, err
		}
		if !p.at(shOp, ")") {
			return c, errShell
		}
		p.next()
	case t.kind != shWord:
		if t.kind == shRedir {
			return p.simple()
		}
		return c, errShell
	case t.text == "if":
		c.ifs, err = p.ifClause()
	case t.text == "case":
		err = p.caseClause(&c)
	case t.text == "while" || t.text == "until":
		c.loop, err = p.whileClause()
	case t.text == "for":
		c.loop, err = p.forClause()
	case t.text == "{":
		p.next()
		c.grouped = true
		if c.group, err = p.list(); err == nil {
			err = p.expect("}")
		}
	case t.text == "function":
		p.next()
		return p.funcDef(p.next())
	case p.i+2 < len(p.toks) && p.toks[p.i+1].kind == shOp && p.toks[p.i+1].text == "(" &&
		p.toks[p.i+2].kind == shOp && p.toks[p.i+2].text == ")":
		name := p.next()
		p.next()
		p.next()
		return p.funcDef(name)
	default:
		return p.simple()
	}
	if err != nil {
		return c, err
	}
	// Redirections after a compound command change where its output goes, not what it runs.
	for p.at(shRedir, "") {
		p.next()
		if p.at(shWord, "") {
			p.next()
		}
	}
	return c, nil
}

// funcDef reads a function's body after its name, and records the name: a call to it runs a body this
// reading does not follow.
func (p *shellParser) funcDef(name shToken) (shCommand, error) {
	if name.kind != shWord {
		return shCommand{}, errShell
	}
	if p.at(shOp, "(") {
		p.next()
		if !p.at(shOp, ")") {
			return shCommand{}, errShell
		}
		p.next()
	}
	for p.at(shNewline, "") {
		p.next()
	}
	if _, err := p.command(); err != nil {
		return shCommand{}, err
	}
	p.funcs[name.value] = true
	return shCommand{funcDef: true}, nil
}

func (p *shellParser) simple() (shCommand, error) {
	s := &shSimple{line: p.peek().line}
	for {
		t := p.peek()
		switch t.kind {
		case shWord:
			s.words = append(s.words, p.next())
		case shRedir:
			p.next()
			if p.at(shWord, "") {
				p.next()
			}
		default:
			if len(s.words) == 0 && t.kind == shOp && t.text == "\x00" {
				return shCommand{}, errShell
			}
			return shCommand{simple: s}, nil
		}
	}
}

func (p *shellParser) ifClause() (*shIf, error) {
	c := &shIf{}
	p.next()
	for {
		cond, err := p.list()
		if err != nil {
			return nil, err
		}
		if err := p.expect("then"); err != nil {
			return nil, err
		}
		body, err := p.list()
		if err != nil {
			return nil, err
		}
		c.conds, c.bodies = append(c.conds, cond), append(c.bodies, body)
		if !p.at(shWord, "elif") {
			break
		}
		p.next()
	}
	if p.at(shWord, "else") {
		p.next()
		body, err := p.list()
		if err != nil {
			return nil, err
		}
		c.elseBody, c.hasElse = body, true
	}
	return c, p.expect("fi")
}

func (p *shellParser) caseClause(c *shCommand) error {
	p.next()
	if !p.at(shWord, "") {
		return errShell
	}
	p.next()
	for p.at(shNewline, "") {
		p.next()
	}
	if err := p.expect("in"); err != nil {
		return err
	}
	for {
		p.skipNewlines()
		if p.at(shWord, "esac") {
			p.next()
			return nil
		}
		if p.at(shOp, "(") {
			p.next()
		}
		for {
			pat := p.next()
			if pat.kind != shWord {
				return errShell
			}
			if pat.value == "*" {
				c.caseAll = true
			}
			if !p.at(shOp, "|") {
				break
			}
			p.next()
		}
		if !p.at(shOp, ")") {
			return errShell
		}
		p.next()
		body, err := p.list()
		if err != nil {
			return err
		}
		c.cases = append(c.cases, body)
		if p.at(shOp, ";;") {
			p.next()
			continue
		}
		if !p.at(shWord, "esac") {
			return errShell
		}
	}
}

func (p *shellParser) whileClause() (*shLoop, error) {
	p.next()
	cond, err := p.list()
	if err != nil {
		return nil, err
	}
	if err := p.expect("do"); err != nil {
		return nil, err
	}
	body, err := p.list()
	if err != nil {
		return nil, err
	}
	return &shLoop{cond: cond, body: body}, p.expect("done")
}

func (p *shellParser) forClause() (*shLoop, error) {
	p.next()
	if !p.at(shWord, "") {
		return nil, errShell
	}
	p.next()
	p.skipNewlines()
	if p.at(shWord, "in") {
		for p.at(shWord, "") && !p.at(shWord, "do") {
			p.next()
		}
	}
	p.skipNewlines()
	if err := p.expect("do"); err != nil {
		return nil, err
	}
	body, err := p.list()
	if err != nil {
		return nil, err
	}
	return &shLoop{body: body}, p.expect("done")
}

// flow is what a part of the script does on the paths a start as root takes through it.
type flow struct {
	// continues is set where some path runs on past it.
	continues bool
	// drop is the first drop of root a path through it ends in.
	drop *shellDrop
	// bad is set where some path does something the evidence cannot stand on: runs a program this
	// reading does not know as setup, in the background or not, or replaces the shell with anything
	// but a drop of root.
	bad bool
}

// rootPath follows the paths a start as root takes through a script.
type rootPath struct{ funcs map[string]bool }

var badFlow = flow{bad: true}

func (r *rootPath) list(l shList) flow {
	out := flow{continues: true}
	for _, ao := range l {
		if !out.continues {
			break
		}
		f := r.andOr(ao)
		if f.bad {
			return badFlow
		}
		if out.drop == nil {
			out.drop = f.drop
		}
		out.continues = f.continues
	}
	return out
}

// andOr follows a && and || list: the first pipeline always runs, and any after it may not.
func (r *rootPath) andOr(ao shAndOr) flow {
	if ao.background {
		return badFlow
	}
	// `[ "$(id -u)" = 0 ] && exec …` is the guard of an if, written on one line.
	if len(ao.pipelines) == 2 {
		switch t := rootTest(ao.pipelines[0]); {
		case t == asRoot && ao.ops[0] == "&&", t == notRoot && ao.ops[0] == "||":
			return r.pipeline(ao.pipelines[1])
		case t != rootUnknown:
			return flow{continues: true}
		}
	}
	first := r.pipeline(ao.pipelines[0])
	if first.bad || !first.continues || len(ao.pipelines) == 1 {
		return first
	}
	out := flow{continues: true}
	for _, pl := range ao.pipelines[1:] {
		f := r.pipeline(pl)
		if f.bad {
			return badFlow
		}
	}
	return out
}

// pipeline follows a pipeline. Every command of one with more than one runs in a subshell, so none of
// them ends the script.
func (r *rootPath) pipeline(pl shPipeline) flow {
	if len(pl.commands) == 1 {
		return r.command(pl.commands[0])
	}
	for _, c := range pl.commands {
		if f := r.command(c); f.bad || !f.continues {
			return badFlow
		}
	}
	return flow{continues: true}
}

func (r *rootPath) command(c shCommand) flow {
	switch {
	case c.funcDef:
		return flow{continues: true}
	case c.simple != nil:
		return r.simple(c.simple)
	case c.ifs != nil:
		return r.ifClause(c.ifs)
	case c.cases != nil || c.caseAll:
		out := flow{continues: !c.caseAll}
		for _, body := range c.cases {
			out = join(out, r.list(body))
		}
		return out
	case c.loop != nil:
		if f := r.list(c.loop.cond); f.bad || !f.continues {
			return badFlow
		}
		if f := r.list(c.loop.body); f.bad {
			return badFlow
		}
		return flow{continues: true}
	case c.subshell:
		if f := r.list(c.group); f.bad {
			return badFlow
		}
		return flow{continues: true}
	case c.grouped:
		return r.list(c.group)
	}
	// An empty case: nothing runs.
	return flow{continues: true}
}

// join is the flow of two alternatives, either of which a path may take.
func join(a, b flow) flow {
	if a.bad || b.bad {
		return badFlow
	}
	out := flow{continues: a.continues || b.continues, drop: a.drop}
	if out.drop == nil {
		out.drop = b.drop
	}
	return out
}

func (r *rootPath) ifClause(c *shIf) flow {
	// A test of whether the script runs as root decides which branch a start as root takes. The other
	// branches are not read: a start as anyone else was never root.
	switch rootTest(conditionPipeline(c.conds[0])) {
	case asRoot:
		return r.list(c.bodies[0])
	case notRoot:
		if len(c.conds) > 1 {
			return r.ifClause(&shIf{conds: c.conds[1:], bodies: c.bodies[1:], elseBody: c.elseBody, hasElse: c.hasElse})
		}
		if c.hasElse {
			return r.list(c.elseBody)
		}
		return flow{continues: true}
	}
	// Otherwise any branch may be the one, and where there is no else, none of them.
	out := flow{continues: !c.hasElse}
	for i, cond := range c.conds {
		if f := r.list(cond); f.bad || !f.continues {
			return badFlow
		}
		out = join(out, r.list(c.bodies[i]))
	}
	if c.hasElse {
		out = join(out, r.list(c.elseBody))
	}
	return out
}

// conditionPipeline is the one pipeline a condition runs, or an empty one where it runs several.
func conditionPipeline(cond shList) shPipeline {
	if len(cond) != 1 || len(cond[0].pipelines) != 1 || cond[0].background {
		return shPipeline{}
	}
	return cond[0].pipelines[0]
}

func (r *rootPath) simple(s *shSimple) flow {
	words := s.words
	for len(words) > 0 && assignment.MatchString(words[0].value) {
		words = words[1:]
	}
	if len(words) == 0 {
		return flow{continues: true}
	}
	name := words[0].value
	switch name {
	case "exec":
		if len(words) == 1 {
			// exec with only redirections changes where output goes and runs nothing.
			return flow{continues: true}
		}
		d, ok := dropOf(words[1:])
		if !ok {
			return badFlow
		}
		d.line = words[0].line
		return flow{drop: &d}
	case "exit":
		return flow{}
	}
	if strings.Contains(name, "$") || strings.Contains(name, "`") || r.funcs[name] {
		return badFlow
	}
	if !setupCommand(path.Base(name), words[1:]) {
		return badFlow
	}
	return flow{continues: true}
}

// assignment is a word setting a variable, `PUID=1000`.
var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// entrypointSetup are the commands a script may run as root before it drops root and still count as
// dropping it: shell builtins, and the file, user and text utilities an entrypoint prepares a volume
// or a user with. Each runs and returns. Any other program might stay running as root beside the
// application, and this reading cannot tell one that does from one that does not.
var entrypointSetup = map[string]bool{
	":": true, "[": true, "[[": true, "test": true, "true": true, "false": true, "echo": true,
	"printf": true, "export": true, "set": true, "unset": true, "local": true, "readonly": true,
	"shift": true, "cd": true, "umask": true, "ulimit": true, "trap": true, "read": true, "wait": true,
	"declare": true, "typeset": true, "type": true, "hash": true, "sleep": true,
	"chown": true, "chmod": true, "chgrp": true, "mkdir": true, "rmdir": true, "rm": true, "cp": true,
	"mv": true, "ln": true, "touch": true, "ls": true, "cat": true, "sed": true, "grep": true,
	"cut": true, "tr": true, "head": true, "tail": true, "sort": true, "uniq": true, "wc": true,
	"tee": true, "basename": true, "dirname": true, "readlink": true, "realpath": true, "stat": true,
	"date": true, "id": true, "whoami": true, "getent": true, "install": true, "envsubst": true,
	"addgroup": true, "adduser": true, "groupadd": true, "useradd": true, "usermod": true,
	"groupmod": true, "deluser": true, "delgroup": true, "userdel": true, "groupdel": true,
}

// setupCommand reports whether a command a start as root runs before its drop is one the evidence
// can stand beside: a setup command, `command -v`, or a drop of root that runs a command as the user
// and returns.
func setupCommand(name string, args []shToken) bool {
	switch {
	case entrypointSetup[name]:
		return true
	case name == "command":
		return len(args) > 0 && (args[0].value == "-v" || args[0].value == "-V")
	case name == "find":
		// find runs what -exec names.
		for i, a := range args {
			if strings.HasPrefix(a.value, "-exec") || strings.HasPrefix(a.value, "-ok") {
				if i+1 >= len(args) || !setupCommand(path.Base(args[i+1].value), args[i+2:]) {
					return false
				}
			}
		}
		return true
	}
	all := append([]shToken{{kind: shWord, value: name}}, args...)
	_, ok := dropOf(all)
	return ok
}

// rootState is what a condition says about running as root.
type rootState int

const (
	rootUnknown rootState = iota
	asRoot
	notRoot
)

// rootTest reads a test that compares the effective user id with 0: `[ "$(id -u)" = "0" ]`,
// `[ $(id -u) -eq 0 ]`, `test`, `[[ … ]]`, `!=` and `-ne`, with the id on either side, and `!` before
// any of them.
func rootTest(pl shPipeline) rootState {
	if len(pl.commands) != 1 || pl.commands[0].simple == nil {
		return rootUnknown
	}
	s := pl.commands[0].simple
	state := simpleRootTest(s)
	if pl.negated {
		switch state {
		case asRoot:
			return notRoot
		case notRoot:
			return asRoot
		}
	}
	return state
}

func simpleRootTest(s *shSimple) rootState {
	var w []string
	for _, t := range s.words {
		w = append(w, t.value)
	}
	switch {
	case len(w) == 5 && w[0] == "[" && w[4] == "]", len(w) == 5 && w[0] == "[[" && w[4] == "]]":
		w = w[1:4]
	case len(w) == 4 && w[0] == "test":
		w = w[1:]
	default:
		return rootUnknown
	}
	a, op, b := w[0], w[1], w[2]
	if isUID(b) {
		a, b = b, a
	}
	if !isUID(a) || b != "0" {
		return rootUnknown
	}
	switch op {
	case "=", "==", "-eq":
		return asRoot
	case "!=", "-ne":
		return notRoot
	}
	return rootUnknown
}

// isUID reports whether a word is the effective user id as a command substitution, `$(id -u)` or
// `id -u` in backticks.
func isUID(w string) bool {
	w = strings.Join(strings.Fields(w), " ")
	return w == "$(id -u)" || w == "`id -u`"
}

// dropCommands are the programs that run a command as another user.
var dropCommands = map[string]bool{"su-exec": true, "gosu": true, "setpriv": true, "runuser": true,
	"s6-setuidgid": true, "chpst": true}

// dropOf reads words as a command that runs another command as a user other than root, returning the
// program and the user. False for anything else, a switch to root included.
func dropOf(words []shToken) (shellDrop, bool) {
	if len(words) == 0 {
		return shellDrop{}, false
	}
	name := path.Base(words[0].value)
	if !dropCommands[name] {
		return shellDrop{}, false
	}
	args := make([]string, 0, len(words)-1)
	for _, w := range words[1:] {
		args = append(args, w.value)
	}
	var user string
	var rest []string
	var ok bool
	switch name {
	case "su-exec", "gosu", "s6-setuidgid":
		if len(args) < 2 || strings.HasPrefix(args[0], "-") {
			return shellDrop{}, false
		}
		user, rest, ok = args[0], args[1:], true
	case "setpriv":
		user, rest, ok = setprivUser(args)
	case "runuser":
		user, rest, ok = runuserUser(args)
	case "chpst":
		user, rest, ok = chpstUser(args)
	}
	if !ok || len(rest) == 0 || rootUser(user) {
		return shellDrop{}, false
	}
	return shellDrop{command: name, user: user}, true
}

// setprivUser reads setpriv's options for the user --reuid sets, and the command after them.
func setprivUser(args []string) (string, []string, bool) {
	withValue := map[string]bool{"--reuid": true, "--regid": true, "--groups": true, "--inh-caps": true,
		"--ambient-caps": true, "--bounding-set": true, "--securebits": true, "--pdeathsig": true,
		"--selinux-label": true, "--apparmor-profile": true}
	flags := map[string]bool{"--init-groups": true, "--clear-groups": true, "--keep-groups": true,
		"--no-new-privs": true, "--reset-env": true}
	user := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return user, args[i+1:], user != ""
		}
		if !strings.HasPrefix(a, "-") {
			return user, args[i:], user != ""
		}
		key, value, inline := strings.Cut(a, "=")
		switch {
		case withValue[key]:
			if !inline {
				if i+1 >= len(args) {
					return "", nil, false
				}
				i++
				value = args[i]
			}
			if key == "--reuid" {
				user = value
			}
		case flags[a]:
		default:
			return "", nil, false
		}
	}
	return "", nil, false
}

// runuserUser reads runuser's options for the user -u names, and the command after them. runuser's
// su-style form, without -u, is not read.
func runuserUser(args []string) (string, []string, bool) {
	user := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return user, args[i+1:], user != ""
		case a == "-u" || a == "--user" || a == "-g" || a == "--group" || a == "-G" || a == "--supp-group" ||
			a == "-w" || a == "--whitelist-environment":
			if i+1 >= len(args) {
				return "", nil, false
			}
			if a == "-u" || a == "--user" {
				user = args[i+1]
			}
			i++
		case strings.HasPrefix(a, "--user="):
			user = strings.TrimPrefix(a, "--user=")
		case strings.HasPrefix(a, "--group="), strings.HasPrefix(a, "--supp-group="),
			strings.HasPrefix(a, "--whitelist-environment="),
			a == "-m", a == "-p", a == "--preserve-environment":
		case strings.HasPrefix(a, "-"):
			return "", nil, false
		default:
			return user, args[i:], user != ""
		}
	}
	return "", nil, false
}

// chpstUser reads chpst's options for the user -u names, and the command after them. -u takes
// `user[:group…]`, or `:uid[:gid…]` in numbers.
func chpstUser(args []string) (string, []string, bool) {
	user := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || len(a) < 2 {
			return user, args[i:], user != ""
		}
		opt, value := a[1], a[2:]
		switch {
		case strings.IndexByte("uUbe/nlLmdopfcrtC", opt) >= 0:
			if value == "" {
				if i+1 >= len(args) {
					return "", nil, false
				}
				i++
				value = args[i]
			}
			if opt == 'u' {
				user = strings.TrimPrefix(value, ":")
			}
		case strings.IndexByte("vP012", opt) >= 0 && value == "":
		default:
			return "", nil, false
		}
	}
	return "", nil, false
}

// rootDefault matches a variable whose default, used when it is unset, is root: `${PUID:-0}`.
var rootDefault = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=](0+|root)\}$`)

// rootUser reports whether a user, as `user[:group]`, is root: empty, `root`, a uid of 0, or a
// variable that is root when unset.
func rootUser(u string) bool {
	name := u
	if strings.HasPrefix(u, "${") {
		// The default inside the braces holds a colon of its own.
		if end := strings.IndexByte(u, '}'); end > 0 {
			name = u[:end+1]
		}
	} else {
		name, _, _ = strings.Cut(u, ":")
	}
	if name == "" || name == "root" || rootDefault.MatchString(name) {
		return true
	}
	return strings.Trim(name, "0") == "" && isDigits(name)
}
