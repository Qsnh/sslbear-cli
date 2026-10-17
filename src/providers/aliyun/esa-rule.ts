/**
 * 按主机名对 ESA 规则表达式求值，如 `(http.host eq "www.example.com") or (ends_with(http.host, ".example.cn"))`。
 * SSL/TLS 规则只支持 http.host 一个匹配字段，因此只需支持主机名相关的比较。
 * 与 ESA 一致，比较区分大小写（不区分时规则里要用 lower()）；主机名按浏览器发送的小写形式参与比较。
 * 语法见 https://help.aliyun.com/zh/edge-security-acceleration/esa/user-guide/operators
 */

type Token = { t: "str" | "word" | "sym"; v: string };

/** undefined 表示无法判断：引用了其他字段、列表（$name），或表达式无法解析 */
type Tri = boolean | undefined;
type Value = string | number | boolean | Value[] | undefined;

const SYMBOLS2 = ["==", "!=", "<=", ">=", "&&", "||"];
const OPERATORS = new Map([
  ["eq", "eq"],
  ["==", "eq"],
  ["ne", "ne"],
  ["!=", "ne"],
  ["contains", "contains"],
  ["matches", "matches"],
  ["~", "matches"],
  ["in", "in"],
  ["lt", "lt"],
  ["<", "lt"],
  ["le", "le"],
  ["<=", "le"],
  ["gt", "gt"],
  [">", "gt"],
  ["ge", "ge"],
  [">=", "ge"],
]);

function tokenize(s: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < s.length) {
    const ch = s[i]!;
    if (/\s/.test(ch)) {
      i++;
    } else if (ch === '"') {
      // 只有 \" 和 \\ 是转义，其余反斜杠原样保留（正则里的 \. 等）
      let v = "";
      for (i++; i < s.length && s[i] !== '"'; i++) {
        if (s[i] === "\\" && (s[i + 1] === '"' || s[i + 1] === "\\")) i++;
        v += s[i];
      }
      if (i >= s.length) throw new SyntaxError("字符串未闭合");
      i++;
      out.push({ t: "str", v });
    } else if (SYMBOLS2.includes(s.slice(i, i + 2))) {
      out.push({ t: "sym", v: s.slice(i, i + 2) });
      i += 2;
    } else if ("(){}[],!<>~$".includes(ch)) {
      out.push({ t: "sym", v: ch });
      i++;
    } else {
      // 字段名、关键字、数字，以及集合里不带引号的 IP / CIDR
      const m = /^[\w.:/*-]+/.exec(s.slice(i));
      if (!m) throw new SyntaxError(`无法识别的字符 ${ch}`);
      out.push({ t: "word", v: m[0] });
      i += m[0].length;
    }
  }
  return out;
}

// 三值逻辑：有一边无法判断时，只有结果不受它影响才给出确定值
const triAnd = (a: Tri, b: Tri): Tri => (a === false || b === false ? false : a && b ? true : undefined);
const triOr = (a: Tri, b: Tri): Tri => (a === true || b === true ? true : a === false && b === false ? false : undefined);
const triNot = (a: Tri): Tri => (a === undefined ? undefined : !a);

function compare(op: string, l: Value, r: Value): Tri {
  if (l === undefined || r === undefined) return undefined;
  switch (op) {
    case "eq":
      return typeof l === typeof r ? l === r : undefined;
    case "ne":
      return triNot(compare("eq", l, r));
    case "contains":
      return typeof l === "string" && typeof r === "string" ? l.includes(r) : undefined;
    case "matches":
      if (typeof l !== "string" || typeof r !== "string") return undefined;
      // 规则是 PCRE；u 模式下 \A、[[:alpha:]] 等 JS 不支持的写法会报错（记为无法判断），而不是被当成普通字符误判为不命中
      try {
        return new RegExp(r, "u").test(l);
      } catch {
        return undefined;
      }
    case "in":
      return Array.isArray(r) ? r.map((x) => compare("eq", l, x)).reduce<Tri>(triOr, false) : undefined;
    default:
      if (typeof l !== "number" || typeof r !== "number") return undefined;
      return op === "lt" ? l < r : op === "le" ? l <= r : op === "gt" ? l > r : l >= r;
  }
}

function call(fn: string, args: Value[]): Value {
  const [a, b] = args;
  switch (fn) {
    case "lower":
      return typeof a === "string" ? a.toLowerCase() : undefined;
    case "len":
      return typeof a === "string" ? a.length : undefined;
    case "starts_with":
    case "ends_with":
      if (typeof a !== "string" || typeof b !== "string") return undefined;
      return fn === "starts_with" ? a.startsWith(b) : a.endsWith(b);
    case "exists":
      return a === undefined ? undefined : true;
    default:
      // percent 等取决于请求本身
      return undefined;
  }
}

class Parser {
  private i = 0;

  constructor(
    private tokens: Token[],
    private host: string,
  ) {}

  parse(): Tri {
    const v = this.or();
    if (this.i < this.tokens.length) throw new SyntaxError(`多余的 ${this.tokens[this.i]!.v}`);
    return v;
  }

  private eat(t: Token["t"], ...vs: string[]): string | undefined {
    const tk = this.tokens[this.i];
    if (tk && tk.t === t && vs.includes(tk.v)) {
      this.i++;
      return tk.v;
    }
    return undefined;
  }

  private expect(sym: string) {
    if (!this.eat("sym", sym)) throw new SyntaxError(`缺少 ${sym}`);
  }

  private or(): Tri {
    let v = this.and();
    while (this.eat("word", "or") || this.eat("sym", "||")) v = triOr(v, this.and());
    return v;
  }

  private and(): Tri {
    let v = this.not();
    while (this.eat("word", "and") || this.eat("sym", "&&")) v = triAnd(v, this.not());
    return v;
  }

  private not(): Tri {
    if (this.eat("word", "not") || this.eat("sym", "!")) return triNot(this.not());
    const left = this.value();
    const tk = this.tokens[this.i];
    const op = tk && tk.t !== "str" ? OPERATORS.get(tk.v) : undefined;
    if (!op) return typeof left === "boolean" ? left : undefined;
    this.i++;
    return compare(op, left, this.value());
  }

  private value(): Value {
    const tk = this.tokens[this.i++];
    if (!tk) throw new SyntaxError("表达式不完整");
    if (tk.t === "str") return tk.v;
    if (tk.t === "sym") {
      if (tk.v === "(") {
        const v = this.or();
        this.expect(")");
        return v;
      }
      if (tk.v === "{") {
        const items: Value[] = [];
        while (!this.eat("sym", "}")) {
          if (!this.eat("sym", ",")) items.push(this.value());
        }
        return items;
      }
      if (tk.v === "$" && this.tokens[this.i]?.t === "word") {
        this.i++;
        return undefined;
      }
      throw new SyntaxError(`意外的 ${tk.v}`);
    }
    if (tk.v === "true" || tk.v === "false") return tk.v === "true";
    if (/^\d+$/.test(tk.v)) return Number(tk.v);
    if (this.eat("sym", "(")) {
      const args: Value[] = [];
      if (!this.eat("sym", ")")) {
        do args.push(this.value());
        while (this.eat("sym", ","));
        this.expect(")");
      }
      return call(tk.v, args);
    }
    // 字段，可带 ["name"] / [*] 下标
    while (this.eat("sym", "[")) {
      this.i++;
      this.expect("]");
    }
    return tk.v === "http.host" ? this.host : undefined;
  }
}

/** null 表示表达式无法解析 */
function evaluate(expr: string, host: string): Tri | null {
  try {
    return new Parser(tokenize(expr), host).parse();
  } catch {
    return null;
  }
}

/** 规则是否命中该主机名；无法判断时返回 undefined */
export function matchHost(expr: string, host: string): boolean | undefined {
  const h = host.toLowerCase();
  let v = evaluate(expr, h);
  // API 文档示例里的规则带着转义过的引号（\"），万一实际返回也是这样导致无法解析，去掉转义再试一次
  if (v === null && expr.includes('\\"')) v = evaluate(expr.replaceAll('\\"', '"'), h);
  return v ?? undefined;
}
