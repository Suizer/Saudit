import {
  Ac as L,
  B as R,
  Ba as ie,
  D as Z,
  Da as E,
  Ga as ne,
  Hc as P,
  Ic as ce,
  Jc as T,
  Ka as se,
  Mc as j,
  W as D,
  Z as S,
  Zb as le,
  _ as De,
  ca as B,
  da as $,
  db as re,
  eb as _,
  ed as de,
  fa as ee,
  g as Y,
  gb as oe,
  gd as Se,
  ha as h,
  j as A,
  k as F,
  kc as ae,
  m as p,
  p as X,
  q as H,
  qa as te,
  rd as ge,
  sd as Be,
  va as x,
  w as Q,
  wc as he,
  zc as ue
} from "./chunk-LHKS7QUN.js";
import {
  e as K,
  j as a
} from "./chunk-TWZW5B45.js";

function Ce() {
  if (!k) try {
    k = window?.trustedTypes?.createPolicy("ngx-highlightjs", {
      createHTML: n => n
    })
  } catch {}
  return k
}

function ke(n) {
  return Ce()?.createHTML(n) || n
}
var O, y, Pe, C, G, k, v, Xe, Qe, fe = K(() => {
  j();
  j();
  Be();
  Se();
  De();
  O = new ee("HIGHLIGHT_OPTIONS"), y = (function(n) {
    return n.FULL_WITH_CORE_LIBRARY_IMPORTS = "The full library and the core library were imported, only one of them should be imported!", n.FULL_WITH_LANGUAGE_IMPORTS = "The highlighting languages were imported they are not needed!", n.CORE_WITHOUT_LANGUAGE_IMPORTS = "The highlighting languages were not imported!", n.LANGUAGE_WITHOUT_CORE_IMPORTS = "The core library was not imported!", n.NO_FULL_AND_NO_CORE_IMPORTS = "Highlight.js library was not imported!", n
  })(y || {}), Pe = (() => {
    class n {
      constructor() {
        this.document = h(te), this.isPlatformBrowser = de(h(ne)), this.options = h(O, {
          optional: !0
        }), this._ready = new Y(null), this.ready = X(this._ready.asObservable().pipe(R(e => !!e))), this.isPlatformBrowser && (this.document.defaultView.hljs ? this._ready.next(this.document.defaultView.hljs) : this._loadLibrary().pipe(D(e => this.options?.lineNumbersLoader ? (this.document.defaultView.hljs = e, this.loadLineNumbers().pipe(S(r => {
          r.activateLineNumbers(), this._ready.next(e)
        }))) : (this._ready.next(e), A)), Z(e => (console.error("[HLJS] ", e), this._ready.error(e), A))).subscribe(), this.options?.themePath && this.loadTheme(this.options.themePath))
      }
      _loadLibrary() {
        if (this.options) {
          if (this.options.fullLibraryLoader && this.options.coreLibraryLoader) return p(() => y.FULL_WITH_CORE_LIBRARY_IMPORTS);
          if (this.options.fullLibraryLoader && this.options.languages) return p(() => y.FULL_WITH_LANGUAGE_IMPORTS);
          if (this.options.coreLibraryLoader && !this.options.languages) return p(() => y.CORE_WITHOUT_LANGUAGE_IMPORTS);
          if (!this.options.coreLibraryLoader && this.options.languages) return p(() => y.LANGUAGE_WITHOUT_CORE_IMPORTS);
          if (this.options.fullLibraryLoader) return this.loadFullLibrary();
          if (this.options.coreLibraryLoader && this.options.languages && Object.keys(this.options.languages).length) return this.loadCoreLibrary().pipe(D(e => this._loadLanguages(e)))
        }
        return p(() => y.NO_FULL_AND_NO_CORE_IMPORTS)
      }
      _loadLanguages(e) {
        let r = Object.entries(this.options.languages).map(([u, M]) => C(M()).pipe(S(b => e.registerLanguage(u, b))));
        return Q(r).pipe(H(() => e))
      }
      loadCoreLibrary() {
        return C(this.options.coreLibraryLoader())
      }
      loadFullLibrary() {
        return C(this.options.fullLibraryLoader())
      }
      loadLineNumbers() {
        return F(this.options.lineNumbersLoader())
      }
      setTheme(e) {
        this.isPlatformBrowser && (this._themeLinkElement ? this._themeLinkElement.href = e : this.loadTheme(e))
      }
      loadTheme(e) {
        this._themeLinkElement = this.document.createElement("link"), this._themeLinkElement.href = e, this._themeLinkElement.type = "text/css", this._themeLinkElement.rel = "stylesheet", this._themeLinkElement.media = "screen,print", this.document.head.appendChild(this._themeLinkElement)
      }
      static {
        this.\u0275fac = function(r) {
          return new(r || n)
        }
      }
      static {
        this.\u0275prov = B({
          token: n,
          factory: n.\u0275fac,
          providedIn: "root"
        })
      }
    }
    return n
  })(), C = n => F(n).pipe(R(c => !!c?.default), H(c => c.default)), G = (() => {
    class n {
      constructor() {
        this.loader = h(Pe), this.options = h(O, {
          optional: !0
        }), this.hljsSignal = x(null), this.hljs = he(() => this.hljsSignal()), this.loader.ready.then(e => {
          this.hljsSignal.set(e), this.options?.highlightOptions && e.configure(this.options.highlightOptions)
        })
      }
      highlight(e, r) {
        return a(this, null, function*() {
          return (yield this.loader.ready).highlight(e, r)
        })
      }
      highlightAuto(e, r) {
        return a(this, null, function*() {
          return (yield this.loader.ready).highlightAuto(e, r)
        })
      }
      highlightElement(e) {
        return a(this, null, function*() {
          (yield this.loader.ready).highlightElement(e)
        })
      }
      highlightAll() {
        return a(this, null, function*() {
          (yield this.loader.ready).highlightAll()
        })
      }
      configure(e) {
        return a(this, null, function*() {
          (yield this.loader.ready).configure(e)
        })
      }
      registerLanguage(e, r) {
        return a(this, null, function*() {
          (yield this.loader.ready).registerLanguage(e, r)
        })
      }
      unregisterLanguage(e) {
        return a(this, null, function*() {
          (yield this.loader.ready).unregisterLanguage(e)
        })
      }
      registerAliases(u, M) {
        return a(this, arguments, function*(e, {
          languageName: r
        }) {
          (yield this.loader.ready).registerAliases(e, {
            languageName: r
          })
        })
      }
      listLanguages() {
        return a(this, null, function*() {
          return (yield this.loader.ready).listLanguages()
        })
      }
      getLanguage(e) {
        return a(this, null, function*() {
          return (yield this.loader.ready).getLanguage(e)
        })
      }
      safeMode() {
        return a(this, null, function*() {
          (yield this.loader.ready).safeMode()
        })
      }
      debugMode() {
        return a(this, null, function*() {
          (yield this.loader.ready).debugMode()
        })
      }
      lineNumbersBlock(e, r) {
        return a(this, null, function*() {
          let u = yield this.loader.ready;
          u.lineNumbersBlock && u.lineNumbersBlock(e, r)
        })
      }
      static {
        this.\u0275fac = function(r) {
          return new(r || n)
        }
      }
      static {
        this.\u0275prov = B({
          token: n,
          factory: n.\u0275fac,
          providedIn: "root"
        })
      }
    }
    return n
  })();
  v = (() => {
    class n {
      constructor() {
        this._hljs = h(G), this._nativeElement = h(E).nativeElement, this._sanitizer = h(ge), T({
          write: () => {
            let e = this.code();
            this.setTextContent(e || ""), e && this.highlightElement(e)
          }
        }), T({
          write: () => {
            let e = this.highlightResult();
            this.setInnerHTML(e?.value), this.highlighted.emit(e)
          }
        })
      }
      setTextContent(e) {
        requestAnimationFrame(() => this._nativeElement.textContent = e)
      }
      setInnerHTML(e) {
        requestAnimationFrame(() => this._nativeElement.innerHTML = ke(this._sanitizer.sanitize(se.HTML, e) || ""))
      }
      static {
        this.\u0275fac = function(r) {
          return new(r || n)
        }
      }
      static {
        this.\u0275dir = _({
          type: n
        })
      }
    }
    return n
  })(), Xe = (() => {
    class n extends v {
      constructor() {
        super(...arguments), this.code = L(null, {
          alias: "highlightAuto"
        }), this.highlightResult = x(null), this.languages = L(), this.highlighted = ue()
      }
      highlightElement(e) {
        return a(this, null, function*() {
          let r = yield this._hljs.highlightAuto(e, this.languages());
          this.highlightResult.set(r)
        })
      }
      static {
        this.\u0275fac = (() => {
          let e;
          return function(u) {
            return (e || (e = ie(n)))(u || n)
          }
        })()
      }
      static {
        this.\u0275dir = _({
          type: n,
          selectors: [
            ["", "highlightAuto", ""]
          ],
          hostVars: 2,
          hostBindings: function(r, u) {
            r & 2 && le("hljs", !0)
          },
          inputs: {
            code: [1, "highlightAuto", "code"],
            languages: [1, "languages"]
          },
          outputs: {
            highlighted: "highlighted"
          },
          features: [ae([{
            provide: v,
            useExisting: n
          }]), oe]
        })
      }
    }
    return n
  })(), Qe = (() => {
    class n {
      static {
        this.\u0275fac = function(r) {
          return new(r || n)
        }
      }
      static {
        this.\u0275mod = re({
          type: n
        })
      }
      static {
        this.\u0275inj = $({})
      }
    }
    return n
  })()
});

function nt() {
  let n = window,
    c = document,
    e = "hljs-ln",
    r = "hljs-ln-line",
    u = "hljs-ln-code",
    M = "hljs-ln-numbers",
    b = "hljs-ln-n",
    w = "data-line-number",
    U = /\r\n|\r|\n/g;
  n.hljs ? (n.hljs.initLineNumbersOnLoad = be, n.hljs.lineNumbersBlock = W, n.hljs.lineNumbersValue = _e, ye()) : n.console.error("highlight.js not detected!");

  function me(t) {
    let i = t;
    for (; i;) {
      if (i.className && i.className.indexOf("hljs-ln-code") !== -1) return !0;
      i = i.parentNode
    }
    return !1
  }

  function pe(t) {
    let i = t;
    for (; i.nodeName !== "TABLE";) i = i.parentNode;
    return i
  }

  function Le(t) {
    let i = t.toString(),
      s = t.anchorNode;
    for (; s.nodeName !== "TD";) s = s.parentNode;
    let o = t.focusNode;
    for (; o.nodeName !== "TD";) o = o.parentNode;
    let l = parseInt(s.dataset.lineNumber),
      d = parseInt(o.dataset.lineNumber);
    if (l != d) {
      let f = s.textContent,
        m = o.textContent;
      if (l > d) {
        let g = l;
        l = d, d = g, g = f, f = m, m = g
      }
      for (; i.indexOf(f) !== 0;) f = f.slice(1);
      for (; i.lastIndexOf(m) === -1;) m = m.slice(0, -1);
      let I = f,
        Fe = pe(s);
      for (let g = l + 1; g < d; ++g) {
        let He = N('.{0}[{1}="{2}"]', [u, w, g]),
          Re = Fe.querySelector(He);
        I += `
` + Re.textContent
      }
      return I += `
` + m, I
    } else return i
  }
  document.addEventListener("copy", function(t) {
    let i = window.getSelection();
    if (me(i.anchorNode)) {
      let s;
      window.navigator.userAgent.indexOf("Edge") !== -1 ? s = Le(i) : s = i.toString(), t.clipboardData.setData("text/plain", s), t.preventDefault()
    }
  });

  function ye() {
    let t = c.createElement("style");
    t.type = "text/css", t.innerHTML = N(".{0}{border-collapse:collapse}.{0} td{padding:0}.{1}:before{content:attr({2})}", [e, b, w]), c.getElementsByTagName("head")[0].appendChild(t)
  }

  function be(t) {
    c.readyState === "interactive" || c.readyState === "complete" ? V(t) : n.addEventListener("DOMContentLoaded", function() {
      V(t)
    })
  }

  function V(t) {
    try {
      let i = c.querySelectorAll("code.hljs,code.nohighlight");
      for (let s in i) i.hasOwnProperty(s) && (Ne(i[s]) || W(i[s], t))
    } catch (i) {
      n.console.error("LineNumbers error: ", i)
    }
  }

  function Ne(t) {
    return t.classList.contains("nohljsln")
  }

  function W(t, i) {
    typeof t == "object" && we(function() {
      t.innerHTML = q(t, i)
    })
  }

  function _e(t, i) {
    if (typeof t != "string") return;
    let s = document.createElement("code");
    return s.innerHTML = t, q(s, i)
  }

  function q(t, i) {
    let s = Ee(t, i);
    return z(t), Te(t.innerHTML, s)
  }

  function Te(t, i) {
    let s = J(t);
    if (s[s.length - 1].trim() === "" && s.pop(), s.length > 1 || i.singleLine) {
      let o = "";
      for (let l = 0, d = s.length; l < d; l++) o += N('<tr><td class="{0} {1}" {3}="{5}"><div class="{2}" {3}="{5}"></div></td><td class="{0} {4}" {3}="{5}">{6}</td></tr>', [r, M, b, w, u, l + i.startFrom, s[l].length > 0 ? s[l] : " "]);
      return N('<table class="{0}">{1}</table>', [e, o])
    }
    return t
  }

  function Ee(t, i) {
    return i = i || {}, {
      singleLine: je(i),
      startFrom: ve(t, i)
    }
  }

  function je(t) {
    return t.singleLine ? t.singleLine : !1
  }

  function ve(t, i) {
    let o = 1;
    isFinite(i.startFrom) && (o = i.startFrom);
    let l = Ie(t, "data-ln-start-from");
    return l !== null && (o = Ae(l, 1)), o
  }

  function z(t) {
    let i = t.childNodes;
    for (let s in i)
      if (i.hasOwnProperty(s)) {
        let o = i[s];
        Me(o.textContent) > 0 && (o.childNodes.length > 0 ? z(o) : Oe(o.parentNode))
      }
  }

  function Oe(t) {
    let i = t.className;
    if (!/hljs-/.test(i)) return;
    let s = J(t.innerHTML),
      o = "";
    for (let l = 0; l < s.length; l++) {
      let d = s[l].length > 0 ? s[l] : " ";
      o += N(`<span class="{0}">{1}</span>
`, [i, d])
    }
    t.innerHTML = o.trim()
  }

  function J(t) {
    return t.length === 0 ? [] : t.split(U)
  }

  function Me(t) {
    return (t.trim().match(U) || []).length
  }

  function we(t) {
    n.setTimeout(t, 0)
  }

  function N(t, i) {
    return t.replace(/\{(\d+)\}/g, function(s, o) {
      return i[o] !== void 0 ? i[o] : s
    })
  }

  function Ie(t, i) {
    return t.hasAttribute(i) ? t.getAttribute(i) : null
  }

  function Ae(t, i) {
    if (!t) return i;
    let s = Number(t);
    return isFinite(s) ? s : i
  }
}
var st, Ge = K(() => {
  j();
  j();
  fe();
  st = (() => {
    class n {
      constructor() {
        this.options = h(O)?.lineNumbersOptions, this._hljs = h(G), this._highlight = h(v), this._nativeElement = h(E).nativeElement, this.startFrom = L(this.options?.startFrom, {
          transform: ce
        }), this.singleLine = L(this.options?.singleLine, {
          transform: P
        }), T({
          write: () => {
            this._highlight.highlightResult() && this.addLineNumbers()
          }
        })
      }
      addLineNumbers() {
        this.destroyLineNumbersObserver(), requestAnimationFrame(() => a(this, null, function*() {
          yield this._hljs.lineNumbersBlock(this._nativeElement, {
            startFrom: this.startFrom(),
            singleLine: this.singleLine()
          }), this._lineNumbersObs = new MutationObserver(() => {
            this._nativeElement.firstElementChild?.tagName.toUpperCase() === "TABLE" && this._nativeElement.classList.add("hljs-line-numbers"), this.destroyLineNumbersObserver()
          }), this._lineNumbersObs.observe(this._nativeElement, {
            childList: !0
          })
        }))
      }
      destroyLineNumbersObserver() {
        this._lineNumbersObs && (this._lineNumbersObs.disconnect(), this._lineNumbersObs = null)
      }
      static {
        this.\u0275fac = function(r) {
          return new(r || n)
        }
      }
      static {
        this.\u0275dir = _({
          type: n,
          selectors: [
            ["", "highlight", "", "lineNumbers", ""],
            ["", "highlightAuto", "", "lineNumbers", ""]
          ],
          inputs: {
            startFrom: [1, "startFrom"],
            singleLine: [1, "singleLine"]
          }
        })
      }
    }
    return n
  })()
});
export {
  O as a, Xe as b, Qe as c, fe as d, nt as e, st as f, Ge as g
};