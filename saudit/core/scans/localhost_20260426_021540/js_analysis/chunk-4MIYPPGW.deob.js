import {
  $ as Q,
  $a as Po,
  $b as Wi,
  $c as bl,
  A as Us,
  Aa as mt,
  Ab as ct,
  Ac as ul,
  B as K,
  Ba as Z,
  Bb as rt,
  Bc as Gi,
  C as Io,
  Ca as Zs,
  Cb as ne,
  Cc as hl,
  D as at,
  Da as D,
  Db as ke,
  E as ee,
  Ea as No,
  Eb as Te,
  Ec as At,
  F as Xe,
  Fa as Wn,
  Fb as Kt,
  G as Oo,
  Ga as Xs,
  H as yt,
  Ha as Gn,
  Hc as F,
  Ia as Qs,
  Ic as ml,
  Ja as Js,
  Jb as Kn,
  Jc as fl,
  K as ko,
  Ka as ti,
  Kb as Hi,
  Kc as Qn,
  Lb as dt,
  Lc as pl,
  M as Qe,
  Mc as f,
  N as he,
  Nb as Ht,
  Nc as zo,
  O as To,
  Oa as tl,
  Ob as Tt,
  Oc as gl,
  P as Hs,
  Pb as U,
  Pc as qi,
  Q as Fo,
  Qa as q,
  Qb as Fe,
  R as $s,
  Ra as el,
  Rb as Rt,
  Rc as vl,
  S as Ws,
  Sa as A,
  Sb as et,
  Sc as fe,
  T as Je,
  Ta as E,
  Tb as it,
  Tc as _l,
  U as zn,
  Ua as Ot,
  Ub as sl,
  V as Ie,
  Va as Oe,
  Vb as $i,
  W as st,
  Wa as kt,
  Wb as Vo,
  X as Dt,
  Xa as lt,
  Xb as jo,
  Y as Gs,
  Ya as C,
  Z as W,
  Za as il,
  Zb as H,
  _ as nt,
  _a as me,
  _b as Zn,
  a as ft,
  aa as qs,
  ab as nl,
  ac as ll,
  b as Bs,
  ba as gt,
  bb as qn,
  bc as Bo,
  c as Yt,
  ca as m,
  cb as P,
  d as Ao,
  da as S,
  db as R,
  e as ji,
  ea as Ys,
  eb as p,
  ed as yl,
  f as y,
  fa as v,
  fb as rl,
  fd as Cl,
  g as Et,
  ga as G,
  gb as L,
  gd as Pe,
  ha as l,
  ib as ei,
  j as Ut,
  ja as It,
  k as pt,
  ka as Vt,
  kb as ol,
  kc as z,
  l as g,
  la as Un,
  lb as Yn,
  ld as ni,
  m as Re,
  ma as Hn,
  mb as Lo,
  n as Lt,
  nb as al,
  o as zs,
  ob as ie,
  pa as N,
  pd as Uo,
  q as b,
  qa as O,
  qb as tt,
  qd as xl,
  r as Ke,
  ra as Bi,
  rd as wl,
  s as St,
  sa as zi,
  sb as vt,
  sc as cl,
  sd as El,
  t as Mo,
  ta as $n,
  tc as dl,
  u as Ae,
  ua as Ui,
  ub as _t,
  v as Me,
  va as J,
  vc as ut,
  w as Ze,
  wa as Ks,
  wc as Zt,
  xa as ht,
  xc as Ne,
  yc as Xn,
  zb as ii
} from "./chunk-LHKS7QUN.js";
import {
  a as h,
  b as $,
  e as _,
  j as js
} from "./chunk-TWZW5B45.js";
var Jn, Ho = _(() => {
  Jn = {
    production: !0,
    hostServer: "."
  }
});

function Ki(i, n) {
  if (i === n) return !0;
  if (i === null || n === null) return !1;
  if (i !== i && n !== n) return !0;
  let t = typeof i,
    e = typeof n,
    r, o, a;
  if (t == e && t == "object")
    if (Array.isArray(i)) {
      if (!Array.isArray(n)) return !1;
      if ((r = i.length) == n.length) {
        for (o = 0; o < r; o++)
          if (!Ki(i[o], n[o])) return !1;
        return !0
      }
    } else {
      if (Array.isArray(n)) return !1;
      a = Object.create(null);
      for (o in i) {
        if (!Ki(i[o], n[o])) return !1;
        a[o] = !0
      }
      for (o in n)
        if (!(o in a) && typeof n[o] < "u") return !1;
      return !0
    } return !1
}

function Ft(i) {
  return typeof i < "u" && i !== null
}

function $o(i) {
  return i && typeof i == "object" && !Array.isArray(i)
}

function Ml(i, n) {
  let t = Object.assign({}, i);
  return $o(i) && $o(n) && Object.keys(n).forEach(e => {
    $o(n[e]) ? e in i ? t[e] = Ml(i[e], n[e]) : Object.assign(t, {
      [e]: n[e]
    }) : Object.assign(t, {
      [e]: n[e]
    })
  }), t
}
var ri, Sl, Yi, Dl, oi, Rl, ai, Al, tr, Wo, Go, qo, Yo, si, Qg, Jg, tv, Il = _(() => {
  f();
  f();
  nt();
  ht();
  ri = class {}, Sl = (() => {
    class i extends ri {
      getTranslation(t) {
        return g({})
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })(), Yi = class {}, Dl = (() => {
    class i {
      handle(t) {
        return t.key
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })();
  oi = class {}, Rl = (() => {
    class i extends oi {
      templateMatcher = /{{\s?([^{}\s]*)\s?}}/g;
      interpolate(t, e) {
        let r;
        return typeof t == "string" ? r = this.interpolateString(t, e) : typeof t == "function" ? r = this.interpolateFunction(t, e) : r = t, r
      }
      getValue(t, e) {
        let r = typeof e == "string" ? e.split(".") : [e];
        e = "";
        do e += r.shift(), Ft(t) && Ft(t[e]) && (typeof t[e] == "object" || !r.length) ? (t = t[e], e = "") : r.length ? e += "." : t = void 0; while (r.length);
        return t
      }
      interpolateFunction(t, e) {
        return t(e)
      }
      interpolateString(t, e) {
        return e ? t.replace(this.templateMatcher, (r, o) => {
          let a = this.getValue(e, o);
          return Ft(a) ? a : r
        }) : t
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })(), ai = class {}, Al = (() => {
    class i extends ai {
      compile(t, e) {
        return t
      }
      compileTranslations(t, e) {
        return t
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })(), tr = class {
    defaultLang;
    currentLang = this.defaultLang;
    translations = {};
    langs = [];
    onTranslationChange = new A;
    onLangChange = new A;
    onDefaultLangChange = new A
  }, Wo = new v("USE_STORE"), Go = new v("USE_DEFAULT_LANG"), qo = new v("DEFAULT_LANGUAGE"), Yo = new v("USE_EXTEND"), si = (() => {
    class i {
      store;
      currentLoader;
      compiler;
      parser;
      missingTranslationHandler;
      useDefaultLang;
      isolate;
      extend;
      loadingTranslations;
      pending = !1;
      _onTranslationChange = new A;
      _onLangChange = new A;
      _onDefaultLangChange = new A;
      _defaultLang;
      _currentLang;
      _langs = [];
      _translations = {};
      _translationRequests = {};
      get onTranslationChange() {
        return this.isolate ? this._onTranslationChange : this.store.onTranslationChange
      }
      get onLangChange() {
        return this.isolate ? this._onLangChange : this.store.onLangChange
      }
      get onDefaultLangChange() {
        return this.isolate ? this._onDefaultLangChange : this.store.onDefaultLangChange
      }
      get defaultLang() {
        return this.isolate ? this._defaultLang : this.store.defaultLang
      }
      set defaultLang(t) {
        this.isolate ? this._defaultLang = t : this.store.defaultLang = t
      }
      get currentLang() {
        return this.isolate ? this._currentLang : this.store.currentLang
      }
      set currentLang(t) {
        this.isolate ? this._currentLang = t : this.store.currentLang = t
      }
      get langs() {
        return this.isolate ? this._langs : this.store.langs
      }
      set langs(t) {
        this.isolate ? this._langs = t : this.store.langs = t
      }
      get translations() {
        return this.isolate ? this._translations : this.store.translations
      }
      set translations(t) {
        this.isolate ? this._translations = t : this.store.translations = t
      }
      constructor(t, e, r, o, a, s = !0, c = !1, d = !1, u) {
        this.store = t, this.currentLoader = e, this.compiler = r, this.parser = o, this.missingTranslationHandler = a, this.useDefaultLang = s, this.isolate = c, this.extend = d, u && this.setDefaultLang(u)
      }
      setDefaultLang(t) {
        if (t === this.defaultLang) return;
        let e = this.retrieveTranslations(t);
        typeof e < "u" ? (this.defaultLang == null && (this.defaultLang = t), e.pipe(yt(1)).subscribe(r => {
          this.changeDefaultLang(t)
        })) : this.changeDefaultLang(t)
      }
      getDefaultLang() {
        return this.defaultLang
      }
      use(t) {
        if (t === this.currentLang) return g(this.translations[t]);
        let e = this.retrieveTranslations(t);
        return typeof e < "u" ? (this.currentLang || (this.currentLang = t), e.pipe(yt(1)).subscribe(r => {
          this.changeLang(t)
        }), e) : (this.changeLang(t), g(this.translations[t]))
      }
      retrieveTranslations(t) {
        let e;
        return (typeof this.translations[t] > "u" || this.extend) && (this._translationRequests[t] = this._translationRequests[t] || this.getTranslation(t), e = this._translationRequests[t]), e
      }
      getTranslation(t) {
        this.pending = !0;
        let e = this.currentLoader.getTranslation(t).pipe(Je(1), yt(1));
        return this.loadingTranslations = e.pipe(b(r => this.compiler.compileTranslations(r, t)), Je(1), yt(1)), this.loadingTranslations.subscribe({
          next: r => {
            this.translations[t] = this.extend && this.translations[t] ? h(h({}, r), this.translations[t]) : r, this.updateLangs(), this.pending = !1
          },
          error: r => {
            this.pending = !1
          }
        }), e
      }
      setTranslation(t, e, r = !1) {
        e = this.compiler.compileTranslations(e, t), (r || this.extend) && this.translations[t] ? this.translations[t] = Ml(this.translations[t], e) : this.translations[t] = e, this.updateLangs(), this.onTranslationChange.emit({
          lang: t,
          translations: this.translations[t]
        })
      }
      getLangs() {
        return this.langs
      }
      addLangs(t) {
        t.forEach(e => {
          this.langs.indexOf(e) === -1 && this.langs.push(e)
        })
      }
      updateLangs() {
        this.addLangs(Object.keys(this.translations))
      }
      getParsedResult(t, e, r) {
        let o;
        if (e instanceof Array) {
          let a = {},
            s = !1;
          for (let c of e) a[c] = this.getParsedResult(t, c, r), Lt(a[c]) && (s = !0);
          if (s) {
            let c = e.map(d => Lt(a[d]) ? a[d] : g(a[d]));
            return Ze(c).pipe(b(d => {
              let u = {};
              return d.forEach((x, j) => {
                u[e[j]] = x
              }), u
            }))
          }
          return a
        }
        if (t && (o = this.parser.interpolate(this.parser.getValue(t, e), r)), typeof o > "u" && this.defaultLang != null && this.defaultLang !== this.currentLang && this.useDefaultLang && (o = this.parser.interpolate(this.parser.getValue(this.translations[this.defaultLang], e), r)), typeof o > "u") {
          let a = {
            key: e,
            translateService: this
          };
          typeof r < "u" && (a.interpolateParams = r), o = this.missingTranslationHandler.handle(a)
        }
        return typeof o < "u" ? o : e
      }
      get(t, e) {
        if (!Ft(t) || !t.length) throw new Error('Parameter "key" required');
        if (this.pending) return this.loadingTranslations.pipe(ee(r => (r = this.getParsedResult(r, t, e), Lt(r) ? r : g(r))));
        {
          let r = this.getParsedResult(this.translations[this.currentLang], t, e);
          return Lt(r) ? r : g(r)
        }
      }
      getStreamOnTranslationChange(t, e) {
        if (!Ft(t) || !t.length) throw new Error('Parameter "key" required');
        return Ae(Me(() => this.get(t, e)), this.onTranslationChange.pipe(st(r => {
          let o = this.getParsedResult(r.translations, t, e);
          return typeof o.subscribe == "function" ? o : g(o)
        })))
      }
      stream(t, e) {
        if (!Ft(t) || !t.length) throw new Error('Parameter "key" required');
        return Ae(Me(() => this.get(t, e)), this.onLangChange.pipe(st(r => {
          let o = this.getParsedResult(r.translations, t, e);
          return Lt(o) ? o : g(o)
        })))
      }
      instant(t, e) {
        if (!Ft(t) || !t.length) throw new Error('Parameter "key" required');
        let r = this.getParsedResult(this.translations[this.currentLang], t, e);
        if (Lt(r)) {
          if (t instanceof Array) {
            let o = {};
            return t.forEach((a, s) => {
              o[t[s]] = t[s]
            }), o
          }
          return t
        } else return r
      }
      set(t, e, r = this.currentLang) {
        this.translations[r][t] = this.compiler.compile(e, r), this.updateLangs(), this.onTranslationChange.emit({
          lang: r,
          translations: this.translations[r]
        })
      }
      changeLang(t) {
        this.currentLang = t, this.onLangChange.emit({
          lang: t,
          translations: this.translations[t]
        }), this.defaultLang == null && this.changeDefaultLang(t)
      }
      changeDefaultLang(t) {
        this.defaultLang = t, this.onDefaultLangChange.emit({
          lang: t,
          translations: this.translations[t]
        })
      }
      reloadLang(t) {
        return this.resetLang(t), this.getTranslation(t)
      }
      resetLang(t) {
        this._translationRequests[t] = void 0, this.translations[t] = void 0
      }
      getBrowserLang() {
        if (typeof window > "u" || typeof window.navigator > "u") return;
        let t = window.navigator.languages ? window.navigator.languages[0] : null;
        if (t = t || window.navigator.language || window.navigator.browserLanguage || window.navigator.userLanguage, !(typeof t > "u")) return t.indexOf("-") !== -1 && (t = t.split("-")[0]), t.indexOf("_") !== -1 && (t = t.split("_")[0]), t
      }
      getBrowserCultureLang() {
        if (typeof window > "u" || typeof window.navigator > "u") return;
        let t = window.navigator.languages ? window.navigator.languages[0] : null;
        return t = t || window.navigator.language || window.navigator.browserLanguage || window.navigator.userLanguage, t
      }
      static \u0275fac = function(e) {
        return new(e || i)(G(tr), G(ri), G(ai), G(oi), G(Yi), G(Go), G(Wo), G(Yo), G(qo))
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })(), Qg = (() => {
    class i {
      translateService;
      element;
      _ref;
      key;
      lastParams;
      currentParams;
      onLangChangeSub;
      onDefaultLangChangeSub;
      onTranslationChangeSub;
      set translate(t) {
        t && (this.key = t, this.checkNodes())
      }
      set translateParams(t) {
        Ki(this.currentParams, t) || (this.currentParams = t, this.checkNodes(!0))
      }
      constructor(t, e, r) {
        this.translateService = t, this.element = e, this._ref = r, this.onTranslationChangeSub || (this.onTranslationChangeSub = this.translateService.onTranslationChange.subscribe(o => {
          o.lang === this.translateService.currentLang && this.checkNodes(!0, o.translations)
        })), this.onLangChangeSub || (this.onLangChangeSub = this.translateService.onLangChange.subscribe(o => {
          this.checkNodes(!0, o.translations)
        })), this.onDefaultLangChangeSub || (this.onDefaultLangChangeSub = this.translateService.onDefaultLangChange.subscribe(o => {
          this.checkNodes(!0)
        }))
      }
      ngAfterViewChecked() {
        this.checkNodes()
      }
      checkNodes(t = !1, e) {
        let r = this.element.nativeElement.childNodes;
        r.length || (this.setContent(this.element.nativeElement, this.key), r = this.element.nativeElement.childNodes);
        for (let o = 0; o < r.length; ++o) {
          let a = r[o];
          if (a.nodeType === 3) {
            let s;
            if (t && (a.lastKey = null), Ft(a.lookupKey)) s = a.lookupKey;
            else if (this.key) s = this.key;
            else {
              let c = this.getContent(a),
                d = c.trim();
              d.length && (a.lookupKey = d, c !== a.currentValue ? (s = d, a.originalContent = c || a.originalContent) : a.originalContent ? s = a.originalContent.trim() : c !== a.currentValue && (s = d, a.originalContent = c || a.originalContent))
            }
            this.updateValue(s, a, e)
          }
        }
      }
      updateValue(t, e, r) {
        if (t) {
          if (e.lastKey === t && this.lastParams === this.currentParams) return;
          this.lastParams = this.currentParams;
          let o = a => {
            a !== t && (e.lastKey = t), e.originalContent || (e.originalContent = this.getContent(e)), e.currentValue = Ft(a) ? a : e.originalContent || t, this.setContent(e, this.key ? e.currentValue : e.originalContent.replace(t, e.currentValue)), this._ref.markForCheck()
          };
          if (Ft(r)) {
            let a = this.translateService.getParsedResult(r, t, this.currentParams);
            Lt(a) ? a.subscribe({
              next: o
            }) : o(a)
          } else this.translateService.get(t, this.currentParams).subscribe(o)
        }
      }
      getContent(t) {
        return Ft(t.textContent) ? t.textContent : t.data
      }
      setContent(t, e) {
        Ft(t.textContent) ? t.textContent = e : t.data = e
      }
      ngOnDestroy() {
        this.onLangChangeSub && this.onLangChangeSub.unsubscribe(), this.onDefaultLangChangeSub && this.onDefaultLangChangeSub.unsubscribe(), this.onTranslationChangeSub && this.onTranslationChangeSub.unsubscribe()
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(si), C(D), C(At))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "translate", ""],
          ["", "ngx-translate", ""]
        ],
        inputs: {
          translate: "translate",
          translateParams: "translateParams"
        },
        standalone: !1
      })
    }
    return i
  })(), Jg = (() => {
    class i {
      translate;
      _ref;
      value = "";
      lastKey = null;
      lastParams = [];
      onTranslationChange;
      onLangChange;
      onDefaultLangChange;
      constructor(t, e) {
        this.translate = t, this._ref = e
      }
      updateValue(t, e, r) {
        let o = a => {
          this.value = a !== void 0 ? a : t, this.lastKey = t, this._ref.markForCheck()
        };
        if (r) {
          let a = this.translate.getParsedResult(r, t, e);
          Lt(a.subscribe) ? a.subscribe(o) : o(a)
        }
        this.translate.get(t, e).subscribe(o)
      }
      transform(t, ...e) {
        if (!t || !t.length) return t;
        if (Ki(t, this.lastKey) && Ki(e, this.lastParams)) return this.value;
        let r;
        if (Ft(e[0]) && e.length)
          if (typeof e[0] == "string" && e[0].length) {
            let o = e[0].replace(/(\')?([a-zA-Z0-9_]+)(\')?(\s)?:/g, '"$2":').replace(/:(\s)?(\')(.*?)(\')/g, ':"$3"');
            try {
              r = JSON.parse(o)
            } catch {
              throw new SyntaxError(`Wrong parameter in TranslatePipe. Expected a valid Object, received: ${e[0]}`)
            }
          } else typeof e[0] == "object" && !Array.isArray(e[0]) && (r = e[0]);
        return this.lastKey = t, this.lastParams = e, this.updateValue(t, r), this._dispose(), this.onTranslationChange || (this.onTranslationChange = this.translate.onTranslationChange.subscribe(o => {
          this.lastKey && o.lang === this.translate.currentLang && (this.lastKey = null, this.updateValue(t, r, o.translations))
        })), this.onLangChange || (this.onLangChange = this.translate.onLangChange.subscribe(o => {
          this.lastKey && (this.lastKey = null, this.updateValue(t, r, o.translations))
        })), this.onDefaultLangChange || (this.onDefaultLangChange = this.translate.onDefaultLangChange.subscribe(() => {
          this.lastKey && (this.lastKey = null, this.updateValue(t, r))
        })), this.value
      }
      _dispose() {
        typeof this.onTranslationChange < "u" && (this.onTranslationChange.unsubscribe(), this.onTranslationChange = void 0), typeof this.onLangChange < "u" && (this.onLangChange.unsubscribe(), this.onLangChange = void 0), typeof this.onDefaultLangChange < "u" && (this.onDefaultLangChange.unsubscribe(), this.onDefaultLangChange = void 0)
      }
      ngOnDestroy() {
        this._dispose()
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(si, 16), C(At, 16))
      };
      static \u0275pipe = rl({
        name: "translate",
        type: i,
        pure: !1,
        standalone: !1
      });
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })(), tv = (() => {
    class i {
      static forRoot(t = {}) {
        return {
          ngModule: i,
          providers: [t.loader || {
            provide: ri,
            useClass: Sl
          }, t.compiler || {
            provide: ai,
            useClass: Al
          }, t.parser || {
            provide: oi,
            useClass: Rl
          }, t.missingTranslationHandler || {
            provide: Yi,
            useClass: Dl
          }, tr, {
            provide: Wo,
            useValue: t.isolate
          }, {
            provide: Go,
            useValue: t.useDefaultLang
          }, {
            provide: Yo,
            useValue: t.extend
          }, {
            provide: qo,
            useValue: t.defaultLanguage
          }, si]
        }
      }
      static forChild(t = {}) {
        return {
          ngModule: i,
          providers: [t.loader || {
            provide: ri,
            useClass: Sl
          }, t.compiler || {
            provide: ai,
            useClass: Al
          }, t.parser || {
            provide: oi,
            useClass: Rl
          }, t.missingTranslationHandler || {
            provide: Yi,
            useClass: Dl
          }, {
            provide: Wo,
            useValue: t.isolate
          }, {
            provide: Go,
            useValue: t.useDefaultLang
          }, {
            provide: Yo,
            useValue: t.extend
          }, {
            provide: qo,
            useValue: t.defaultLanguage
          }, si]
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })()
});

function je(i) {
  return new Jo(i)
}

function Vl(i, n, t) {
  let e = t.path.split("/");
  if (e.length > i.length || t.pathMatch === "full" && (n.hasChildren() || e.length < i.length)) return null;
  let r = {};
  for (let o = 0; o < e.length; o++) {
    let a = e[o],
      s = i[o];
    if (a[0] === ":") r[a.substring(1)] = s;
    else if (a !== s.path) return null
  }
  return {
    consumed: i.slice(0, e.length),
    posParams: r
  }
}

function oh(i, n) {
  if (i.length !== n.length) return !1;
  for (let t = 0; t < i.length; ++t)
    if (!Xt(i[t], n[t])) return !1;
  return !0
}

function Xt(i, n) {
  let t = i ? ta(i) : void 0,
    e = n ? ta(n) : void 0;
  if (!t || !e || t.length != e.length) return !1;
  let r;
  for (let o = 0; o < t.length; o++)
    if (r = t[o], !jl(i[r], n[r])) return !1;
  return !0
}

function ta(i) {
  return [...Object.keys(i), ...Object.getOwnPropertySymbols(i)]
}

function jl(i, n) {
  if (Array.isArray(i) && Array.isArray(n)) {
    if (i.length !== n.length) return !1;
    let t = [...i].sort(),
      e = [...n].sort();
    return t.every((r, o) => e[o] === r)
  } else return i === n
}

function Bl(i) {
  return i.length > 0 ? i[i.length - 1] : null
}

function oe(i) {
  return Lt(i) ? i : Yn(i) ? pt(Promise.resolve(i)) : g(i)
}

function Ol(i, n, t) {
  return ah[t.paths](i.root, n.root, t.matrixParams) && zl[t.queryParams](i.queryParams, n.queryParams) && !(t.fragment === "exact" && i.fragment !== n.fragment)
}

function sh(i, n) {
  return Xt(i, n)
}

function Ul(i, n, t) {
  if (!Le(i.segments, n.segments) || !nr(i.segments, n.segments, t) || i.numberOfChildren !== n.numberOfChildren) return !1;
  for (let e in n.children)
    if (!i.children[e] || !Ul(i.children[e], n.children[e], t)) return !1;
  return !0
}

function lh(i, n) {
  return Object.keys(n).length <= Object.keys(i).length && Object.keys(n).every(t => jl(i[t], n[t]))
}

function Hl(i, n, t) {
  return $l(i, n, n.segments, t)
}

function $l(i, n, t, e) {
  if (i.segments.length > t.length) {
    let r = i.segments.slice(0, t.length);
    return !(!Le(r, t) || n.hasChildren() || !nr(r, t, e))
  } else if (i.segments.length === t.length) {
    if (!Le(i.segments, t) || !nr(i.segments, t, e)) return !1;
    for (let r in n.children)
      if (!i.children[r] || !Hl(i.children[r], n.children[r], e)) return !1;
    return !0
  } else {
    let r = t.slice(0, i.segments.length),
      o = t.slice(i.segments.length);
    return !Le(i.segments, r) || !nr(i.segments, r, e) || !i.children[w] ? !1 : $l(i.children[w], n, o, e)
  }
}

function nr(i, n, t) {
  return n.every((e, r) => zl[t](i[r].parameters, e.parameters))
}

function ch(i, n) {
  return Le(i, n) && i.every((t, e) => Xt(t.parameters, n[e].parameters))
}

function Le(i, n) {
  return i.length !== n.length ? !1 : i.every((t, e) => t.path === n[e].path)
}

function dh(i, n) {
  let t = [];
  return Object.entries(i.children).forEach(([e, r]) => {
    e === w && (t = t.concat(n(r, e)))
  }), Object.entries(i.children).forEach(([e, r]) => {
    e !== w && (t = t.concat(n(r, e)))
  }), t
}

function rr(i) {
  return i.segments.map(n => Gl(n)).join("/")
}

function Zi(i, n) {
  if (!i.hasChildren()) return rr(i);
  if (n) {
    let t = i.children[w] ? Zi(i.children[w], !1) : "",
      e = [];
    return Object.entries(i.children).forEach(([r, o]) => {
      r !== w && e.push(`${r}:${Zi(o,!1)}`)
    }), e.length > 0 ? `${t}(${e.join("//")})` : t
  } else {
    let t = dh(i, (e, r) => r === w ? [Zi(i.children[w], !1)] : [`${r}:${Zi(e,!1)}`]);
    return Object.keys(i.children).length === 1 && i.children[w] != null ? `${rr(i)}/${t[0]}` : `${rr(i)}/(${t.join("//")})`
  }
}

function Wl(i) {
  return encodeURIComponent(i).replace(/%40/g, "@").replace(/%3A/gi, ":").replace(/%24/g, "$").replace(/%2C/gi, ",")
}

function er(i) {
  return Wl(i).replace(/%3B/gi, ";")
}

function hh(i) {
  return encodeURI(i)
}

function ea(i) {
  return Wl(i).replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/%26/gi, "&")
}

function or(i) {
  return decodeURIComponent(i)
}

function kl(i) {
  return or(i.replace(/\+/g, "%20"))
}

function Gl(i) {
  return `${ea(i.path)}${mh(i.parameters)}`
}

function mh(i) {
  return Object.entries(i).map(([n, t]) => `;${ea(n)}=${ea(t)}`).join("")
}

function fh(i) {
  let n = Object.entries(i).map(([t, e]) => Array.isArray(e) ? e.map(r => `${er(t)}=${er(r)}`).join("&") : `${er(t)}=${er(e)}`).filter(t => t);
  return n.length ? `?${n.join("&")}` : ""
}

function Ko(i) {
  let n = i.match(ph);
  return n ? n[0] : ""
}

function vh(i) {
  let n = i.match(gh);
  return n ? n[0] : ""
}

function bh(i) {
  let n = i.match(_h);
  return n ? n[0] : ""
}

function Ch(i) {
  let n = i.match(yh);
  return n ? n[0] : ""
}

function ql(i) {
  return i.segments.length > 0 ? new k([], {
    [w]: i
  }) : i
}

function Yl(i) {
  let n = {};
  for (let [e, r] of Object.entries(i.children)) {
    let o = Yl(r);
    if (e === w && o.segments.length === 0 && o.hasChildren())
      for (let [a, s] of Object.entries(o.children)) n[a] = s;
    else(o.segments.length > 0 || o.hasChildren()) && (n[e] = o)
  }
  let t = new k(i.segments, n);
  return xh(t)
}

function xh(i) {
  if (i.numberOfChildren === 1 && i.children[w]) {
    let n = i.children[w];
    return new k(i.segments.concat(n.segments), n.children)
  }
  return i
}

function ve(i) {
  return i instanceof Jt
}

function Kl(i, n, t = null, e = null) {
  let r = Zl(i);
  return Xl(r, n, t, e)
}

function Zl(i) {
  let n;

  function t(o) {
    let a = {};
    for (let c of o.children) {
      let d = t(c);
      a[c.outlet] = d
    }
    let s = new k(o.url, a);
    return o === i && (n = s), s
  }
  let e = t(i.root),
    r = ql(e);
  return n ?? r
}

function Xl(i, n, t, e) {
  let r = i;
  for (; r.parent;) r = r.parent;
  if (n.length === 0) return Zo(r, r, r, t, e);
  let o = wh(n);
  if (o.toRoot()) return Zo(r, r, new k([], {}), t, e);
  let a = Eh(o, r, i),
    s = a.processChildren ? Qi(a.segmentGroup, a.index, o.commands) : Jl(a.segmentGroup, a.index, o.commands);
  return Zo(r, a.segmentGroup, s, t, e)
}

function ar(i) {
  return typeof i == "object" && i != null && !i.outlets && !i.segmentPath
}

function tn(i) {
  return typeof i == "object" && i != null && i.outlets
}

function Zo(i, n, t, e, r) {
  let o = {};
  e && Object.entries(e).forEach(([c, d]) => {
    o[c] = Array.isArray(d) ? d.map(u => `${u}`) : `${d}`
  });
  let a;
  i === n ? a = t : a = Ql(i, n, t);
  let s = ql(Yl(a));
  return new Jt(s, o, r)
}

function Ql(i, n, t) {
  let e = {};
  return Object.entries(i.children).forEach(([r, o]) => {
    o === n ? e[r] = t : e[r] = Ql(o, n, t)
  }), new k(i.segments, e)
}

function wh(i) {
  if (typeof i[0] == "string" && i.length === 1 && i[0] === "/") return new sr(!0, 0, i);
  let n = 0,
    t = !1,
    e = i.reduce((r, o, a) => {
      if (typeof o == "object" && o != null) {
        if (o.outlets) {
          let s = {};
          return Object.entries(o.outlets).forEach(([c, d]) => {
            s[c] = typeof d == "string" ? d.split("/") : d
          }), [...r, {
            outlets: s
          }]
        }
        if (o.segmentPath) return [...r, o.segmentPath]
      }
      return typeof o != "string" ? [...r, o] : a === 0 ? (o.split("/").forEach((s, c) => {
        c == 0 && s === "." || (c == 0 && s === "" ? t = !0 : s === ".." ? n++ : s != "" && r.push(s))
      }), r) : [...r, o]
    }, []);
  return new sr(t, n, e)
}

function Eh(i, n, t) {
  if (i.isAbsolute) return new di(n, !0, 0);
  if (!t) return new di(n, !1, NaN);
  if (t.parent === null) return new di(t, !0, 0);
  let e = ar(i.commands[0]) ? 0 : 1,
    r = t.segments.length - 1 + e;
  return Sh(t, r, i.numberOfDoubleDots)
}

function Sh(i, n, t) {
  let e = i,
    r = n,
    o = t;
  for (; o > r;) {
    if (o -= r, e = e.parent, !e) throw new Q(4005, !1);
    r = e.segments.length
  }
  return new di(e, !1, r - o)
}

function Dh(i) {
  return tn(i[0]) ? i[0].outlets : {
    [w]: i
  }
}

function Jl(i, n, t) {
  if (i ??= new k([], {}), i.segments.length === 0 && i.hasChildren()) return Qi(i, n, t);
  let e = Rh(i, n, t),
    r = t.slice(e.commandIndex);
  if (e.match && e.pathIndex < i.segments.length) {
    let o = new k(i.segments.slice(0, e.pathIndex), {});
    return o.children[w] = new k(i.segments.slice(e.pathIndex), i.children), Qi(o, 0, r)
  } else return e.match && r.length === 0 ? new k(i.segments, {}) : e.match && !i.hasChildren() ? na(i, n, t) : e.match ? Qi(i, 0, r) : na(i, n, t)
}

function Qi(i, n, t) {
  if (t.length === 0) return new k(i.segments, {});
  {
    let e = Dh(t),
      r = {};
    if (Object.keys(e).some(o => o !== w) && i.children[w] && i.numberOfChildren === 1 && i.children[w].segments.length === 0) {
      let o = Qi(i.children[w], n, t);
      return new k(i.segments, o.children)
    }
    return Object.entries(e).forEach(([o, a]) => {
      typeof a == "string" && (a = [a]), a !== null && (r[o] = Jl(i.children[o], n, a))
    }), Object.entries(i.children).forEach(([o, a]) => {
      e[o] === void 0 && (r[o] = a)
    }), new k(i.segments, r)
  }
}

function Rh(i, n, t) {
  let e = 0,
    r = n,
    o = {
      match: !1,
      pathIndex: 0,
      commandIndex: 0
    };
  for (; r < i.segments.length;) {
    if (e >= t.length) return o;
    let a = i.segments[r],
      s = t[e];
    if (tn(s)) break;
    let c = `${s}`,
      d = e < t.length - 1 ? t[e + 1] : null;
    if (r > 0 && c === void 0) break;
    if (c && d && typeof d == "object" && d.outlets === void 0) {
      if (!Fl(c, d, a)) return o;
      e += 2
    } else {
      if (!Fl(c, {}, a)) return o;
      e++
    }
    r++
  }
  return {
    match: !0,
    pathIndex: r,
    commandIndex: e
  }
}

function na(i, n, t) {
  let e = i.segments.slice(0, n),
    r = 0;
  for (; r < t.length;) {
    let o = t[r];
    if (tn(o)) {
      let c = Ah(o.outlets);
      return new k(e, c)
    }
    if (r === 0 && ar(t[0])) {
      let c = i.segments[n];
      e.push(new pe(c.path, Tl(t[0]))), r++;
      continue
    }
    let a = tn(o) ? o.outlets[w] : `${o}`,
      s = r < t.length - 1 ? t[r + 1] : null;
    a && s && ar(s) ? (e.push(new pe(a, Tl(s))), r += 2) : (e.push(new pe(a, {})), r++)
  }
  return new k(e, {})
}

function Ah(i) {
  let n = {};
  return Object.entries(i).forEach(([t, e]) => {
    typeof e == "string" && (e = [e]), e !== null && (n[t] = na(new k([], {}), 0, e))
  }), n
}

function Tl(i) {
  let n = {};
  return Object.entries(i).forEach(([t, e]) => n[t] = `${e}`), n
}

function Fl(i, n, t) {
  return i == t.path && Xt(n, t.parameters)
}

function Mh(i) {
  return !(i instanceof nn) && !(i instanceof gi)
}

function Ih(i, n) {
  return i.providers && !i._injector && (i._injector = qn(i.providers, n, `Route: ${i.path}`)), i._injector ?? n
}

function $t(i) {
  return i.outlet || w
}

function Oh(i, n) {
  let t = i.filter(e => $t(e) === n);
  return t.push(...i.filter(e => $t(e) !== n)), t
}

function bi(i) {
  if (!i) return null;
  if (i.routeConfig?._injector) return i.routeConfig._injector;
  for (let n = i.parent; n; n = n.parent) {
    let t = n.routeConfig;
    if (t?._loadedInjector) return t._loadedInjector;
    if (t?._injector) return t._injector
  }
  return null
}

function ra(i, n) {
  if (i === n.value) return n;
  for (let t of n.children) {
    let e = ra(i, t);
    if (e) return e
  }
  return null
}

function oa(i, n) {
  if (i === n.value) return [n];
  for (let t of n.children) {
    let e = oa(i, t);
    if (e.length) return e.unshift(n), e
  }
  return []
}

function ci(i) {
  let n = {};
  return i && i.children.forEach(t => n[t.value.outlet] = t), n
}

function tc(i) {
  let n = kh(i),
    t = new Et([new pe("", {})]),
    e = new Et({}),
    r = new Et({}),
    o = new Et({}),
    a = new Et(""),
    s = new re(t, e, o, a, r, w, i, n.root);
  return s.snapshot = n.root, new rn(new Nt(s, []), n)
}

function kh(i) {
  let n = {},
    t = {},
    e = {},
    o = new Ve([], n, e, "", t, w, i, null, {});
  return new on("", new Nt(o, []))
}

function yr(i, n, t = "emptyOnly") {
  let e, {
    routeConfig: r
  } = i;
  return n !== null && (t === "always" || r?.path === "" || !n.component && !n.routeConfig?.loadComponent) ? e = {
    params: h(h({}, n.params), i.params),
    data: h(h({}, n.data), i.data),
    resolve: h(h(h(h({}, i.data), n.data), r?.data), i._resolvedData)
  } : e = {
    params: h({}, i.params),
    data: h({}, i.data),
    resolve: h(h({}, i.data), i._resolvedData ?? {})
  }, r && ic(r) && (e.resolve[cn] = r.title), e
}

function ma(i, n) {
  n.value._routerState = i, n.children.forEach(t => ma(i, t))
}

function ec(i) {
  let n = i.children.length > 0 ? ` { ${i.children.map(ec).join(", ")} } ` : "";
  return `${i.value}${n}`
}

function Xo(i) {
  if (i.snapshot) {
    let n = i.snapshot,
      t = i._futureSnapshot;
    i.snapshot = t, Xt(n.queryParams, t.queryParams) || i.queryParamsSubject.next(t.queryParams), n.fragment !== t.fragment && i.fragmentSubject.next(t.fragment), Xt(n.params, t.params) || i.paramsSubject.next(t.params), oh(n.url, t.url) || i.urlSubject.next(t.url), Xt(n.data, t.data) || i.dataSubject.next(t.data)
  } else i.snapshot = i._futureSnapshot, i.dataSubject.next(i._futureSnapshot.data)
}

function aa(i, n) {
  let t = Xt(i.params, n.params) && ch(i.url, n.url),
    e = !i.parent != !n.parent;
  return t && !e && (!i.parent || aa(i.parent, n.parent))
}

function ic(i) {
  return typeof i.title == "string" || i.title === null
}

function va(i) {
  let n = i.children && i.children.map(va),
    t = n ? $(h({}, i), {
      children: n
    }) : h({}, i);
  return !t.component && !t.loadComponent && (n || t.loadChildren) && t.outlet && t.outlet !== w && (t.component = ga), t
}

function Th(i, n, t) {
  let e = an(i, n._root, t ? t._root : void 0);
  return new rn(e, n)
}

function an(i, n, t) {
  if (t && i.shouldReuseRoute(n.value, t.value.snapshot)) {
    let e = t.value;
    e._futureSnapshot = n.value;
    let r = Fh(i, n, t);
    return new Nt(e, r)
  } else {
    if (i.shouldAttach(n.value)) {
      let o = i.retrieve(n.value);
      if (o !== null) {
        let a = o.route;
        return a.value._futureSnapshot = n.value, a.children = n.children.map(s => an(i, s)), a
      }
    }
    let e = Nh(n.value),
      r = n.children.map(o => an(i, o));
    return new Nt(e, r)
  }
}

function Fh(i, n, t) {
  return n.children.map(e => {
    for (let r of t.children)
      if (i.shouldReuseRoute(e.value, r.value.snapshot)) return an(i, e, r);
    return an(i, e)
  })
}

function Nh(i) {
  return new re(new Et(i.url), new Et(i.params), new Et(i.queryParams), new Et(i.fragment), new Et(i.data), i.outlet, i.component, i)
}

function Cr(i, n) {
  let {
    redirectTo: t,
    navigationBehaviorOptions: e
  } = ve(n) ? {
    redirectTo: n,
    navigationBehaviorOptions: void 0
  } : n, r = oc(!1, Ct.Redirect);
  return r.url = t, r.navigationBehaviorOptions = e, r
}

function oc(i, n) {
  let t = new Error(`NavigationCancelingError: ${i||""}`);
  return t[rc] = !0, t.cancellationCode = n, t
}

function Ph(i) {
  return ac(i) && ve(i.url)
}

function ac(i) {
  return !!i && i[rc]
}

function Vh(i, n, t) {
  let e = i._root,
    r = n ? n._root : null;
  return Xi(e, r, t, [e.value])
}

function jh(i) {
  let n = i.routeConfig ? i.routeConfig.canActivateChild : null;
  return !n || n.length === 0 ? null : {
    node: i,
    guards: n
  }
}

function yi(i, n) {
  let t = Symbol(),
    e = n.get(i, t);
  return e === t ? typeof i == "function" && !Ys(i) ? i : n.get(i) : e
}

function Xi(i, n, t, e, r = {
  canDeactivateChecks: [],
  canActivateChecks: []
}) {
  let o = ci(n);
  return i.children.forEach(a => {
    Bh(a, o[a.value.outlet], t, e.concat([a.value]), r), delete o[a.value.outlet]
  }), Object.entries(o).forEach(([a, s]) => Ji(s, t.getContext(a), r)), r
}

function Bh(i, n, t, e, r = {
  canDeactivateChecks: [],
  canActivateChecks: []
}) {
  let o = i.value,
    a = n ? n.value : null,
    s = t ? t.getContext(i.value.outlet) : null;
  if (a && o.routeConfig === a.routeConfig) {
    let c = zh(a, o, o.routeConfig.runGuardsAndResolvers);
    c ? r.canActivateChecks.push(new xr(e)) : (o.data = a.data, o._resolvedData = a._resolvedData), o.component ? Xi(i, n, s ? s.children : null, e, r) : Xi(i, n, t, e, r), c && s && s.outlet && s.outlet.isActivated && r.canDeactivateChecks.push(new hi(s.outlet.component, a))
  } else a && Ji(n, s, r), r.canActivateChecks.push(new xr(e)), o.component ? Xi(i, null, s ? s.children : null, e, r) : Xi(i, null, t, e, r);
  return r
}

function zh(i, n, t) {
  if (typeof t == "function") return t(i, n);
  switch (t) {
    case "pathParamsChange":
      return !Le(i.url, n.url);
    case "pathParamsOrQueryParamsChange":
      return !Le(i.url, n.url) || !Xt(i.queryParams, n.queryParams);
    case "always":
      return !0;
    case "paramsOrQueryParamsChange":
      return !aa(i, n) || !Xt(i.queryParams, n.queryParams);
    case "paramsChange":
    default:
      return !aa(i, n)
  }
}

function Ji(i, n, t) {
  let e = ci(i),
    r = i.value;
  Object.entries(e).forEach(([o, a]) => {
    r.component ? n ? Ji(a, n.children.getContext(o), t) : Ji(a, null, t) : Ji(a, n, t)
  }), r.component ? n && n.outlet && n.outlet.isActivated ? t.canDeactivateChecks.push(new hi(n.outlet.component, r)) : t.canDeactivateChecks.push(new hi(null, r)) : t.canDeactivateChecks.push(new hi(null, r))
}

function un(i) {
  return typeof i == "function"
}

function Uh(i) {
  return typeof i == "boolean"
}

function Hh(i) {
  return i && un(i.canLoad)
}

function $h(i) {
  return i && un(i.canActivate)
}

function Wh(i) {
  return i && un(i.canActivateChild)
}

function Gh(i) {
  return i && un(i.canDeactivate)
}

function qh(i) {
  return i && un(i.canMatch)
}

function sc(i) {
  return i instanceof zs || i?.name === "EmptyError"
}

function _i() {
  return st(i => Ke(i.map(n => n.pipe(yt(1), Ie(ir)))).pipe(b(n => {
    for (let t of n)
      if (t !== !0) {
        if (t === ir) return ir;
        if (t === !1 || Yh(t)) return t
      } return !0
  }), K(n => n !== ir), yt(1)))
}

function Yh(i) {
  return ve(i) || i instanceof vi
}

function Kh(i, n) {
  return St(t => {
    let {
      targetSnapshot: e,
      currentSnapshot: r,
      guards: {
        canActivateChecks: o,
        canDeactivateChecks: a
      }
    } = t;
    return a.length === 0 && o.length === 0 ? g($(h({}, t), {
      guardsResult: !0
    })) : Zh(a, e, r, i).pipe(St(s => s && Uh(s) ? Xh(e, o, i, n) : g(s)), b(s => $(h({}, t), {
      guardsResult: s
    })))
  })
}

function Zh(i, n, t, e) {
  return pt(i).pipe(St(r => im(r.component, r.route, t, n, e)), he(r => r !== !0, !0))
}

function Xh(i, n, t, e) {
  return pt(n).pipe(ee(r => Ae(Jh(r.route.parent, e), Qh(r.route, e), em(i, r.path, t), tm(i, r.route, t))), he(r => r !== !0, !0))
}

function Qh(i, n) {
  return i !== null && n && n(new gr(i)), g(!0)
}

function Jh(i, n) {
  return i !== null && n && n(new fr(i)), g(!0)
}

function tm(i, n, t) {
  let e = n.routeConfig ? n.routeConfig.canActivate : null;
  if (!e || e.length === 0) return g(!0);
  let r = e.map(o => Me(() => {
    let a = bi(n) ?? t,
      s = yi(o, a),
      c = $h(s) ? s.canActivate(n, i) : Vt(a, () => s(n, i));
    return oe(c).pipe(he())
  }));
  return g(r).pipe(_i())
}

function em(i, n, t) {
  let e = n[n.length - 1],
    o = n.slice(0, n.length - 1).reverse().map(a => jh(a)).filter(a => a !== null).map(a => Me(() => {
      let s = a.guards.map(c => {
        let d = bi(a.node) ?? t,
          u = yi(c, d),
          x = Wh(u) ? u.canActivateChild(e, i) : Vt(d, () => u(e, i));
        return oe(x).pipe(he())
      });
      return g(s).pipe(_i())
    }));
  return g(o).pipe(_i())
}

function im(i, n, t, e, r) {
  let o = n && n.routeConfig ? n.routeConfig.canDeactivate : null;
  if (!o || o.length === 0) return g(!0);
  let a = o.map(s => {
    let c = bi(n) ?? r,
      d = yi(s, c),
      u = Gh(d) ? d.canDeactivate(i, n, t, e) : Vt(c, () => d(i, n, t, e));
    return oe(u).pipe(he())
  });
  return g(a).pipe(_i())
}

function nm(i, n, t, e) {
  let r = n.canLoad;
  if (r === void 0 || r.length === 0) return g(!0);
  let o = r.map(a => {
    let s = yi(a, i),
      c = Hh(s) ? s.canLoad(n, t) : Vt(i, () => s(n, t));
    return oe(c)
  });
  return g(o).pipe(_i(), lc(e))
}

function lc(i) {
  return Bs(W(n => {
    if (typeof n != "boolean") throw Cr(i, n)
  }), b(n => n === !0))
}

function rm(i, n, t, e) {
  let r = n.canMatch;
  if (!r || r.length === 0) return g(!0);
  let o = r.map(a => {
    let s = yi(a, i),
      c = qh(s) ? s.canMatch(n, t) : Vt(i, () => s(n, t));
    return oe(c)
  });
  return g(o).pipe(_i(), lc(e))
}

function li(i) {
  return Re(new sn(i))
}

function om(i) {
  return Re(new Q(4e3, !1))
}

function am(i) {
  return Re(oc(!1, Ct.GuardRejected))
}

function sm(i, n, t) {
  if (typeof i == "string") return g(i);
  let e = i,
    {
      queryParams: r,
      fragment: o,
      routeConfig: a,
      url: s,
      outlet: c,
      params: d,
      data: u,
      title: x
    } = n;
  return oe(Vt(t, () => e({
    params: d,
    data: u,
    queryParams: r,
    fragment: o,
    routeConfig: a,
    url: s,
    outlet: c,
    title: x
  })))
}

function lm(i, n, t, e, r) {
  let o = cc(i, n, t);
  return o.matched ? (e = Ih(n, e), rm(e, n, t, r).pipe(b(a => a === !0 ? o : h({}, da)))) : g(o)
}

function cc(i, n, t) {
  if (n.path === "**") return cm(t);
  if (n.path === "") return n.pathMatch === "full" && (i.hasChildren() || t.length > 0) ? h({}, da) : {
    matched: !0,
    consumedSegments: [],
    remainingSegments: t,
    parameters: {},
    positionalParamSegments: {}
  };
  let r = (n.matcher || Vl)(t, i, n);
  if (!r) return h({}, da);
  let o = {};
  Object.entries(r.posParams ?? {}).forEach(([s, c]) => {
    o[s] = c.path
  });
  let a = r.consumed.length > 0 ? h(h({}, o), r.consumed[r.consumed.length - 1].parameters) : o;
  return {
    matched: !0,
    consumedSegments: r.consumed,
    remainingSegments: t.slice(r.consumed.length),
    parameters: a,
    positionalParamSegments: r.posParams ?? {}
  }
}

function cm(i) {
  return {
    matched: !0,
    parameters: i.length > 0 ? Bl(i).parameters : {},
    consumedSegments: i,
    remainingSegments: [],
    positionalParamSegments: {}
  }
}

function Nl(i, n, t, e) {
  return t.length > 0 && hm(i, t, e) ? {
    segmentGroup: new k(n, um(e, new k(t, i.children))),
    slicedSegments: []
  } : t.length === 0 && mm(i, t, e) ? {
    segmentGroup: new k(i.segments, dm(i, t, e, i.children)),
    slicedSegments: t
  } : {
    segmentGroup: new k(i.segments, i.children),
    slicedSegments: t
  }
}

function dm(i, n, t, e) {
  let r = {};
  for (let o of t)
    if (Er(i, n, o) && !e[$t(o)]) {
      let a = new k([], {});
      r[$t(o)] = a
    } return h(h({}, e), r)
}

function um(i, n) {
  let t = {};
  t[w] = n;
  for (let e of i)
    if (e.path === "" && $t(e) !== w) {
      let r = new k([], {});
      t[$t(e)] = r
    } return t
}

function hm(i, n, t) {
  return t.some(e => Er(i, n, e) && $t(e) !== w)
}

function mm(i, n, t) {
  return t.some(e => Er(i, n, e))
}

function Er(i, n, t) {
  return (i.hasChildren() || n.length > 0) && t.pathMatch === "full" ? !1 : t.path === ""
}

function fm(i, n, t) {
  return n.length === 0 && !i.children[t]
}

function pm(i, n, t, e, r, o, a = "emptyOnly") {
  return new ha(i, n, t, e, r, a, o).recognize()
}

function vm(i) {
  i.sort((n, t) => n.value.outlet === w ? -1 : t.value.outlet === w ? 1 : n.value.outlet.localeCompare(t.value.outlet))
}

function _m(i) {
  let n = i.value.routeConfig;
  return n && n.path === ""
}

function dc(i) {
  let n = [],
    t = new Set;
  for (let e of i) {
    if (!_m(e)) {
      n.push(e);
      continue
    }
    let r = n.find(o => e.value.routeConfig === o.value.routeConfig);
    r !== void 0 ? (r.children.push(...e.children), t.add(r)) : n.push(e)
  }
  for (let e of t) {
    let r = dc(e.children);
    n.push(new Nt(e.value, r))
  }
  return n.filter(e => !t.has(e))
}

function Pl(i) {
  return i.data || {}
}

function Ll(i) {
  return i.resolve || {}
}

function bm(i, n, t, e, r, o) {
  return St(a => pm(i, n, t, e, a.extractedUrl, r, o).pipe(b(({
    state: s,
    tree: c
  }) => $(h({}, a), {
    targetSnapshot: s,
    urlAfterRedirects: c
  }))))
}

function ym(i, n) {
  return St(t => {
    let {
      targetSnapshot: e,
      guards: {
        canActivateChecks: r
      }
    } = t;
    if (!r.length) return g(t);
    let o = new Set(r.map(c => c.route)),
      a = new Set;
    for (let c of o)
      if (!a.has(c))
        for (let d of uc(c)) a.add(d);
    let s = 0;
    return pt(a).pipe(ee(c => o.has(c) ? Cm(c, e, i, n) : (c.data = yr(c, c.parent, i).resolve, g(void 0))), W(() => s++), To(1), St(c => s === a.size ? g(t) : Ut))
  })
}

function uc(i) {
  let n = i.children.map(t => uc(t)).flat();
  return [i, ...n]
}

function Cm(i, n, t, e) {
  let r = i.routeConfig,
    o = i._resolve;
  return r?.title !== void 0 && !ic(r) && (o[cn] = r.title), Me(() => (i.data = yr(i, i.parent, t).resolve, xm(o, i, n, e).pipe(b(a => (i._resolvedData = a, i.data = h(h({}, i.data), a), null)))))
}

function xm(i, n, t, e) {
  let r = ta(i);
  if (r.length === 0) return g({});
  let o = {};
  return pt(r).pipe(St(a => wm(i[a], n, t, e).pipe(he(), W(s => {
    if (s instanceof vi) throw Cr(new ge, s);
    o[a] = s
  }))), To(1), b(() => o), at(a => sc(a) ? Ut : Re(a)))
}

function wm(i, n, t, e) {
  let r = bi(n) ?? e,
    o = yi(i, r),
    a = o.resolve ? o.resolve(n, t) : Vt(r, () => o(n, t));
  return oe(a)
}

function Qo(i) {
  return st(n => {
    let t = i(n);
    return t ? pt(t).pipe(b(() => n)) : g(n)
  })
}

function mc(i, n, t, e) {
  return oe(Vt(t, () => i.loadChildren())).pipe(b(fc), st(pc), St(r => r instanceof nl || Array.isArray(r) ? g(r) : pt(n.compileModuleAsync(r))), b(r => {
    e && e(i);
    let o, a, s = !1;
    return Array.isArray(r) ? (a = r, s = !0) : (o = r.create(t).injector, a = o.get(Ci, [], {
      optional: !0,
      self: !0
    }).flat()), {
      routes: a.map(va),
      injector: o
    }
  }))
}

function Em(i) {
  return i && typeof i == "object" && "default" in i
}

function fc(i) {
  return Em(i) ? i.default : i
}

function pc(i) {
  return g(i)
}

function gc(i, n, t) {
  let e = i.get(ya),
    r = i.get(O);
  if (!r.startViewTransition || e.skipNextTransition) return e.skipNextTransition = !1, new Promise(d => setTimeout(d));
  let o, a = new Promise(d => {
      o = d
    }),
    s = r.startViewTransition(() => (o(), Dm(i)));
  s.ready.catch(d => {});
  let {
    onViewTransitionCreated: c
  } = e;
  return c && Vt(i, () => c({
    transition: s,
    from: n,
    to: t
  })), a
}

function Dm(i) {
  return new Promise(n => {
    Ot({
      read: () => setTimeout(n)
    }, {
      injector: i
    })
  })
}

function Rm(i) {
  return i !== ui
}

function Ar(i, n) {
  i.events.pipe(K(t => t instanceof jt || t instanceof Qt || t instanceof fi || t instanceof te), b(t => t instanceof jt || t instanceof te ? 0 : (t instanceof Qt ? t.code === Ct.Redirect || t.code === Ct.SupersededByNewNavigation : !1) ? 2 : 1), K(t => t !== 2), yt(1)).subscribe(() => {
    n()
  })
}

function km(i) {
  for (let n = 0; n < i.length; n++)
    if (i[n] == null) throw new Q(4008, !1)
}
var w, cn, Jo, ah, zl, Jt, k, pe, Be, ge, uh, ph, gh, _h, yh, ia, sr, di, ui, ot, Pt, _e, jt, Ct, mi, Qt, te, fi, en, lr, cr, dr, ur, hr, mr, fr, pr, gr, vr, pi, nn, gi, _r, ze, br, Nt, rn, re, Ve, on, nc, fa, sa, dn, pa, ga, vi, rc, Lh, la, xr, hi, ir, sn, ln, ca, da, ua, gm, ha, _a, hc, be, Ci, Sr, Dr, Sm, ba, ya, Ca, Rr, vc, wr, Am, _c, Mm, Im, Om, ae, xa = _(() => {
  Pe();
  f();
  f();
  nt();
  ht();
  El();
  w = "primary", cn = Symbol("RouteTitle"), Jo = class {
    params;
    constructor(n) {
      this.params = n || {}
    }
    has(n) {
      return Object.prototype.hasOwnProperty.call(this.params, n)
    }
    get(n) {
      if (this.has(n)) {
        let t = this.params[n];
        return Array.isArray(t) ? t[0] : t
      }
      return null
    }
    getAll(n) {
      if (this.has(n)) {
        let t = this.params[n];
        return Array.isArray(t) ? t : [t]
      }
      return []
    }
    get keys() {
      return Object.keys(this.params)
    }
  };
  ah = {
    exact: Ul,
    subset: Hl
  }, zl = {
    exact: sh,
    subset: lh,
    ignored: () => !0
  };
  Jt = class {
    root;
    queryParams;
    fragment;
    _queryParamMap;
    constructor(n = new k([], {}), t = {}, e = null) {
      this.root = n, this.queryParams = t, this.fragment = e
    }
    get queryParamMap() {
      return this._queryParamMap ??= je(this.queryParams), this._queryParamMap
    }
    toString() {
      return uh.serialize(this)
    }
  }, k = class {
    segments;
    children;
    parent = null;
    constructor(n, t) {
      this.segments = n, this.children = t, Object.values(t).forEach(e => e.parent = this)
    }
    hasChildren() {
      return this.numberOfChildren > 0
    }
    get numberOfChildren() {
      return Object.keys(this.children).length
    }
    toString() {
      return rr(this)
    }
  }, pe = class {
    path;
    parameters;
    _parameterMap;
    constructor(n, t) {
      this.path = n, this.parameters = t
    }
    get parameterMap() {
      return this._parameterMap ??= je(this.parameters), this._parameterMap
    }
    toString() {
      return Gl(this)
    }
  };
  Be = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: () => new ge,
        providedIn: "root"
      })
    }
    return i
  })(), ge = class {
    parse(n) {
      let t = new ia(n);
      return new Jt(t.parseRootSegment(), t.parseQueryParams(), t.parseFragment())
    }
    serialize(n) {
      let t = `/${Zi(n.root,!0)}`,
        e = fh(n.queryParams),
        r = typeof n.fragment == "string" ? `#${hh(n.fragment)}` : "";
      return `${t}${e}${r}`
    }
  }, uh = new ge;
  ph = /^[^\/()?;#]+/;
  gh = /^[^\/()?;=#]+/;
  _h = /^[^=?&#]+/;
  yh = /^[^&#]+/;
  ia = class {
    url;
    remaining;
    constructor(n) {
      this.url = n, this.remaining = n
    }
    parseRootSegment() {
      return this.consumeOptional("/"), this.remaining === "" || this.peekStartsWith("?") || this.peekStartsWith("#") ? new k([], {}) : new k([], this.parseChildren())
    }
    parseQueryParams() {
      let n = {};
      if (this.consumeOptional("?"))
        do this.parseQueryParam(n); while (this.consumeOptional("&"));
      return n
    }
    parseFragment() {
      return this.consumeOptional("#") ? decodeURIComponent(this.remaining) : null
    }
    parseChildren() {
      if (this.remaining === "") return {};
      this.consumeOptional("/");
      let n = [];
      for (this.peekStartsWith("(") || n.push(this.parseSegment()); this.peekStartsWith("/") && !this.peekStartsWith("//") && !this.peekStartsWith("/(");) this.capture("/"), n.push(this.parseSegment());
      let t = {};
      this.peekStartsWith("/(") && (this.capture("/"), t = this.parseParens(!0));
      let e = {};
      return this.peekStartsWith("(") && (e = this.parseParens(!1)), (n.length > 0 || Object.keys(t).length > 0) && (e[w] = new k(n, t)), e
    }
    parseSegment() {
      let n = Ko(this.remaining);
      if (n === "" && this.peekStartsWith(";")) throw new Q(4009, !1);
      return this.capture(n), new pe(or(n), this.parseMatrixParams())
    }
    parseMatrixParams() {
      let n = {};
      for (; this.consumeOptional(";");) this.parseParam(n);
      return n
    }
    parseParam(n) {
      let t = vh(this.remaining);
      if (!t) return;
      this.capture(t);
      let e = "";
      if (this.consumeOptional("=")) {
        let r = Ko(this.remaining);
        r && (e = r, this.capture(e))
      }
      n[or(t)] = or(e)
    }
    parseQueryParam(n) {
      let t = bh(this.remaining);
      if (!t) return;
      this.capture(t);
      let e = "";
      if (this.consumeOptional("=")) {
        let a = Ch(this.remaining);
        a && (e = a, this.capture(e))
      }
      let r = kl(t),
        o = kl(e);
      if (n.hasOwnProperty(r)) {
        let a = n[r];
        Array.isArray(a) || (a = [a], n[r] = a), a.push(o)
      } else n[r] = o
    }
    parseParens(n) {
      let t = {};
      for (this.capture("("); !this.consumeOptional(")") && this.remaining.length > 0;) {
        let e = Ko(this.remaining),
          r = this.remaining[e.length];
        if (r !== "/" && r !== ")" && r !== ";") throw new Q(4010, !1);
        let o;
        e.indexOf(":") > -1 ? (o = e.slice(0, e.indexOf(":")), this.capture(o), this.capture(":")) : n && (o = w);
        let a = this.parseChildren();
        t[o ?? w] = Object.keys(a).length === 1 && a[w] ? a[w] : new k([], a), this.consumeOptional("//")
      }
      return t
    }
    peekStartsWith(n) {
      return this.remaining.startsWith(n)
    }
    consumeOptional(n) {
      return this.peekStartsWith(n) ? (this.remaining = this.remaining.substring(n.length), !0) : !1
    }
    capture(n) {
      if (!this.consumeOptional(n)) throw new Q(4011, !1)
    }
  };
  sr = class {
    isAbsolute;
    numberOfDoubleDots;
    commands;
    constructor(n, t, e) {
      if (this.isAbsolute = n, this.numberOfDoubleDots = t, this.commands = e, n && e.length > 0 && ar(e[0])) throw new Q(4003, !1);
      let r = e.find(tn);
      if (r && r !== Bl(e)) throw new Q(4004, !1)
    }
    toRoot() {
      return this.isAbsolute && this.commands.length === 1 && this.commands[0] == "/"
    }
  };
  di = class {
    segmentGroup;
    processChildren;
    index;
    constructor(n, t, e) {
      this.segmentGroup = n, this.processChildren = t, this.index = e
    }
  };
  ui = "imperative", ot = (function(i) {
    return i[i.NavigationStart = 0] = "NavigationStart", i[i.NavigationEnd = 1] = "NavigationEnd", i[i.NavigationCancel = 2] = "NavigationCancel", i[i.NavigationError = 3] = "NavigationError", i[i.RoutesRecognized = 4] = "RoutesRecognized", i[i.ResolveStart = 5] = "ResolveStart", i[i.ResolveEnd = 6] = "ResolveEnd", i[i.GuardsCheckStart = 7] = "GuardsCheckStart", i[i.GuardsCheckEnd = 8] = "GuardsCheckEnd", i[i.RouteConfigLoadStart = 9] = "RouteConfigLoadStart", i[i.RouteConfigLoadEnd = 10] = "RouteConfigLoadEnd", i[i.ChildActivationStart = 11] = "ChildActivationStart", i[i.ChildActivationEnd = 12] = "ChildActivationEnd", i[i.ActivationStart = 13] = "ActivationStart", i[i.ActivationEnd = 14] = "ActivationEnd", i[i.Scroll = 15] = "Scroll", i[i.NavigationSkipped = 16] = "NavigationSkipped", i
  })(ot || {}), Pt = class {
    id;
    url;
    constructor(n, t) {
      this.id = n, this.url = t
    }
  }, _e = class extends Pt {
    type = ot.NavigationStart;
    navigationTrigger;
    restoredState;
    constructor(n, t, e = "imperative", r = null) {
      super(n, t), this.navigationTrigger = e, this.restoredState = r
    }
    toString() {
      return `NavigationStart(id: ${this.id}, url: '${this.url}')`
    }
  }, jt = class extends Pt {
    urlAfterRedirects;
    type = ot.NavigationEnd;
    constructor(n, t, e) {
      super(n, t), this.urlAfterRedirects = e
    }
    toString() {
      return `NavigationEnd(id: ${this.id}, url: '${this.url}', urlAfterRedirects: '${this.urlAfterRedirects}')`
    }
  }, Ct = (function(i) {
    return i[i.Redirect = 0] = "Redirect", i[i.SupersededByNewNavigation = 1] = "SupersededByNewNavigation", i[i.NoDataFromResolver = 2] = "NoDataFromResolver", i[i.GuardRejected = 3] = "GuardRejected", i[i.Aborted = 4] = "Aborted", i
  })(Ct || {}), mi = (function(i) {
    return i[i.IgnoredSameUrlNavigation = 0] = "IgnoredSameUrlNavigation", i[i.IgnoredByUrlHandlingStrategy = 1] = "IgnoredByUrlHandlingStrategy", i
  })(mi || {}), Qt = class extends Pt {
    reason;
    code;
    type = ot.NavigationCancel;
    constructor(n, t, e, r) {
      super(n, t), this.reason = e, this.code = r
    }
    toString() {
      return `NavigationCancel(id: ${this.id}, url: '${this.url}')`
    }
  }, te = class extends Pt {
    reason;
    code;
    type = ot.NavigationSkipped;
    constructor(n, t, e, r) {
      super(n, t), this.reason = e, this.code = r
    }
  }, fi = class extends Pt {
    error;
    target;
    type = ot.NavigationError;
    constructor(n, t, e, r) {
      super(n, t), this.error = e, this.target = r
    }
    toString() {
      return `NavigationError(id: ${this.id}, url: '${this.url}', error: ${this.error})`
    }
  }, en = class extends Pt {
    urlAfterRedirects;
    state;
    type = ot.RoutesRecognized;
    constructor(n, t, e, r) {
      super(n, t), this.urlAfterRedirects = e, this.state = r
    }
    toString() {
      return `RoutesRecognized(id: ${this.id}, url: '${this.url}', urlAfterRedirects: '${this.urlAfterRedirects}', state: ${this.state})`
    }
  }, lr = class extends Pt {
    urlAfterRedirects;
    state;
    type = ot.GuardsCheckStart;
    constructor(n, t, e, r) {
      super(n, t), this.urlAfterRedirects = e, this.state = r
    }
    toString() {
      return `GuardsCheckStart(id: ${this.id}, url: '${this.url}', urlAfterRedirects: '${this.urlAfterRedirects}', state: ${this.state})`
    }
  }, cr = class extends Pt {
    urlAfterRedirects;
    state;
    shouldActivate;
    type = ot.GuardsCheckEnd;
    constructor(n, t, e, r, o) {
      super(n, t), this.urlAfterRedirects = e, this.state = r, this.shouldActivate = o
    }
    toString() {
      return `GuardsCheckEnd(id: ${this.id}, url: '${this.url}', urlAfterRedirects: '${this.urlAfterRedirects}', state: ${this.state}, shouldActivate: ${this.shouldActivate})`
    }
  }, dr = class extends Pt {
    urlAfterRedirects;
    state;
    type = ot.ResolveStart;
    constructor(n, t, e, r) {
      super(n, t), this.urlAfterRedirects = e, this.state = r
    }
    toString() {
      return `ResolveStart(id: ${this.id}, url: '${this.url}', urlAfterRedirects: '${this.urlAfterRedirects}', state: ${this.state})`
    }
  }, ur = class extends Pt {
    urlAfterRedirects;
    state;
    type = ot.ResolveEnd;
    constructor(n, t, e, r) {
      super(n, t), this.urlAfterRedirects = e, this.state = r
    }
    toString() {
      return `ResolveEnd(id: ${this.id}, url: '${this.url}', urlAfterRedirects: '${this.urlAfterRedirects}', state: ${this.state})`
    }
  }, hr = class {
    route;
    type = ot.RouteConfigLoadStart;
    constructor(n) {
      this.route = n
    }
    toString() {
      return `RouteConfigLoadStart(path: ${this.route.path})`
    }
  }, mr = class {
    route;
    type = ot.RouteConfigLoadEnd;
    constructor(n) {
      this.route = n
    }
    toString() {
      return `RouteConfigLoadEnd(path: ${this.route.path})`
    }
  }, fr = class {
    snapshot;
    type = ot.ChildActivationStart;
    constructor(n) {
      this.snapshot = n
    }
    toString() {
      return `ChildActivationStart(path: '${this.snapshot.routeConfig&&this.snapshot.routeConfig.path||""}')`
    }
  }, pr = class {
    snapshot;
    type = ot.ChildActivationEnd;
    constructor(n) {
      this.snapshot = n
    }
    toString() {
      return `ChildActivationEnd(path: '${this.snapshot.routeConfig&&this.snapshot.routeConfig.path||""}')`
    }
  }, gr = class {
    snapshot;
    type = ot.ActivationStart;
    constructor(n) {
      this.snapshot = n
    }
    toString() {
      return `ActivationStart(path: '${this.snapshot.routeConfig&&this.snapshot.routeConfig.path||""}')`
    }
  }, vr = class {
    snapshot;
    type = ot.ActivationEnd;
    constructor(n) {
      this.snapshot = n
    }
    toString() {
      return `ActivationEnd(path: '${this.snapshot.routeConfig&&this.snapshot.routeConfig.path||""}')`
    }
  }, pi = class {
    routerEvent;
    position;
    anchor;
    type = ot.Scroll;
    constructor(n, t, e) {
      this.routerEvent = n, this.position = t, this.anchor = e
    }
    toString() {
      let n = this.position ? `${this.position[0]}, ${this.position[1]}` : null;
      return `Scroll(anchor: '${this.anchor}', position: '${n}')`
    }
  }, nn = class {}, gi = class {
    url;
    navigationBehaviorOptions;
    constructor(n, t) {
      this.url = n, this.navigationBehaviorOptions = t
    }
  };
  _r = class {
    rootInjector;
    outlet = null;
    route = null;
    children;
    attachRef = null;
    get injector() {
      return bi(this.route?.snapshot) ?? this.rootInjector
    }
    constructor(n) {
      this.rootInjector = n, this.children = new ze(this.rootInjector)
    }
  }, ze = (() => {
    class i {
      rootInjector;
      contexts = new Map;
      constructor(t) {
        this.rootInjector = t
      }
      onChildOutletCreated(t, e) {
        let r = this.getOrCreateContext(t);
        r.outlet = e, this.contexts.set(t, r)
      }
      onChildOutletDestroyed(t) {
        let e = this.getContext(t);
        e && (e.outlet = null, e.attachRef = null)
      }
      onOutletDeactivated() {
        let t = this.contexts;
        return this.contexts = new Map, t
      }
      onOutletReAttached(t) {
        this.contexts = t
      }
      getOrCreateContext(t) {
        let e = this.getContext(t);
        return e || (e = new _r(this.rootInjector), this.contexts.set(t, e)), e
      }
      getContext(t) {
        return this.contexts.get(t) || null
      }
      static \u0275fac = function(e) {
        return new(e || i)(G(It))
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), br = class {
    _root;
    constructor(n) {
      this._root = n
    }
    get root() {
      return this._root.value
    }
    parent(n) {
      let t = this.pathFromRoot(n);
      return t.length > 1 ? t[t.length - 2] : null
    }
    children(n) {
      let t = ra(n, this._root);
      return t ? t.children.map(e => e.value) : []
    }
    firstChild(n) {
      let t = ra(n, this._root);
      return t && t.children.length > 0 ? t.children[0].value : null
    }
    siblings(n) {
      let t = oa(n, this._root);
      return t.length < 2 ? [] : t[t.length - 2].children.map(r => r.value).filter(r => r !== n)
    }
    pathFromRoot(n) {
      return oa(n, this._root).map(t => t.value)
    }
  };
  Nt = class {
    value;
    children;
    constructor(n, t) {
      this.value = n, this.children = t
    }
    toString() {
      return `TreeNode(${this.value})`
    }
  };
  rn = class extends br {
    snapshot;
    constructor(n, t) {
      super(n), this.snapshot = t, ma(this, n)
    }
    toString() {
      return this.snapshot.toString()
    }
  };
  re = class {
    urlSubject;
    paramsSubject;
    queryParamsSubject;
    fragmentSubject;
    dataSubject;
    outlet;
    component;
    snapshot;
    _futureSnapshot;
    _routerState;
    _paramMap;
    _queryParamMap;
    title;
    url;
    params;
    queryParams;
    fragment;
    data;
    constructor(n, t, e, r, o, a, s, c) {
      this.urlSubject = n, this.paramsSubject = t, this.queryParamsSubject = e, this.fragmentSubject = r, this.dataSubject = o, this.outlet = a, this.component = s, this._futureSnapshot = c, this.title = this.dataSubject?.pipe(b(d => d[cn])) ?? g(void 0), this.url = n, this.params = t, this.queryParams = e, this.fragment = r, this.data = o
    }
    get routeConfig() {
      return this._futureSnapshot.routeConfig
    }
    get root() {
      return this._routerState.root
    }
    get parent() {
      return this._routerState.parent(this)
    }
    get firstChild() {
      return this._routerState.firstChild(this)
    }
    get children() {
      return this._routerState.children(this)
    }
    get pathFromRoot() {
      return this._routerState.pathFromRoot(this)
    }
    get paramMap() {
      return this._paramMap ??= this.params.pipe(b(n => je(n))), this._paramMap
    }
    get queryParamMap() {
      return this._queryParamMap ??= this.queryParams.pipe(b(n => je(n))), this._queryParamMap
    }
    toString() {
      return this.snapshot ? this.snapshot.toString() : `Future(${this._futureSnapshot})`
    }
  };
  Ve = class {
    url;
    params;
    queryParams;
    fragment;
    data;
    outlet;
    component;
    routeConfig;
    _resolve;
    _resolvedData;
    _routerState;
    _paramMap;
    _queryParamMap;
    get title() {
      return this.data?.[cn]
    }
    constructor(n, t, e, r, o, a, s, c, d) {
      this.url = n, this.params = t, this.queryParams = e, this.fragment = r, this.data = o, this.outlet = a, this.component = s, this.routeConfig = c, this._resolve = d
    }
    get root() {
      return this._routerState.root
    }
    get parent() {
      return this._routerState.parent(this)
    }
    get firstChild() {
      return this._routerState.firstChild(this)
    }
    get children() {
      return this._routerState.children(this)
    }
    get pathFromRoot() {
      return this._routerState.pathFromRoot(this)
    }
    get paramMap() {
      return this._paramMap ??= je(this.params), this._paramMap
    }
    get queryParamMap() {
      return this._queryParamMap ??= je(this.queryParams), this._queryParamMap
    }
    toString() {
      let n = this.url.map(e => e.toString()).join("/"),
        t = this.routeConfig ? this.routeConfig.path : "";
      return `Route(url:'${n}', path:'${t}')`
    }
  }, on = class extends br {
    url;
    constructor(n, t) {
      super(t), this.url = n, ma(this, t)
    }
    toString() {
      return ec(this._root)
    }
  };
  nc = new v(""), fa = (() => {
    class i {
      activated = null;
      get activatedComponentRef() {
        return this.activated
      }
      _activatedRoute = null;
      name = w;
      activateEvents = new A;
      deactivateEvents = new A;
      attachEvents = new A;
      detachEvents = new A;
      routerOutletData = ul();
      parentContexts = l(ze);
      location = l(me);
      changeDetector = l(At);
      inputBinder = l(dn, {
        optional: !0
      });
      supportsBindingToComponentInputs = !0;
      ngOnChanges(t) {
        if (t.name) {
          let {
            firstChange: e,
            previousValue: r
          } = t.name;
          if (e) return;
          this.isTrackedInParentContexts(r) && (this.deactivate(), this.parentContexts.onChildOutletDestroyed(r)), this.initializeOutletWithName()
        }
      }
      ngOnDestroy() {
        this.isTrackedInParentContexts(this.name) && this.parentContexts.onChildOutletDestroyed(this.name), this.inputBinder?.unsubscribeFromRouteData(this)
      }
      isTrackedInParentContexts(t) {
        return this.parentContexts.getContext(t)?.outlet === this
      }
      ngOnInit() {
        this.initializeOutletWithName()
      }
      initializeOutletWithName() {
        if (this.parentContexts.onChildOutletCreated(this.name, this), this.activated) return;
        let t = this.parentContexts.getContext(this.name);
        t?.route && (t.attachRef ? this.attach(t.attachRef, t.route) : this.activateWith(t.route, t.injector))
      }
      get isActivated() {
        return !!this.activated
      }
      get component() {
        if (!this.activated) throw new Q(4012, !1);
        return this.activated.instance
      }
      get activatedRoute() {
        if (!this.activated) throw new Q(4012, !1);
        return this._activatedRoute
      }
      get activatedRouteData() {
        return this._activatedRoute ? this._activatedRoute.snapshot.data : {}
      }
      detach() {
        if (!this.activated) throw new Q(4012, !1);
        this.location.detach();
        let t = this.activated;
        return this.activated = null, this._activatedRoute = null, this.detachEvents.emit(t.instance), t
      }
      attach(t, e) {
        this.activated = t, this._activatedRoute = e, this.location.insert(t.hostView), this.inputBinder?.bindActivatedRouteToOutletComponent(this), this.attachEvents.emit(t.instance)
      }
      deactivate() {
        if (this.activated) {
          let t = this.component;
          this.activated.destroy(), this.activated = null, this._activatedRoute = null, this.deactivateEvents.emit(t)
        }
      }
      activateWith(t, e) {
        if (this.isActivated) throw new Q(4013, !1);
        this._activatedRoute = t;
        let r = this.location,
          a = t.snapshot.component,
          s = this.parentContexts.getOrCreateContext(this.name).children,
          c = new sa(t, s, r.injector, this.routerOutletData);
        this.activated = r.createComponent(a, {
          index: r.length,
          injector: c,
          environmentInjector: e
        }), this.changeDetector.markForCheck(), this.inputBinder?.bindActivatedRouteToOutletComponent(this), this.activateEvents.emit(this.activated.instance)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["router-outlet"]
        ],
        inputs: {
          name: "name",
          routerOutletData: [1, "routerOutletData"]
        },
        outputs: {
          activateEvents: "activate",
          deactivateEvents: "deactivate",
          attachEvents: "attach",
          detachEvents: "detach"
        },
        exportAs: ["outlet"],
        features: [mt]
      })
    }
    return i
  })(), sa = class {
    route;
    childContexts;
    parent;
    outletData;
    constructor(n, t, e, r) {
      this.route = n, this.childContexts = t, this.parent = e, this.outletData = r
    }
    get(n, t) {
      return n === re ? this.route : n === ze ? this.childContexts : n === nc ? this.outletData : this.parent.get(n, t)
    }
  }, dn = new v(""), pa = (() => {
    class i {
      outletDataSubscriptions = new Map;
      bindActivatedRouteToOutletComponent(t) {
        this.unsubscribeFromRouteData(t), this.subscribeToRouteData(t)
      }
      unsubscribeFromRouteData(t) {
        this.outletDataSubscriptions.get(t)?.unsubscribe(), this.outletDataSubscriptions.delete(t)
      }
      subscribeToRouteData(t) {
        let {
          activatedRoute: e
        } = t, r = Ke([e.queryParams, e.params, e.data]).pipe(st(([o, a, s], c) => (s = h(h(h({}, o), a), s), c === 0 ? g(s) : Promise.resolve(s)))).subscribe(o => {
          if (!t.isActivated || !t.activatedComponentRef || t.activatedRoute !== e || e.component === null) {
            this.unsubscribeFromRouteData(t);
            return
          }
          let a = pl(e.component);
          if (!a) {
            this.unsubscribeFromRouteData(t);
            return
          }
          for (let {
              templateName: s
            }
            of a.inputs) t.activatedComponentRef.setInput(s, o[s])
        });
        this.outletDataSubscriptions.set(t, r)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })(), ga = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["ng-component"]
        ],
        exportAs: ["emptyRouterOutlet"],
        decls: 1,
        vars: 0,
        template: function(e, r) {
          e & 1 && ne(0, "router-outlet")
        },
        dependencies: [fa],
        encapsulation: 2
      })
    }
    return i
  })();
  vi = class {
    redirectTo;
    navigationBehaviorOptions;
    constructor(n, t) {
      this.redirectTo = n, this.navigationBehaviorOptions = t
    }
  }, rc = "ngNavigationCancelingError";
  Lh = (i, n, t, e) => b(r => (new la(n, r.targetRouterState, r.currentRouterState, t, e).activate(i), r)), la = class {
    routeReuseStrategy;
    futureState;
    currState;
    forwardEvent;
    inputBindingEnabled;
    constructor(n, t, e, r, o) {
      this.routeReuseStrategy = n, this.futureState = t, this.currState = e, this.forwardEvent = r, this.inputBindingEnabled = o
    }
    activate(n) {
      let t = this.futureState._root,
        e = this.currState ? this.currState._root : null;
      this.deactivateChildRoutes(t, e, n), Xo(this.futureState.root), this.activateChildRoutes(t, e, n)
    }
    deactivateChildRoutes(n, t, e) {
      let r = ci(t);
      n.children.forEach(o => {
        let a = o.value.outlet;
        this.deactivateRoutes(o, r[a], e), delete r[a]
      }), Object.values(r).forEach(o => {
        this.deactivateRouteAndItsChildren(o, e)
      })
    }
    deactivateRoutes(n, t, e) {
      let r = n.value,
        o = t ? t.value : null;
      if (r === o)
        if (r.component) {
          let a = e.getContext(r.outlet);
          a && this.deactivateChildRoutes(n, t, a.children)
        } else this.deactivateChildRoutes(n, t, e);
      else o && this.deactivateRouteAndItsChildren(t, e)
    }
    deactivateRouteAndItsChildren(n, t) {
      n.value.component && this.routeReuseStrategy.shouldDetach(n.value.snapshot) ? this.detachAndStoreRouteSubtree(n, t) : this.deactivateRouteAndOutlet(n, t)
    }
    detachAndStoreRouteSubtree(n, t) {
      let e = t.getContext(n.value.outlet),
        r = e && n.value.component ? e.children : t,
        o = ci(n);
      for (let a of Object.values(o)) this.deactivateRouteAndItsChildren(a, r);
      if (e && e.outlet) {
        let a = e.outlet.detach(),
          s = e.children.onOutletDeactivated();
        this.routeReuseStrategy.store(n.value.snapshot, {
          componentRef: a,
          route: n,
          contexts: s
        })
      }
    }
    deactivateRouteAndOutlet(n, t) {
      let e = t.getContext(n.value.outlet),
        r = e && n.value.component ? e.children : t,
        o = ci(n);
      for (let a of Object.values(o)) this.deactivateRouteAndItsChildren(a, r);
      e && (e.outlet && (e.outlet.deactivate(), e.children.onOutletDeactivated()), e.attachRef = null, e.route = null)
    }
    activateChildRoutes(n, t, e) {
      let r = ci(t);
      n.children.forEach(o => {
        this.activateRoutes(o, r[o.value.outlet], e), this.forwardEvent(new vr(o.value.snapshot))
      }), n.children.length && this.forwardEvent(new pr(n.value.snapshot))
    }
    activateRoutes(n, t, e) {
      let r = n.value,
        o = t ? t.value : null;
      if (Xo(r), r === o)
        if (r.component) {
          let a = e.getOrCreateContext(r.outlet);
          this.activateChildRoutes(n, t, a.children)
        } else this.activateChildRoutes(n, t, e);
      else if (r.component) {
        let a = e.getOrCreateContext(r.outlet);
        if (this.routeReuseStrategy.shouldAttach(r.snapshot)) {
          let s = this.routeReuseStrategy.retrieve(r.snapshot);
          this.routeReuseStrategy.store(r.snapshot, null), a.children.onOutletReAttached(s.contexts), a.attachRef = s.componentRef, a.route = s.route.value, a.outlet && a.outlet.attach(s.componentRef, s.route.value), Xo(s.route.value), this.activateChildRoutes(n, null, a.children)
        } else a.attachRef = null, a.route = r, a.outlet && a.outlet.activateWith(r, a.injector), this.activateChildRoutes(n, null, a.children)
      } else this.activateChildRoutes(n, null, e)
    }
  }, xr = class {
    path;
    route;
    constructor(n) {
      this.path = n, this.route = this.path[this.path.length - 1]
    }
  }, hi = class {
    component;
    route;
    constructor(n, t) {
      this.component = n, this.route = t
    }
  };
  ir = Symbol("INITIAL_VALUE");
  sn = class {
    segmentGroup;
    constructor(n) {
      this.segmentGroup = n || null
    }
  }, ln = class extends Error {
    urlTree;
    constructor(n) {
      super(), this.urlTree = n
    }
  };
  ca = class {
    urlSerializer;
    urlTree;
    constructor(n, t) {
      this.urlSerializer = n, this.urlTree = t
    }
    lineralizeSegments(n, t) {
      let e = [],
        r = t.root;
      for (;;) {
        if (e = e.concat(r.segments), r.numberOfChildren === 0) return g(e);
        if (r.numberOfChildren > 1 || !r.children[w]) return om(`${n.redirectTo}`);
        r = r.children[w]
      }
    }
    applyRedirectCommands(n, t, e, r, o) {
      return sm(t, r, o).pipe(b(a => {
        if (a instanceof Jt) throw new ln(a);
        let s = this.applyRedirectCreateUrlTree(a, this.urlSerializer.parse(a), n, e);
        if (a[0] === "/") throw new ln(s);
        return s
      }))
    }
    applyRedirectCreateUrlTree(n, t, e, r) {
      let o = this.createSegmentGroup(n, t.root, e, r);
      return new Jt(o, this.createQueryParams(t.queryParams, this.urlTree.queryParams), t.fragment)
    }
    createQueryParams(n, t) {
      let e = {};
      return Object.entries(n).forEach(([r, o]) => {
        if (typeof o == "string" && o[0] === ":") {
          let s = o.substring(1);
          e[r] = t[s]
        } else e[r] = o
      }), e
    }
    createSegmentGroup(n, t, e, r) {
      let o = this.createSegments(n, t.segments, e, r),
        a = {};
      return Object.entries(t.children).forEach(([s, c]) => {
        a[s] = this.createSegmentGroup(n, c, e, r)
      }), new k(o, a)
    }
    createSegments(n, t, e, r) {
      return t.map(o => o.path[0] === ":" ? this.findPosParam(n, o, r) : this.findOrReturn(o, e))
    }
    findPosParam(n, t, e) {
      let r = e[t.path.substring(1)];
      if (!r) throw new Q(4001, !1);
      return r
    }
    findOrReturn(n, t) {
      let e = 0;
      for (let r of t) {
        if (r.path === n.path) return t.splice(e), r;
        e++
      }
      return n
    }
  };
  da = {
    matched: !1,
    consumedSegments: [],
    remainingSegments: [],
    parameters: {},
    positionalParamSegments: {}
  };
  ua = class {};
  gm = 31, ha = class {
    injector;
    configLoader;
    rootComponentType;
    config;
    urlTree;
    paramsInheritanceStrategy;
    urlSerializer;
    applyRedirects;
    absoluteRedirectCount = 0;
    allowRedirects = !0;
    constructor(n, t, e, r, o, a, s) {
      this.injector = n, this.configLoader = t, this.rootComponentType = e, this.config = r, this.urlTree = o, this.paramsInheritanceStrategy = a, this.urlSerializer = s, this.applyRedirects = new ca(this.urlSerializer, this.urlTree)
    }
    noMatchError(n) {
      return new Q(4002, `'${n.segmentGroup}'`)
    }
    recognize() {
      let n = Nl(this.urlTree.root, [], [], this.config).segmentGroup;
      return this.match(n).pipe(b(({
        children: t,
        rootSnapshot: e
      }) => {
        let r = new Nt(e, t),
          o = new on("", r),
          a = Kl(e, [], this.urlTree.queryParams, this.urlTree.fragment);
        return a.queryParams = this.urlTree.queryParams, o.url = this.urlSerializer.serialize(a), {
          state: o,
          tree: a
        }
      }))
    }
    match(n) {
      let t = new Ve([], Object.freeze({}), Object.freeze(h({}, this.urlTree.queryParams)), this.urlTree.fragment, Object.freeze({}), w, this.rootComponentType, null, {});
      return this.processSegmentGroup(this.injector, this.config, n, w, t).pipe(b(e => ({
        children: e,
        rootSnapshot: t
      })), at(e => {
        if (e instanceof ln) return this.urlTree = e.urlTree, this.match(e.urlTree.root);
        throw e instanceof sn ? this.noMatchError(e) : e
      }))
    }
    processSegmentGroup(n, t, e, r, o) {
      return e.segments.length === 0 && e.hasChildren() ? this.processChildren(n, t, e, o) : this.processSegment(n, t, e, e.segments, r, !0, o).pipe(b(a => a instanceof Nt ? [a] : []))
    }
    processChildren(n, t, e, r) {
      let o = [];
      for (let a of Object.keys(e.children)) a === "primary" ? o.unshift(a) : o.push(a);
      return pt(o).pipe(ee(a => {
        let s = e.children[a],
          c = Oh(t, a);
        return this.processSegmentGroup(n, c, s, a, r)
      }), $s((a, s) => (a.push(...s), a)), Oo(null), Hs(), St(a => {
        if (a === null) return li(e);
        let s = dc(a);
        return vm(s), g(s)
      }))
    }
    processSegment(n, t, e, r, o, a, s) {
      return pt(t).pipe(ee(c => this.processSegmentAgainstRoute(c._injector ?? n, t, c, e, r, o, a, s).pipe(at(d => {
        if (d instanceof sn) return g(null);
        throw d
      }))), he(c => !!c), at(c => {
        if (sc(c)) return fm(e, r, o) ? g(new ua) : li(e);
        throw c
      }))
    }
    processSegmentAgainstRoute(n, t, e, r, o, a, s, c) {
      return $t(e) !== a && (a === w || !Er(r, o, e)) ? li(r) : e.redirectTo === void 0 ? this.matchSegmentAgainstRoute(n, r, e, o, a, c) : this.allowRedirects && s ? this.expandSegmentAgainstRouteUsingRedirect(n, r, t, e, o, a, c) : li(r)
    }
    expandSegmentAgainstRouteUsingRedirect(n, t, e, r, o, a, s) {
      let {
        matched: c,
        parameters: d,
        consumedSegments: u,
        positionalParamSegments: x,
        remainingSegments: j
      } = cc(t, r, o);
      if (!c) return li(t);
      typeof r.redirectTo == "string" && r.redirectTo[0] === "/" && (this.absoluteRedirectCount++, this.absoluteRedirectCount > gm && (this.allowRedirects = !1));
      let B = new Ve(o, d, Object.freeze(h({}, this.urlTree.queryParams)), this.urlTree.fragment, Pl(r), $t(r), r.component ?? r._loadedComponent ?? null, r, Ll(r)),
        I = yr(B, s, this.paramsInheritanceStrategy);
      return B.params = Object.freeze(I.params), B.data = Object.freeze(I.data), this.applyRedirects.applyRedirectCommands(u, r.redirectTo, x, B, n).pipe(st(bt => this.applyRedirects.lineralizeSegments(r, bt)), St(bt => this.processSegment(n, e, t, bt.concat(j), a, !1, s)))
    }
    matchSegmentAgainstRoute(n, t, e, r, o, a) {
      let s = lm(t, e, r, n, this.urlSerializer);
      return e.path === "**" && (t.children = {}), s.pipe(st(c => c.matched ? (n = e._injector ?? n, this.getChildConfig(n, e, r).pipe(st(({
        routes: d
      }) => {
        let u = e._loadedInjector ?? n,
          {
            parameters: x,
            consumedSegments: j,
            remainingSegments: B
          } = c,
          I = new Ve(j, x, Object.freeze(h({}, this.urlTree.queryParams)), this.urlTree.fragment, Pl(e), $t(e), e.component ?? e._loadedComponent ?? null, e, Ll(e)),
          V = yr(I, a, this.paramsInheritanceStrategy);
        I.params = Object.freeze(V.params), I.data = Object.freeze(V.data);
        let {
          segmentGroup: bt,
          slicedSegments: Ye
        } = Nl(t, j, B, d);
        if (Ye.length === 0 && bt.hasChildren()) return this.processChildren(u, d, bt, I).pipe(b(De => new Nt(I, De)));
        if (d.length === 0 && Ye.length === 0) return g(new Nt(I, []));
        let Vi = $t(e) === o;
        return this.processSegment(u, d, bt, Ye, Vi ? w : o, !0, I).pipe(b(De => new Nt(I, De instanceof Nt ? [De] : [])))
      }))) : li(t)))
    }
    getChildConfig(n, t, e) {
      return t.children ? g({
        routes: t.children,
        injector: n
      }) : t.loadChildren ? t._loadedRoutes !== void 0 ? g({
        routes: t._loadedRoutes,
        injector: t._loadedInjector
      }) : nm(n, t, e, this.urlSerializer).pipe(St(r => r ? this.configLoader.loadChildren(n, t).pipe(W(o => {
        t._loadedRoutes = o.routes, t._loadedInjector = o.injector
      })) : am(t))) : g({
        routes: [],
        injector: n
      })
    }
  };
  _a = (() => {
    class i {
      buildTitle(t) {
        let e, r = t.root;
        for (; r !== void 0;) e = this.getResolvedTitleForRoute(r) ?? e, r = r.children.find(o => o.outlet === w);
        return e
      }
      getResolvedTitleForRoute(t) {
        return t.data[cn]
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: () => l(hc),
        providedIn: "root"
      })
    }
    return i
  })(), hc = (() => {
    class i extends _a {
      title;
      constructor(t) {
        super(), this.title = t
      }
      updateTitle(t) {
        let e = this.buildTitle(t);
        e !== void 0 && this.title.setTitle(e)
      }
      static \u0275fac = function(e) {
        return new(e || i)(G(xl))
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), be = new v("", {
    providedIn: "root",
    factory: () => ({})
  }), Ci = new v(""), Sr = (() => {
    class i {
      componentLoaders = new WeakMap;
      childrenLoaders = new WeakMap;
      onLoadStartListener;
      onLoadEndListener;
      compiler = l(dl);
      loadComponent(t, e) {
        if (this.componentLoaders.get(e)) return this.componentLoaders.get(e);
        if (e._loadedComponent) return g(e._loadedComponent);
        this.onLoadStartListener && this.onLoadStartListener(e);
        let r = oe(Vt(t, () => e.loadComponent())).pipe(b(fc), st(pc), W(a => {
            this.onLoadEndListener && this.onLoadEndListener(e), e._loadedComponent = a
          }), Qe(() => {
            this.componentLoaders.delete(e)
          })),
          o = new ji(r, () => new y).pipe(Ao());
        return this.componentLoaders.set(e, o), o
      }
      loadChildren(t, e) {
        if (this.childrenLoaders.get(e)) return this.childrenLoaders.get(e);
        if (e._loadedRoutes) return g({
          routes: e._loadedRoutes,
          injector: e._loadedInjector
        });
        this.onLoadStartListener && this.onLoadStartListener(e);
        let o = mc(e, this.compiler, t, this.onLoadEndListener).pipe(Qe(() => {
            this.childrenLoaders.delete(e)
          })),
          a = new ji(o, () => new y).pipe(Ao());
        return this.childrenLoaders.set(e, a), a
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })();
  Dr = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: () => l(Sm),
        providedIn: "root"
      })
    }
    return i
  })(), Sm = (() => {
    class i {
      shouldProcessUrl(t) {
        return !0
      }
      extract(t) {
        return t
      }
      merge(t, e) {
        return t
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), ba = new v(""), ya = new v("");
  Ca = new v(""), Rr = (() => {
    class i {
      currentNavigation = J(null, {
        equal: () => !1
      });
      currentTransition = null;
      lastSuccessfulNavigation = null;
      events = new y;
      transitionAbortWithErrorSubject = new y;
      configLoader = l(Sr);
      environmentInjector = l(It);
      destroyRef = l(Bi);
      urlSerializer = l(Be);
      rootContexts = l(ze);
      location = l(fe);
      inputBindingEnabled = l(dn, {
        optional: !0
      }) !== null;
      titleStrategy = l(_a);
      options = l(be, {
        optional: !0
      }) || {};
      paramsInheritanceStrategy = this.options.paramsInheritanceStrategy || "emptyOnly";
      urlHandlingStrategy = l(Dr);
      createViewTransition = l(ba, {
        optional: !0
      });
      navigationErrorHandler = l(Ca, {
        optional: !0
      });
      navigationId = 0;
      get hasRequestedNavigation() {
        return this.navigationId !== 0
      }
      transitions;
      afterPreactivation = () => g(void 0);
      rootComponentType = null;
      destroyed = !1;
      constructor() {
        let t = r => this.events.next(new hr(r)),
          e = r => this.events.next(new mr(r));
        this.configLoader.onLoadEndListener = e, this.configLoader.onLoadStartListener = t, this.destroyRef.onDestroy(() => {
          this.destroyed = !0
        })
      }
      complete() {
        this.transitions?.complete()
      }
      handleNavigationRequest(t) {
        let e = ++this.navigationId;
        ut(() => {
          this.transitions?.next($(h({}, t), {
            extractedUrl: this.urlHandlingStrategy.extract(t.rawUrl),
            targetSnapshot: null,
            targetRouterState: null,
            guards: {
              canActivateChecks: [],
              canDeactivateChecks: []
            },
            guardsResult: null,
            abortController: new AbortController,
            id: e
          }))
        })
      }
      setupNavigations(t) {
        return this.transitions = new Et(null), this.transitions.pipe(K(e => e !== null), st(e => {
          let r = !1;
          return g(e).pipe(st(o => {
            if (this.navigationId > e.id) return this.cancelNavigationTransition(e, "", Ct.SupersededByNewNavigation), Ut;
            this.currentTransition = e, this.currentNavigation.set({
              id: o.id,
              initialUrl: o.rawUrl,
              extractedUrl: o.extractedUrl,
              targetBrowserUrl: typeof o.extras.browserUrl == "string" ? this.urlSerializer.parse(o.extras.browserUrl) : o.extras.browserUrl,
              trigger: o.source,
              extras: o.extras,
              previousNavigation: this.lastSuccessfulNavigation ? $(h({}, this.lastSuccessfulNavigation), {
                previousNavigation: null
              }) : null,
              abort: () => o.abortController.abort()
            });
            let a = !t.navigated || this.isUpdatingInternalState() || this.isUpdatedBrowserUrl(),
              s = o.extras.onSameUrlNavigation ?? t.onSameUrlNavigation;
            if (!a && s !== "reload") return this.events.next(new te(o.id, this.urlSerializer.serialize(o.rawUrl), "", mi.IgnoredSameUrlNavigation)), o.resolve(!1), Ut;
            if (this.urlHandlingStrategy.shouldProcessUrl(o.rawUrl)) return g(o).pipe(st(c => (this.events.next(new _e(c.id, this.urlSerializer.serialize(c.extractedUrl), c.source, c.restoredState)), c.id !== this.navigationId ? Ut : Promise.resolve(c))), bm(this.environmentInjector, this.configLoader, this.rootComponentType, t.config, this.urlSerializer, this.paramsInheritanceStrategy), W(c => {
              e.targetSnapshot = c.targetSnapshot, e.urlAfterRedirects = c.urlAfterRedirects, this.currentNavigation.update(u => (u.finalUrl = c.urlAfterRedirects, u));
              let d = new en(c.id, this.urlSerializer.serialize(c.extractedUrl), this.urlSerializer.serialize(c.urlAfterRedirects), c.targetSnapshot);
              this.events.next(d)
            }));
            if (a && this.urlHandlingStrategy.shouldProcessUrl(o.currentRawUrl)) {
              let {
                id: c,
                extractedUrl: d,
                source: u,
                restoredState: x,
                extras: j
              } = o, B = new _e(c, this.urlSerializer.serialize(d), u, x);
              this.events.next(B);
              let I = tc(this.rootComponentType).snapshot;
              return this.currentTransition = e = $(h({}, o), {
                targetSnapshot: I,
                urlAfterRedirects: d,
                extras: $(h({}, j), {
                  skipLocationChange: !1,
                  replaceUrl: !1
                })
              }), this.currentNavigation.update(V => (V.finalUrl = d, V)), g(e)
            } else return this.events.next(new te(o.id, this.urlSerializer.serialize(o.extractedUrl), "", mi.IgnoredByUrlHandlingStrategy)), o.resolve(!1), Ut
          }), W(o => {
            let a = new lr(o.id, this.urlSerializer.serialize(o.extractedUrl), this.urlSerializer.serialize(o.urlAfterRedirects), o.targetSnapshot);
            this.events.next(a)
          }), b(o => (this.currentTransition = e = $(h({}, o), {
            guards: Vh(o.targetSnapshot, o.currentSnapshot, this.rootContexts)
          }), e)), Kh(this.environmentInjector, o => this.events.next(o)), W(o => {
            if (e.guardsResult = o.guardsResult, o.guardsResult && typeof o.guardsResult != "boolean") throw Cr(this.urlSerializer, o.guardsResult);
            let a = new cr(o.id, this.urlSerializer.serialize(o.extractedUrl), this.urlSerializer.serialize(o.urlAfterRedirects), o.targetSnapshot, !!o.guardsResult);
            this.events.next(a)
          }), K(o => o.guardsResult ? !0 : (this.cancelNavigationTransition(o, "", Ct.GuardRejected), !1)), Qo(o => {
            if (o.guards.canActivateChecks.length !== 0) return g(o).pipe(W(a => {
              let s = new dr(a.id, this.urlSerializer.serialize(a.extractedUrl), this.urlSerializer.serialize(a.urlAfterRedirects), a.targetSnapshot);
              this.events.next(s)
            }), st(a => {
              let s = !1;
              return g(a).pipe(ym(this.paramsInheritanceStrategy, this.environmentInjector), W({
                next: () => s = !0,
                complete: () => {
                  s || this.cancelNavigationTransition(a, "", Ct.NoDataFromResolver)
                }
              }))
            }), W(a => {
              let s = new ur(a.id, this.urlSerializer.serialize(a.extractedUrl), this.urlSerializer.serialize(a.urlAfterRedirects), a.targetSnapshot);
              this.events.next(s)
            }))
          }), Qo(o => {
            let a = s => {
              let c = [];
              if (s.routeConfig?.loadComponent) {
                let d = bi(s) ?? this.environmentInjector;
                c.push(this.configLoader.loadComponent(d, s.routeConfig).pipe(W(u => {
                  s.component = u
                }), b(() => {})))
              }
              for (let d of s.children) c.push(...a(d));
              return c
            };
            return Ke(a(o.targetSnapshot.root)).pipe(Oo(null), yt(1))
          }), Qo(() => this.afterPreactivation()), st(() => {
            let {
              currentSnapshot: o,
              targetSnapshot: a
            } = e, s = this.createViewTransition?.(this.environmentInjector, o.root, a.root);
            return s ? pt(s).pipe(b(() => e)) : g(e)
          }), b(o => {
            let a = Th(t.routeReuseStrategy, o.targetSnapshot, o.currentRouterState);
            return this.currentTransition = e = $(h({}, o), {
              targetRouterState: a
            }), this.currentNavigation.update(s => (s.targetRouterState = a, s)), e
          }), W(() => {
            this.events.next(new nn)
          }), Lh(this.rootContexts, t.routeReuseStrategy, o => this.events.next(o), this.inputBindingEnabled), yt(1), Dt(new Yt(o => {
            let a = e.abortController.signal,
              s = () => o.next();
            return a.addEventListener("abort", s), () => a.removeEventListener("abort", s)
          }).pipe(K(() => !r && !e.targetRouterState), W(() => {
            this.cancelNavigationTransition(e, e.abortController.signal.reason + "", Ct.Aborted)
          }))), W({
            next: o => {
              r = !0, this.lastSuccessfulNavigation = ut(this.currentNavigation), this.events.next(new jt(o.id, this.urlSerializer.serialize(o.extractedUrl), this.urlSerializer.serialize(o.urlAfterRedirects))), this.titleStrategy?.updateTitle(o.targetRouterState.snapshot), o.resolve(!0)
            },
            complete: () => {
              r = !0
            }
          }), Dt(this.transitionAbortWithErrorSubject.pipe(W(o => {
            throw o
          }))), Qe(() => {
            r || this.cancelNavigationTransition(e, "", Ct.SupersededByNewNavigation), this.currentTransition?.id === e.id && (this.currentNavigation.set(null), this.currentTransition = null)
          }), at(o => {
            if (this.destroyed) return e.resolve(!1), Ut;
            if (r = !0, ac(o)) this.events.next(new Qt(e.id, this.urlSerializer.serialize(e.extractedUrl), o.message, o.cancellationCode)), Ph(o) ? this.events.next(new gi(o.url, o.navigationBehaviorOptions)) : e.resolve(!1);
            else {
              let a = new fi(e.id, this.urlSerializer.serialize(e.extractedUrl), o, e.targetSnapshot ?? void 0);
              try {
                let s = Vt(this.environmentInjector, () => this.navigationErrorHandler?.(a));
                if (s instanceof vi) {
                  let {
                    message: c,
                    cancellationCode: d
                  } = Cr(this.urlSerializer, s);
                  this.events.next(new Qt(e.id, this.urlSerializer.serialize(e.extractedUrl), c, d)), this.events.next(new gi(s.redirectTo, s.navigationBehaviorOptions))
                } else throw this.events.next(a), o
              } catch (s) {
                this.options.resolveNavigationPromiseOnError ? e.resolve(!1) : e.reject(s)
              }
            }
            return Ut
          }))
        }))
      }
      cancelNavigationTransition(t, e, r) {
        let o = new Qt(t.id, this.urlSerializer.serialize(t.extractedUrl), e, r);
        this.events.next(o), t.resolve(!1)
      }
      isUpdatingInternalState() {
        return this.currentTransition?.extractedUrl.toString() !== this.currentTransition?.currentUrlTree.toString()
      }
      isUpdatedBrowserUrl() {
        let t = this.urlHandlingStrategy.extract(this.urlSerializer.parse(this.location.path(!0))),
          e = ut(this.currentNavigation),
          r = e?.targetBrowserUrl ?? e?.extractedUrl;
        return t.toString() !== r?.toString() && !e?.extras.skipLocationChange
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })();
  vc = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: () => l(Am),
        providedIn: "root"
      })
    }
    return i
  })(), wr = class {
    shouldDetach(n) {
      return !1
    }
    store(n, t) {}
    shouldAttach(n) {
      return !1
    }
    retrieve(n) {
      return null
    }
    shouldReuseRoute(n, t) {
      return n.routeConfig === t.routeConfig
    }
  }, Am = (() => {
    class i extends wr {
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), _c = (() => {
    class i {
      urlSerializer = l(Be);
      options = l(be, {
        optional: !0
      }) || {};
      canceledNavigationResolution = this.options.canceledNavigationResolution || "replace";
      location = l(fe);
      urlHandlingStrategy = l(Dr);
      urlUpdateStrategy = this.options.urlUpdateStrategy || "deferred";
      currentUrlTree = new Jt;
      getCurrentUrlTree() {
        return this.currentUrlTree
      }
      rawUrlTree = this.currentUrlTree;
      getRawUrlTree() {
        return this.rawUrlTree
      }
      createBrowserPath({
        finalUrl: t,
        initialUrl: e,
        targetBrowserUrl: r
      }) {
        let o = t !== void 0 ? this.urlHandlingStrategy.merge(t, e) : e,
          a = r ?? o;
        return a instanceof Jt ? this.urlSerializer.serialize(a) : a
      }
      commitTransition({
        targetRouterState: t,
        finalUrl: e,
        initialUrl: r
      }) {
        e && t ? (this.currentUrlTree = e, this.rawUrlTree = this.urlHandlingStrategy.merge(e, r), this.routerState = t) : this.rawUrlTree = r
      }
      routerState = tc(null);
      getRouterState() {
        return this.routerState
      }
      stateMemento = this.createStateMemento();
      updateStateMemento() {
        this.stateMemento = this.createStateMemento()
      }
      createStateMemento() {
        return {
          rawUrlTree: this.rawUrlTree,
          currentUrlTree: this.currentUrlTree,
          routerState: this.routerState
        }
      }
      resetInternalState({
        finalUrl: t
      }) {
        this.routerState = this.stateMemento.routerState, this.currentUrlTree = this.stateMemento.currentUrlTree, this.rawUrlTree = this.urlHandlingStrategy.merge(this.currentUrlTree, t ?? this.rawUrlTree)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: () => l(Mm),
        providedIn: "root"
      })
    }
    return i
  })(), Mm = (() => {
    class i extends _c {
      currentPageId = 0;
      lastSuccessfulId = -1;
      restoredState() {
        return this.location.getState()
      }
      get browserPageId() {
        return this.canceledNavigationResolution !== "computed" ? this.currentPageId : this.restoredState()?.\u0275routerPageId ?? this.currentPageId
      }
      registerNonRouterCurrentEntryChangeListener(t) {
        return this.location.subscribe(e => {
          e.type === "popstate" && setTimeout(() => {
            t(e.url, e.state, "popstate")
          })
        })
      }
      handleRouterEvent(t, e) {
        t instanceof _e ? this.updateStateMemento() : t instanceof te ? this.commitTransition(e) : t instanceof en ? this.urlUpdateStrategy === "eager" && (e.extras.skipLocationChange || this.setBrowserUrl(this.createBrowserPath(e), e)) : t instanceof nn ? (this.commitTransition(e), this.urlUpdateStrategy === "deferred" && !e.extras.skipLocationChange && this.setBrowserUrl(this.createBrowserPath(e), e)) : t instanceof Qt && t.code !== Ct.SupersededByNewNavigation && t.code !== Ct.Redirect ? this.restoreHistory(e) : t instanceof fi ? this.restoreHistory(e, !0) : t instanceof jt && (this.lastSuccessfulId = t.id, this.currentPageId = this.browserPageId)
      }
      setBrowserUrl(t, {
        extras: e,
        id: r
      }) {
        let {
          replaceUrl: o,
          state: a
        } = e;
        if (this.location.isCurrentPathEqualTo(t) || o) {
          let s = this.browserPageId,
            c = h(h({}, a), this.generateNgRouterState(r, s));
          this.location.replaceState(t, "", c)
        } else {
          let s = h(h({}, a), this.generateNgRouterState(r, this.browserPageId + 1));
          this.location.go(t, "", s)
        }
      }
      restoreHistory(t, e = !1) {
        if (this.canceledNavigationResolution === "computed") {
          let r = this.browserPageId,
            o = this.currentPageId - r;
          o !== 0 ? this.location.historyGo(o) : this.getCurrentUrlTree() === t.finalUrl && o === 0 && (this.resetInternalState(t), this.resetUrlToCurrentUrlTree())
        } else this.canceledNavigationResolution === "replace" && (e && this.resetInternalState(t), this.resetUrlToCurrentUrlTree())
      }
      resetUrlToCurrentUrlTree() {
        this.location.replaceState(this.urlSerializer.serialize(this.getRawUrlTree()), "", this.generateNgRouterState(this.lastSuccessfulId, this.currentPageId))
      }
      generateNgRouterState(t, e) {
        return this.canceledNavigationResolution === "computed" ? {
          navigationId: t,
          \u0275routerPageId: e
        } : {
          navigationId: t
        }
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })();
  Im = {
    paths: "exact",
    fragment: "ignored",
    matrixParams: "ignored",
    queryParams: "exact"
  }, Om = {
    paths: "subset",
    fragment: "ignored",
    matrixParams: "ignored",
    queryParams: "subset"
  }, ae = (() => {
    class i {
      get currentUrlTree() {
        return this.stateManager.getCurrentUrlTree()
      }
      get rawUrlTree() {
        return this.stateManager.getRawUrlTree()
      }
      disposed = !1;
      nonRouterCurrentEntryChangeSubscription;
      console = l(ol);
      stateManager = l(_c);
      options = l(be, {
        optional: !0
      }) || {};
      pendingTasks = l(Ks);
      urlUpdateStrategy = this.options.urlUpdateStrategy || "deferred";
      navigationTransitions = l(Rr);
      urlSerializer = l(Be);
      location = l(fe);
      urlHandlingStrategy = l(Dr);
      injector = l(It);
      _events = new y;
      get events() {
        return this._events
      }
      get routerState() {
        return this.stateManager.getRouterState()
      }
      navigated = !1;
      routeReuseStrategy = l(vc);
      onSameUrlNavigation = this.options.onSameUrlNavigation || "ignore";
      config = l(Ci, {
        optional: !0
      })?.flat() ?? [];
      componentInputBindingEnabled = !!l(dn, {
        optional: !0
      });
      currentNavigation = this.navigationTransitions.currentNavigation.asReadonly();
      constructor() {
        this.resetConfig(this.config), this.navigationTransitions.setupNavigations(this).subscribe({
          error: t => {
            this.console.warn(t)
          }
        }), this.subscribeToNavigationEvents()
      }
      eventsSubscription = new ft;
      subscribeToNavigationEvents() {
        let t = this.navigationTransitions.events.subscribe(e => {
          try {
            let r = this.navigationTransitions.currentTransition,
              o = ut(this.navigationTransitions.currentNavigation);
            if (r !== null && o !== null) {
              if (this.stateManager.handleRouterEvent(e, o), e instanceof Qt && e.code !== Ct.Redirect && e.code !== Ct.SupersededByNewNavigation) this.navigated = !0;
              else if (e instanceof jt) this.navigated = !0;
              else if (e instanceof gi) {
                let a = e.navigationBehaviorOptions,
                  s = this.urlHandlingStrategy.merge(e.url, r.currentRawUrl),
                  c = h({
                    browserUrl: r.extras.browserUrl,
                    info: r.extras.info,
                    skipLocationChange: r.extras.skipLocationChange,
                    replaceUrl: r.extras.replaceUrl || this.urlUpdateStrategy === "eager" || Rm(r.source)
                  }, a);
                this.scheduleNavigation(s, ui, null, c, {
                  resolve: r.resolve,
                  reject: r.reject,
                  promise: r.promise
                })
              }
            }
            Mh(e) && this._events.next(e)
          } catch (r) {
            this.navigationTransitions.transitionAbortWithErrorSubject.next(r)
          }
        });
        this.eventsSubscription.add(t)
      }
      resetRootComponentType(t) {
        this.routerState.root.component = t, this.navigationTransitions.rootComponentType = t
      }
      initialNavigation() {
        this.setUpLocationChangeListener(), this.navigationTransitions.hasRequestedNavigation || this.navigateToSyncWithBrowser(this.location.path(!0), ui, this.stateManager.restoredState())
      }
      setUpLocationChangeListener() {
        this.nonRouterCurrentEntryChangeSubscription ??= this.stateManager.registerNonRouterCurrentEntryChangeListener((t, e, r) => {
          this.navigateToSyncWithBrowser(t, r, e)
        })
      }
      navigateToSyncWithBrowser(t, e, r) {
        let o = {
            replaceUrl: !0
          },
          a = r?.navigationId ? r : null;
        if (r) {
          let c = h({}, r);
          delete c.navigationId, delete c.\u0275routerPageId, Object.keys(c).length !== 0 && (o.state = c)
        }
        let s = this.parseUrl(t);
        this.scheduleNavigation(s, e, a, o).catch(c => {
          this.disposed || this.injector.get($n)(c)
        })
      }
      get url() {
        return this.serializeUrl(this.currentUrlTree)
      }
      getCurrentNavigation() {
        return ut(this.navigationTransitions.currentNavigation)
      }
      get lastSuccessfulNavigation() {
        return this.navigationTransitions.lastSuccessfulNavigation
      }
      resetConfig(t) {
        this.config = t.map(va), this.navigated = !1
      }
      ngOnDestroy() {
        this.dispose()
      }
      dispose() {
        this._events.unsubscribe(), this.navigationTransitions.complete(), this.nonRouterCurrentEntryChangeSubscription && (this.nonRouterCurrentEntryChangeSubscription.unsubscribe(), this.nonRouterCurrentEntryChangeSubscription = void 0), this.disposed = !0, this.eventsSubscription.unsubscribe()
      }
      createUrlTree(t, e = {}) {
        let {
          relativeTo: r,
          queryParams: o,
          fragment: a,
          queryParamsHandling: s,
          preserveFragment: c
        } = e, d = c ? this.currentUrlTree.fragment : a, u = null;
        switch (s ?? this.options.defaultQueryParamsHandling) {
          case "merge":
            u = h(h({}, this.currentUrlTree.queryParams), o);
            break;
          case "preserve":
            u = this.currentUrlTree.queryParams;
            break;
          default:
            u = o || null
        }
        u !== null && (u = this.removeEmptyProps(u));
        let x;
        try {
          let j = r ? r.snapshot : this.routerState.snapshot.root;
          x = Zl(j)
        } catch {
          (typeof t[0] != "string" || t[0][0] !== "/") && (t = []), x = this.currentUrlTree.root
        }
        return Xl(x, t, u, d ?? null)
      }
      navigateByUrl(t, e = {
        skipLocationChange: !1
      }) {
        let r = ve(t) ? t : this.parseUrl(t),
          o = this.urlHandlingStrategy.merge(r, this.rawUrlTree);
        return this.scheduleNavigation(o, ui, null, e)
      }
      navigate(t, e = {
        skipLocationChange: !1
      }) {
        return km(t), this.navigateByUrl(this.createUrlTree(t, e), e)
      }
      serializeUrl(t) {
        return this.urlSerializer.serialize(t)
      }
      parseUrl(t) {
        try {
          return this.urlSerializer.parse(t)
        } catch {
          return this.console.warn(qs(4018, !1)), this.urlSerializer.parse("/")
        }
      }
      isActive(t, e) {
        let r;
        if (e === !0 ? r = h({}, Im) : e === !1 ? r = h({}, Om) : r = e, ve(t)) return Ol(this.currentUrlTree, t, r);
        let o = this.parseUrl(t);
        return Ol(this.currentUrlTree, o, r)
      }
      removeEmptyProps(t) {
        return Object.entries(t).reduce((e, [r, o]) => (o != null && (e[r] = o), e), {})
      }
      scheduleNavigation(t, e, r, o, a) {
        if (this.disposed) return Promise.resolve(!1);
        let s, c, d;
        a ? (s = a.resolve, c = a.reject, d = a.promise) : d = new Promise((x, j) => {
          s = x, c = j
        });
        let u = this.pendingTasks.add();
        return Ar(this, () => {
          queueMicrotask(() => this.pendingTasks.remove(u))
        }), this.navigationTransitions.handleNavigationRequest({
          source: e,
          restoredState: r,
          currentUrlTree: this.currentUrlTree,
          currentRawUrl: this.currentUrlTree,
          rawUrl: t,
          extras: o,
          resolve: s,
          reject: c,
          promise: d,
          currentSnapshot: this.routerState.snapshot,
          currentRouterState: this.routerState
        }), d.catch(x => Promise.reject(x))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});

function Fm(i) {
  return i.routerState.root
}

function mn(i, n) {
  return {
    \u0275kind: i,
    \u0275providers: n
  }
}

function Nm() {
  let i = l(N);
  return n => {
    let t = i.get(ie);
    if (n !== t.components[0]) return;
    let e = i.get(ae),
      r = i.get(xc);
    i.get(Ea) === 1 && e.initialNavigation(), i.get(Sc, null, {
      optional: !0
    })?.setUpPreloading(), i.get(Cc, null, {
      optional: !0
    })?.init(), e.resetRootComponentType(t.componentTypes[0]), r.closed || (r.next(), r.complete(), r.unsubscribe())
  }
}

function wc() {
  let i = [{
    provide: Js,
    useValue: !0
  }, {
    provide: Ea,
    useValue: 0
  }, Lo(() => {
    let n = l(N);
    return n.get(gl, Promise.resolve()).then(() => new Promise(e => {
      let r = n.get(ae),
        o = n.get(xc);
      Ar(r, () => {
        e(!0)
      }), n.get(Rr).afterPreactivation = () => (e(!0), o.closed ? g(void 0) : o), r.initialNavigation()
    }))
  })];
  return mn(2, i)
}

function Ec() {
  let i = [Lo(() => {
    l(ae).setUpLocationChangeListener()
  }), {
    provide: Ea,
    useValue: 2
  }];
  return mn(3, i)
}

function Dc(i) {
  return mn(0, [{
    provide: Sc,
    useExisting: yc
  }, {
    provide: hn,
    useExisting: i
  }])
}

function Rc() {
  return mn(8, [pa, {
    provide: dn,
    useExisting: pa
  }])
}

function Ac(i) {
  el("NgRouterViewTransitions");
  let n = [{
    provide: ba,
    useValue: gc
  }, {
    provide: ya,
    useValue: h({
      skipNextTransition: !!i?.skipInitialTransition
    }, i)
  }];
  return mn(9, n)
}

function Lm() {
  return {
    provide: Cc,
    useFactory: () => {
      let i = l(Cl),
        n = l(E),
        t = l(be),
        e = l(Rr),
        r = l(Be);
      return t.scrollOffset && i.setOffset(t.scrollOffset), new Tm(r, e, i, n, t)
    }
  }
}

function Vm() {
  return {
    provide: qi,
    useClass: _l
  }
}

function jm() {
  return {
    provide: qi,
    useClass: vl
  }
}

function Bm(i) {
  return [i.initialNavigation === "disabled" ? Ec().\u0275providers : [], i.initialNavigation === "enabledBlocking" ? wc().\u0275providers : []]
}

function zm() {
  return [{
    provide: wa,
    useFactory: Nm
  }, {
    provide: al,
    multi: !0,
    useExisting: wa
  }]
}
var bc, hn, yc, Cc, Tm, xc, Ea, Sc, Mc, Pm, wa, Ic = _(() => {
  Pe();
  Pe();
  f();
  f();
  xa();
  nt();
  ht();
  bc = (() => {
    class i {
      router;
      route;
      tabIndexAttribute;
      renderer;
      el;
      locationStrategy;
      reactiveHref = J(null);
      get href() {
        return ut(this.reactiveHref)
      }
      set href(t) {
        this.reactiveHref.set(t)
      }
      target;
      queryParams;
      fragment;
      queryParamsHandling;
      state;
      info;
      relativeTo;
      isAnchorElement;
      subscription;
      onChanges = new y;
      applicationErrorHandler = l($n);
      options = l(be, {
        optional: !0
      });
      constructor(t, e, r, o, a, s) {
        this.router = t, this.route = e, this.tabIndexAttribute = r, this.renderer = o, this.el = a, this.locationStrategy = s, this.reactiveHref.set(l(new Xn("href"), {
          optional: !0
        }));
        let c = a.nativeElement.tagName?.toLowerCase();
        this.isAnchorElement = c === "a" || c === "area" || !!(typeof customElements == "object" && customElements.get(c)?.observedAttributes?.includes?.("href")), this.isAnchorElement ? this.setTabIndexIfNotOnNativeEl("0") : this.subscribeToNavigationEventsIfNecessary()
      }
      subscribeToNavigationEventsIfNecessary() {
        if (this.subscription !== void 0 || !this.isAnchorElement) return;
        let t = this.preserveFragment,
          e = r => r === "merge" || r === "preserve";
        t ||= e(this.queryParamsHandling), t ||= !this.queryParamsHandling && !e(this.options?.defaultQueryParamsHandling), t && (this.subscription = this.router.events.subscribe(r => {
          r instanceof jt && this.updateHref()
        }))
      }
      preserveFragment = !1;
      skipLocationChange = !1;
      replaceUrl = !1;
      setTabIndexIfNotOnNativeEl(t) {
        this.tabIndexAttribute != null || this.isAnchorElement || this.applyAttributeValue("tabindex", t)
      }
      ngOnChanges(t) {
        this.isAnchorElement && (this.updateHref(), this.subscribeToNavigationEventsIfNecessary()), this.onChanges.next(this)
      }
      routerLinkInput = null;
      set routerLink(t) {
        t == null ? (this.routerLinkInput = null, this.setTabIndexIfNotOnNativeEl(null)) : (ve(t) ? this.routerLinkInput = t : this.routerLinkInput = Array.isArray(t) ? t : [t], this.setTabIndexIfNotOnNativeEl("0"))
      }
      onClick(t, e, r, o, a) {
        let s = this.urlTree;
        if (s === null || this.isAnchorElement && (t !== 0 || e || r || o || a || typeof this.target == "string" && this.target != "_self")) return !0;
        let c = {
          skipLocationChange: this.skipLocationChange,
          replaceUrl: this.replaceUrl,
          state: this.state,
          info: this.info
        };
        return this.router.navigateByUrl(s, c)?.catch(d => {
          this.applicationErrorHandler(d)
        }), !this.isAnchorElement
      }
      ngOnDestroy() {
        this.subscription?.unsubscribe()
      }
      updateHref() {
        let t = this.urlTree;
        this.reactiveHref.set(t !== null && this.locationStrategy ? this.locationStrategy?.prepareExternalUrl(this.router.serializeUrl(t)) ?? "" : null)
      }
      applyAttributeValue(t, e) {
        let r = this.renderer,
          o = this.el.nativeElement;
        e !== null ? r.setAttribute(o, t, e) : r.removeAttribute(o, t)
      }
      get urlTree() {
        return this.routerLinkInput === null ? null : ve(this.routerLinkInput) ? this.routerLinkInput : this.router.createUrlTree(this.routerLinkInput, {
          relativeTo: this.relativeTo !== void 0 ? this.relativeTo : this.route,
          queryParams: this.queryParams,
          fragment: this.fragment,
          queryParamsHandling: this.queryParamsHandling,
          preserveFragment: this.preserveFragment
        })
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(ae), C(re), Zs("tabindex"), C(lt), C(D), C(qi))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "routerLink", ""]
        ],
        hostVars: 2,
        hostBindings: function(e, r) {
          e & 1 && dt("click", function(a) {
            return r.onClick(a.button, a.ctrlKey, a.shiftKey, a.altKey, a.metaKey)
          }), e & 2 && tt("href", r.reactiveHref(), tl)("target", r.target)
        },
        inputs: {
          target: "target",
          queryParams: "queryParams",
          fragment: "fragment",
          queryParamsHandling: "queryParamsHandling",
          state: "state",
          info: "info",
          relativeTo: "relativeTo",
          preserveFragment: [2, "preserveFragment", "preserveFragment", F],
          skipLocationChange: [2, "skipLocationChange", "skipLocationChange", F],
          replaceUrl: [2, "replaceUrl", "replaceUrl", F],
          routerLink: "routerLink"
        },
        features: [mt]
      })
    }
    return i
  })(), hn = class {}, yc = (() => {
    class i {
      router;
      injector;
      preloadingStrategy;
      loader;
      subscription;
      constructor(t, e, r, o) {
        this.router = t, this.injector = e, this.preloadingStrategy = r, this.loader = o
      }
      setUpPreloading() {
        this.subscription = this.router.events.pipe(K(t => t instanceof jt), ee(() => this.preload())).subscribe(() => {})
      }
      preload() {
        return this.processRoutes(this.injector, this.router.config)
      }
      ngOnDestroy() {
        this.subscription && this.subscription.unsubscribe()
      }
      processRoutes(t, e) {
        let r = [];
        for (let o of e) {
          o.providers && !o._injector && (o._injector = qn(o.providers, t, `Route: ${o.path}`));
          let a = o._injector ?? t,
            s = o._loadedInjector ?? a;
          (o.loadChildren && !o._loadedRoutes && o.canLoad === void 0 || o.loadComponent && !o._loadedComponent) && r.push(this.preloadConfig(a, o)), (o.children || o._loadedRoutes) && r.push(this.processRoutes(s, o.children ?? o._loadedRoutes))
        }
        return pt(r).pipe(Mo())
      }
      preloadConfig(t, e) {
        return this.preloadingStrategy.preload(e, () => {
          let r;
          e.loadChildren && e.canLoad === void 0 ? r = this.loader.loadChildren(t, e) : r = g(null);
          let o = r.pipe(St(a => a === null ? g(void 0) : (e._loadedRoutes = a.routes, e._loadedInjector = a.injector, this.processRoutes(a.injector ?? t, a.routes))));
          if (e.loadComponent && !e._loadedComponent) {
            let a = this.loader.loadComponent(t, e);
            return pt([o, a]).pipe(Mo())
          } else return o
        })
      }
      static \u0275fac = function(e) {
        return new(e || i)(G(ae), G(It), G(hn), G(Sr))
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Cc = new v(""), Tm = (() => {
    class i {
      urlSerializer;
      transitions;
      viewportScroller;
      zone;
      options;
      routerEventsSubscription;
      scrollEventsSubscription;
      lastId = 0;
      lastSource = ui;
      restoredId = 0;
      store = {};
      constructor(t, e, r, o, a = {}) {
        this.urlSerializer = t, this.transitions = e, this.viewportScroller = r, this.zone = o, this.options = a, a.scrollPositionRestoration ||= "disabled", a.anchorScrolling ||= "disabled"
      }
      init() {
        this.options.scrollPositionRestoration !== "disabled" && this.viewportScroller.setHistoryScrollRestoration("manual"), this.routerEventsSubscription = this.createScrollEvents(), this.scrollEventsSubscription = this.consumeScrollEvents()
      }
      createScrollEvents() {
        return this.transitions.events.subscribe(t => {
          t instanceof _e ? (this.store[this.lastId] = this.viewportScroller.getScrollPosition(), this.lastSource = t.navigationTrigger, this.restoredId = t.restoredState ? t.restoredState.navigationId : 0) : t instanceof jt ? (this.lastId = t.id, this.scheduleScrollEvent(t, this.urlSerializer.parse(t.urlAfterRedirects).fragment)) : t instanceof te && t.code === mi.IgnoredSameUrlNavigation && (this.lastSource = void 0, this.restoredId = 0, this.scheduleScrollEvent(t, this.urlSerializer.parse(t.url).fragment))
        })
      }
      consumeScrollEvents() {
        return this.transitions.events.subscribe(t => {
          if (!(t instanceof pi)) return;
          let e = {
            behavior: "instant"
          };
          t.position ? this.options.scrollPositionRestoration === "top" ? this.viewportScroller.scrollToPosition([0, 0], e) : this.options.scrollPositionRestoration === "enabled" && this.viewportScroller.scrollToPosition(t.position, e) : t.anchor && this.options.anchorScrolling === "enabled" ? this.viewportScroller.scrollToAnchor(t.anchor) : this.options.scrollPositionRestoration !== "disabled" && this.viewportScroller.scrollToPosition([0, 0])
        })
      }
      scheduleScrollEvent(t, e) {
        this.zone.runOutsideAngular(() => js(this, null, function*() {
          yield new Promise(r => {
            setTimeout(r), typeof requestAnimationFrame < "u" && requestAnimationFrame(r)
          }), this.zone.run(() => {
            this.transitions.events.next(new pi(t, this.lastSource === "popstate" ? this.store[this.restoredId] : null, e))
          })
        }))
      }
      ngOnDestroy() {
        this.routerEventsSubscription?.unsubscribe(), this.scrollEventsSubscription?.unsubscribe()
      }
      static \u0275fac = function(e) {
        il()
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac
      })
    }
    return i
  })();
  xc = new v("", {
    factory: () => new y
  }), Ea = new v("", {
    providedIn: "root",
    factory: () => 1
  });
  Sc = new v("");
  Mc = [fe, {
    provide: Be,
    useClass: ge
  }, ae, ze, {
    provide: re,
    useFactory: Fm,
    deps: [ae]
  }, Sr, []], Pm = (() => {
    class i {
      constructor() {}
      static forRoot(t, e) {
        return {
          ngModule: i,
          providers: [Mc, [], {
              provide: Ci,
              multi: !0,
              useValue: t
            },
            [], e?.errorHandler ? {
              provide: Ca,
              useValue: e.errorHandler
            } : [], {
              provide: be,
              useValue: e || {}
            },
            e?.useHash ? Vm() : jm(), Lm(), e?.preloadingStrategy ? Dc(e.preloadingStrategy).\u0275providers : [], e?.initialNavigation ? Bm(e) : [], e?.bindToComponentInputs ? Rc().\u0275providers : [], e?.enableViewTransitions ? Ac().\u0275providers : [], zm()
          ]
        }
      }
      static forChild(t) {
        return {
          ngModule: i,
          providers: [{
            provide: Ci,
            multi: !0,
            useValue: t
          }]
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })();
  wa = new v("")
});
var Um = _(() => {
  xa();
  Ic();
});
var r_, Hm = _(() => {
  Ho();
  f();
  Uo();
  ht();
  f();
  r_ = (() => {
    class i {
      http = l(ni);
      hostServer = Jn.hostServer;
      host = this.hostServer + "/rest/admin";
      configObservable;
      getApplicationConfiguration() {
        return this.configObservable ? this.configObservable : (this.configObservable = this.http.get(this.host + "/application-configuration").pipe(b(t => t.config, at(t => {
          throw t
        }))), this.configObservable)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});
var Sa, T, se = _(() => {
  f();
  f();
  Pe();
  try {
    Sa = typeof Intl < "u" && Intl.v8BreakIterator
  } catch {
    Sa = !1
  }
  T = (() => {
    class i {
      _platformId = l(Xs);
      isBrowser = this._platformId ? yl(this._platformId) : typeof document == "object" && !!document;
      EDGE = this.isBrowser && /(edge)/i.test(navigator.userAgent);
      TRIDENT = this.isBrowser && /(msie|trident)/i.test(navigator.userAgent);
      BLINK = this.isBrowser && !!(window.chrome || Sa) && typeof CSS < "u" && !this.EDGE && !this.TRIDENT;
      WEBKIT = this.isBrowser && /AppleWebKit/i.test(navigator.userAgent) && !this.BLINK && !this.EDGE && !this.TRIDENT;
      IOS = this.isBrowser && /iPad|iPhone|iPod/.test(navigator.userAgent) && !("MSStream" in window);
      FIREFOX = this.isBrowser && /(firefox|minefield)/i.test(navigator.userAgent);
      ANDROID = this.isBrowser && /android/i.test(navigator.userAgent) && !this.TRIDENT;
      SAFARI = this.isBrowser && /safari/i.test(navigator.userAgent) && this.WEBKIT;
      constructor() {}
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});

function Oc() {
  if (Da == null) {
    let i = typeof document < "u" ? document.head : null;
    Da = !!(i && (i.createShadowRoot || i.attachShadow))
  }
  return Da
}

function Ra(i) {
  if (Oc()) {
    let n = i.getRootNode ? i.getRootNode() : null;
    if (typeof ShadowRoot < "u" && ShadowRoot && n instanceof ShadowRoot) return n
  }
  return null
}

function Aa() {
  let i = typeof document < "u" && document ? document.activeElement : null;
  for (; i && i.shadowRoot;) {
    let n = i.shadowRoot.activeElement;
    if (n === i) break;
    i = n
  }
  return i
}

function xt(i) {
  return i.composedPath ? i.composedPath()[0] : i.target
}
var Da, fn = _(() => {});

function Ma() {
  return typeof __karma__ < "u" && !!__karma__ || typeof jasmine < "u" && !!jasmine || typeof jest < "u" && !!jest || typeof Mocha < "u" && !!Mocha
}
var kc = _(() => {});
var Mr, Mt, xi = _(() => {
  f();
  f();
  Mr = new WeakMap, Mt = (() => {
    class i {
      _appRef;
      _injector = l(N);
      _environmentInjector = l(It);
      load(t) {
        let e = this._appRef = this._appRef || this._injector.get(ie),
          r = Mr.get(e);
        r || (r = {
          loaders: new Set,
          refs: []
        }, Mr.set(e, r), e.onDestroy(() => {
          Mr.get(e)?.refs.forEach(o => o.destroy()), Mr.delete(e)
        })), r.loaders.has(t) || (r.loaders.add(t), r.refs.push(Qn(t, {
          environmentInjector: this._environmentInjector
        })))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});

function Y(i) {
  return i == null ? "" : typeof i == "string" ? i : `${i}px`
}
var Ia = _(() => {});

function wi(i) {
  return Array.isArray(i) ? i : [i]
}
var Oa = _(() => {});

function pn(i, n = 0) {
  return Tc(i) ? Number(i) : arguments.length === 2 ? n : 0
}

function Tc(i) {
  return !isNaN(parseFloat(i)) && !isNaN(Number(i))
}

function wt(i) {
  return i instanceof D ? i.nativeElement : i
}
var Ei = _(() => {
  f()
});

function Wm() {
  return l(O)
}

function ka(i) {
  let n = i?.toLowerCase() || "";
  return n === "auto" && typeof navigator < "u" && navigator?.language ? Gm.test(navigator.language) ? "rtl" : "ltr" : n === "rtl" ? "rtl" : "ltr"
}
var $m, Gm, le, Ir = _(() => {
  f();
  f();
  $m = new v("cdk-dir-doc", {
    providedIn: "root",
    factory: Wm
  });
  Gm = /^(ar|ckb|dv|he|iw|fa|nqo|ps|sd|ug|ur|yi|.*[-_](Adlm|Arab|Hebr|Nkoo|Rohg|Thaa))(?!.*[-_](Latn|Cyrl)($|-|_))($|-|_)/i;
  le = (() => {
    class i {
      get value() {
        return this.valueSignal()
      }
      valueSignal = J("ltr");
      change = new A;
      constructor() {
        let t = l($m, {
          optional: !0
        });
        if (t) {
          let e = t.body ? t.body.dir : null,
            r = t.documentElement ? t.documentElement.dir : null;
          this.valueSignal.set(ka(e || r || "ltr"))
        }
      }
      ngOnDestroy() {
        this.change.complete()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});

function gn() {
  if (Ue == null) {
    if (typeof document != "object" || !document || typeof Element != "function" || !Element) return Ue = !1, Ue;
    if (document.documentElement?.style && "scrollBehavior" in document.documentElement.style) Ue = !0;
    else {
      let i = Element.prototype.scrollTo;
      i ? Ue = !/\{\s*\[native code\]\s*\}/.test(i.toString()) : Ue = !1
    }
  }
  return Ue
}

function He() {
  if (typeof document != "object" || !document) return Bt.NORMAL;
  if (Or == null) {
    let i = document.createElement("div"),
      n = i.style;
    i.dir = "rtl", n.width = "1px", n.overflow = "auto", n.visibility = "hidden", n.pointerEvents = "none", n.position = "absolute";
    let t = document.createElement("div"),
      e = t.style;
    e.width = "2px", e.height = "1px", i.appendChild(t), document.body.appendChild(i), Or = Bt.NORMAL, i.scrollLeft === 0 && (i.scrollLeft = 1, Or = i.scrollLeft === 0 ? Bt.NEGATED : Bt.INVERTED), i.remove()
  }
  return Or
}
var Bt, Or, Ue, kr = _(() => {
  Bt = (function(i) {
    return i[i.NORMAL = 0] = "NORMAL", i[i.NEGATED = 1] = "NEGATED", i[i.INVERTED = 2] = "INVERTED", i
  })(Bt || {})
});
var M_, ye, vn = _(() => {
  Ir();
  f();
  f();
  M_ = (() => {
    class i {
      _isInitialized = !1;
      _rawDir;
      change = new A;
      get dir() {
        return this.valueSignal()
      }
      set dir(t) {
        let e = this.valueSignal();
        this.valueSignal.set(ka(t)), this._rawDir = t, e !== this.valueSignal() && this._isInitialized && this.change.emit(this.valueSignal())
      }
      get value() {
        return this.dir
      }
      valueSignal = J("ltr");
      ngAfterContentInit() {
        this._isInitialized = !0
      }
      ngOnDestroy() {
        this.change.complete()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "dir", ""]
        ],
        hostVars: 1,
        hostBindings: function(e, r) {
          e & 2 && tt("dir", r._rawDir)
        },
        inputs: {
          dir: "dir"
        },
        outputs: {
          change: "dirChange"
        },
        exportAs: ["dir"],
        features: [z([{
          provide: le,
          useExisting: i
        }])]
      })
    }
    return i
  })(), ye = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })()
});

function k_(i) {
  return i && typeof i.connect == "function" && !(i instanceof ji)
}
var Fc, qm = _(() => {
  nt();
  Fc = class {}
});
var Ym, N_, Km = _(() => {
  f();
  Ym = (function(i) {
    return i[i.REPLACED = 0] = "REPLACED", i[i.INSERTED = 1] = "INSERTED", i[i.MOVED = 2] = "MOVED", i[i.REMOVED = 3] = "REMOVED", i
  })(Ym || {}), N_ = new v("_ViewRepeater")
});
var Xm, _n, Qm, Jm, Si, Ta, Fa, Na = _(() => {
  f();
  f();
  nt();
  ht();
  Ei();
  se();
  Ir();
  kr();
  vn();
  Xm = 20, _n = (() => {
    class i {
      _ngZone = l(E);
      _platform = l(T);
      _renderer = l(kt).createRenderer(null, null);
      _cleanupGlobalListener;
      constructor() {}
      _scrolled = new y;
      _scrolledCount = 0;
      scrollContainers = new Map;
      register(t) {
        this.scrollContainers.has(t) || this.scrollContainers.set(t, t.elementScrolled().subscribe(() => this._scrolled.next(t)))
      }
      deregister(t) {
        let e = this.scrollContainers.get(t);
        e && (e.unsubscribe(), this.scrollContainers.delete(t))
      }
      scrolled(t = Xm) {
        return this._platform.isBrowser ? new Yt(e => {
          this._cleanupGlobalListener || (this._cleanupGlobalListener = this._ngZone.runOutsideAngular(() => this._renderer.listen("document", "scroll", () => this._scrolled.next())));
          let r = t > 0 ? this._scrolled.pipe(Io(t)).subscribe(e) : this._scrolled.subscribe(e);
          return this._scrolledCount++, () => {
            r.unsubscribe(), this._scrolledCount--, this._scrolledCount || (this._cleanupGlobalListener?.(), this._cleanupGlobalListener = void 0)
          }
        }) : g()
      }
      ngOnDestroy() {
        this._cleanupGlobalListener?.(), this._cleanupGlobalListener = void 0, this.scrollContainers.forEach((t, e) => this.deregister(e)), this._scrolled.complete()
      }
      ancestorScrolled(t, e) {
        let r = this.getAncestorScrollContainers(t);
        return this.scrolled(e).pipe(K(o => !o || r.indexOf(o) > -1))
      }
      getAncestorScrollContainers(t) {
        let e = [];
        return this.scrollContainers.forEach((r, o) => {
          this._scrollableContainsElement(o, t) && e.push(o)
        }), e
      }
      _scrollableContainsElement(t, e) {
        let r = wt(e),
          o = t.getElementRef().nativeElement;
        do
          if (r == o) return !0; while (r = r.parentElement);
        return !1
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Qm = (() => {
    class i {
      elementRef = l(D);
      scrollDispatcher = l(_n);
      ngZone = l(E);
      dir = l(le, {
        optional: !0
      });
      _scrollElement = this.elementRef.nativeElement;
      _destroyed = new y;
      _renderer = l(lt);
      _cleanupScroll;
      _elementScrolled = new y;
      constructor() {}
      ngOnInit() {
        this._cleanupScroll = this.ngZone.runOutsideAngular(() => this._renderer.listen(this._scrollElement, "scroll", t => this._elementScrolled.next(t))), this.scrollDispatcher.register(this)
      }
      ngOnDestroy() {
        this._cleanupScroll?.(), this._elementScrolled.complete(), this.scrollDispatcher.deregister(this), this._destroyed.next(), this._destroyed.complete()
      }
      elementScrolled() {
        return this._elementScrolled
      }
      getElementRef() {
        return this.elementRef
      }
      scrollTo(t) {
        let e = this.elementRef.nativeElement,
          r = this.dir && this.dir.value == "rtl";
        t.left == null && (t.left = r ? t.end : t.start), t.right == null && (t.right = r ? t.start : t.end), t.bottom != null && (t.top = e.scrollHeight - e.clientHeight - t.bottom), r && He() != Bt.NORMAL ? (t.left != null && (t.right = e.scrollWidth - e.clientWidth - t.left), He() == Bt.INVERTED ? t.left = t.right : He() == Bt.NEGATED && (t.left = t.right ? -t.right : t.right)) : t.right != null && (t.left = e.scrollWidth - e.clientWidth - t.right), this._applyScrollToOptions(t)
      }
      _applyScrollToOptions(t) {
        let e = this.elementRef.nativeElement;
        gn() ? e.scrollTo(t) : (t.top != null && (e.scrollTop = t.top), t.left != null && (e.scrollLeft = t.left))
      }
      measureScrollOffset(t) {
        let e = "left",
          r = "right",
          o = this.elementRef.nativeElement;
        if (t == "top") return o.scrollTop;
        if (t == "bottom") return o.scrollHeight - o.clientHeight - o.scrollTop;
        let a = this.dir && this.dir.value == "rtl";
        return t == "start" ? t = a ? r : e : t == "end" && (t = a ? e : r), a && He() == Bt.INVERTED ? t == e ? o.scrollWidth - o.clientWidth - o.scrollLeft : o.scrollLeft : a && He() == Bt.NEGATED ? t == e ? o.scrollLeft + o.scrollWidth - o.clientWidth : -o.scrollLeft : t == e ? o.scrollLeft : o.scrollWidth - o.clientWidth - o.scrollLeft
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdk-scrollable", ""],
          ["", "cdkScrollable", ""]
        ]
      })
    }
    return i
  })(), Jm = 20, Si = (() => {
    class i {
      _platform = l(T);
      _listeners;
      _viewportSize;
      _change = new y;
      _document = l(O);
      constructor() {
        let t = l(E),
          e = l(kt).createRenderer(null, null);
        t.runOutsideAngular(() => {
          if (this._platform.isBrowser) {
            let r = o => this._change.next(o);
            this._listeners = [e.listen("window", "resize", r), e.listen("window", "orientationchange", r)]
          }
          this.change().subscribe(() => this._viewportSize = null)
        })
      }
      ngOnDestroy() {
        this._listeners?.forEach(t => t()), this._change.complete()
      }
      getViewportSize() {
        this._viewportSize || this._updateViewportSize();
        let t = {
          width: this._viewportSize.width,
          height: this._viewportSize.height
        };
        return this._platform.isBrowser || (this._viewportSize = null), t
      }
      getViewportRect() {
        let t = this.getViewportScrollPosition(),
          {
            width: e,
            height: r
          } = this.getViewportSize();
        return {
          top: t.top,
          left: t.left,
          bottom: t.top + r,
          right: t.left + e,
          height: r,
          width: e
        }
      }
      getViewportScrollPosition() {
        if (!this._platform.isBrowser) return {
          top: 0,
          left: 0
        };
        let t = this._document,
          e = this._getWindow(),
          r = t.documentElement,
          o = r.getBoundingClientRect(),
          a = -o.top || t.body.scrollTop || e.scrollY || r.scrollTop || 0,
          s = -o.left || t.body.scrollLeft || e.scrollX || r.scrollLeft || 0;
        return {
          top: a,
          left: s
        }
      }
      change(t = Jm) {
        return t > 0 ? this._change.pipe(Io(t)) : this._change
      }
      _getWindow() {
        return this._document.defaultView || window
      }
      _updateViewportSize() {
        let t = this._getWindow();
        this._viewportSize = this._platform.isBrowser ? {
          width: t.innerWidth,
          height: t.innerHeight
        } : {
          width: 0,
          height: 0
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Ta = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })(), Fa = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [ye, Ta, ye, Ta]
      })
    }
    return i
  })()
});
var bn, Di, Ce, Pa, Ri, Tr, ub, La, Fr, Va = _(() => {
  f();
  f();
  bn = class {
    _attachedHost;
    attach(n) {
      return this._attachedHost = n, n.attach(this)
    }
    detach() {
      let n = this._attachedHost;
      n != null && (this._attachedHost = null, n.detach())
    }
    get isAttached() {
      return this._attachedHost != null
    }
    setAttachedHost(n) {
      this._attachedHost = n
    }
  }, Di = class extends bn {
    component;
    viewContainerRef;
    injector;
    projectableNodes;
    constructor(n, t, e, r) {
      super(), this.component = n, this.viewContainerRef = t, this.injector = e, this.projectableNodes = r
    }
  }, Ce = class extends bn {
    templateRef;
    viewContainerRef;
    context;
    injector;
    constructor(n, t, e, r) {
      super(), this.templateRef = n, this.viewContainerRef = t, this.context = e, this.injector = r
    }
    get origin() {
      return this.templateRef.elementRef
    }
    attach(n, t = this.context) {
      return this.context = t, super.attach(n)
    }
    detach() {
      return this.context = void 0, super.detach()
    }
  }, Pa = class extends bn {
    element;
    constructor(n) {
      super(), this.element = n instanceof D ? n.nativeElement : n
    }
  }, Ri = class {
    _attachedPortal;
    _disposeFn;
    _isDisposed = !1;
    hasAttached() {
      return !!this._attachedPortal
    }
    attach(n) {
      if (n instanceof Di) return this._attachedPortal = n, this.attachComponentPortal(n);
      if (n instanceof Ce) return this._attachedPortal = n, this.attachTemplatePortal(n);
      if (this.attachDomPortal && n instanceof Pa) return this._attachedPortal = n, this.attachDomPortal(n)
    }
    attachDomPortal = null;
    detach() {
      this._attachedPortal && (this._attachedPortal.setAttachedHost(null), this._attachedPortal = null), this._invokeDisposeFn()
    }
    dispose() {
      this.hasAttached() && this.detach(), this._invokeDisposeFn(), this._isDisposed = !0
    }
    setDisposeFn(n) {
      this._disposeFn = n
    }
    _invokeDisposeFn() {
      this._disposeFn && (this._disposeFn(), this._disposeFn = null)
    }
  }, Tr = class extends Ri {
    outletElement;
    _appRef;
    _defaultInjector;
    constructor(n, t, e) {
      super(), this.outletElement = n, this._appRef = t, this._defaultInjector = e
    }
    attachComponentPortal(n) {
      let t;
      if (n.viewContainerRef) {
        let e = n.injector || n.viewContainerRef.injector,
          r = e.get(Po, null, {
            optional: !0
          }) || void 0;
        t = n.viewContainerRef.createComponent(n.component, {
          index: n.viewContainerRef.length,
          injector: e,
          ngModuleRef: r,
          projectableNodes: n.projectableNodes || void 0
        }), this.setDisposeFn(() => t.destroy())
      } else {
        let e = this._appRef,
          r = n.injector || this._defaultInjector || N.NULL,
          o = r.get(It, e.injector);
        t = Qn(n.component, {
          elementInjector: r,
          environmentInjector: o,
          projectableNodes: n.projectableNodes || void 0
        }), e.attachView(t.hostView), this.setDisposeFn(() => {
          e.viewCount > 0 && e.detachView(t.hostView), t.destroy()
        })
      }
      return this.outletElement.appendChild(this._getComponentRootNode(t)), this._attachedPortal = n, t
    }
    attachTemplatePortal(n) {
      let t = n.viewContainerRef,
        e = t.createEmbeddedView(n.templateRef, n.context, {
          injector: n.injector
        });
      return e.rootNodes.forEach(r => this.outletElement.appendChild(r)), e.detectChanges(), this.setDisposeFn(() => {
        let r = t.indexOf(e);
        r !== -1 && t.remove(r)
      }), this._attachedPortal = n, e
    }
    attachDomPortal = n => {
      let t = n.element;
      t.parentNode;
      let e = this.outletElement.ownerDocument.createComment("dom-portal");
      t.parentNode.insertBefore(e, t), this.outletElement.appendChild(t), this._attachedPortal = n, super.setDisposeFn(() => {
        e.parentNode && e.parentNode.replaceChild(t, e)
      })
    };
    dispose() {
      super.dispose(), this.outletElement.remove()
    }
    _getComponentRootNode(n) {
      return n.hostView.rootNodes[0]
    }
  }, ub = (() => {
    class i extends Ce {
      constructor() {
        let t = l(Oe),
          e = l(me);
        super(t, e)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdkPortal", ""]
        ],
        exportAs: ["cdkPortal"],
        features: [L]
      })
    }
    return i
  })(), La = (() => {
    class i extends Ri {
      _moduleRef = l(Po, {
        optional: !0
      });
      _document = l(O);
      _viewContainerRef = l(me);
      _isInitialized = !1;
      _attachedRef;
      constructor() {
        super()
      }
      get portal() {
        return this._attachedPortal
      }
      set portal(t) {
        this.hasAttached() && !t && !this._isInitialized || (this.hasAttached() && super.detach(), t && super.attach(t), this._attachedPortal = t || null)
      }
      attached = new A;
      get attachedRef() {
        return this._attachedRef
      }
      ngOnInit() {
        this._isInitialized = !0
      }
      ngOnDestroy() {
        super.dispose(), this._attachedRef = this._attachedPortal = null
      }
      attachComponentPortal(t) {
        t.setAttachedHost(this);
        let e = t.viewContainerRef != null ? t.viewContainerRef : this._viewContainerRef,
          r = e.createComponent(t.component, {
            index: e.length,
            injector: t.injector || e.injector,
            projectableNodes: t.projectableNodes || void 0,
            ngModuleRef: this._moduleRef || void 0
          });
        return e !== this._viewContainerRef && this._getRootNode().appendChild(r.hostView.rootNodes[0]), super.setDisposeFn(() => r.destroy()), this._attachedPortal = t, this._attachedRef = r, this.attached.emit(r), r
      }
      attachTemplatePortal(t) {
        t.setAttachedHost(this);
        let e = this._viewContainerRef.createEmbeddedView(t.templateRef, t.context, {
          injector: t.injector
        });
        return super.setDisposeFn(() => this._viewContainerRef.clear()), this._attachedPortal = t, this._attachedRef = e, this.attached.emit(e), e
      }
      attachDomPortal = t => {
        let e = t.element;
        e.parentNode;
        let r = this._document.createComment("dom-portal");
        t.setAttachedHost(this), e.parentNode.insertBefore(r, e), this._getRootNode().appendChild(e), this._attachedPortal = t, super.setDisposeFn(() => {
          r.parentNode && r.parentNode.replaceChild(e, r)
        })
      };
      _getRootNode() {
        let t = this._viewContainerRef.element.nativeElement;
        return t.nodeType === t.ELEMENT_NODE ? t : t.parentNode
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdkPortalOutlet", ""]
        ],
        inputs: {
          portal: [0, "cdkPortalOutlet", "portal"]
        },
        outputs: {
          attached: "attached"
        },
        exportAs: ["cdkPortalOutlet"],
        features: [L]
      })
    }
    return i
  })(), Fr = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })()
});
var ja, Wt, Ba = _(() => {
  f();
  f();
  ja = {}, Wt = (() => {
    class i {
      _appId = l(Wn);
      getId(t) {
        return this._appId !== "ng" && (t += this._appId), ja.hasOwnProperty(t) || (ja[t] = 0), `${t}${ja[t]++}`
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});

function Nr(i, ...n) {
  return n.length ? n.some(t => i[t]) : i.altKey || i.shiftKey || i.ctrlKey || i.metaKey
}
var za = _(() => {});

function Uc(i) {
  return new Pr(i.get(Si), i.get(O))
}

function Hc(i, n) {
  return new Lr(i.get(_n), i.get(E), i.get(Si), n)
}

function Ua(i, n) {
  return n.some(t => {
    let e = i.bottom < t.top,
      r = i.top > t.bottom,
      o = i.right < t.left,
      a = i.left > t.right;
    return e || r || o || a
  })
}

function Pc(i, n) {
  return n.some(t => {
    let e = i.top < t.top,
      r = i.bottom > t.bottom,
      o = i.left < t.left,
      a = i.right > t.right;
    return e || r || o || a
  })
}

function Hr(i, n) {
  return new Vr(i.get(_n), i.get(Si), i.get(E), n)
}

function Lc(i, n) {
  let t = typeof ShadowRoot < "u" && ShadowRoot,
    e = n;
  for (; e;) {
    if (e === i) return !0;
    e = t && e instanceof ShadowRoot ? e.host : e.parentNode
  }
  return !1
}

function Ga(i, n) {
  return new zr(n, i.get(Si), i.get(O), i.get(T), i.get(Wa))
}

function $e(i, n) {
  for (let t in n) n.hasOwnProperty(t) && (i[t] = n[t]);
  return i
}

function jc(i) {
  if (typeof i != "number" && i != null) {
    let [n, t] = i.split(tf);
    return !t || t === "px" ? parseFloat(n) : null
  }
  return i || null
}

function Bc(i) {
  return {
    top: Math.floor(i.top),
    right: Math.floor(i.right),
    bottom: Math.floor(i.bottom),
    left: Math.floor(i.left),
    width: Math.floor(i.width),
    height: Math.floor(i.height)
  }
}

function ef(i, n) {
  return i === n ? !0 : i.isOriginClipped === n.isOriginClipped && i.isOriginOutsideView === n.isOriginOutsideView && i.isOverlayClipped === n.isOverlayClipped && i.isOverlayOutsideView === n.isOverlayOutsideView
}

function $r(i) {
  return new Ur
}

function Cn(i, n) {
  i.get(Mt).load(Yc);
  let t = i.get(Wa),
    e = i.get(O),
    r = i.get(Wt),
    o = i.get(ie),
    a = i.get(le),
    s = e.createElement("div"),
    c = e.createElement("div");
  c.id = r.getId("cdk-overlay-"), c.classList.add("cdk-overlay-pane"), s.appendChild(c), t.getContainerElement().appendChild(s);
  let d = new Tr(c, o, i),
    u = new We(n),
    x = i.get(lt, null, {
      optional: !0
    }) || i.get(kt).createRenderer(null, null);
  return u.direction = u.direction || a.value, new Br(d, s, c, u, i.get(E), i.get(Gc), e, i.get(fe), i.get(qc), n?.disableAnimations ?? i.get(Gn, null, {
    optional: !0
  }) === "NoopAnimations", i.get(It), x)
}

function of(i) {
  let n = l(N);
  return () => Hr(n)
}
var Nc, Pr, Lr, yn, Vr, $c, We, jr, Wc, Gc, qc, Yc, Wa, Ha, Br, Vc, tf, zr, zc, Ur, Kc, Zc, nf, Xc, $a, rf, af, qa, Ya = _(() => {
  f();
  f();
  Pe();
  se();
  fn();
  kc();
  xi();
  nt();
  Ia();
  Oa();
  Na();
  Va();
  kr();
  ht();
  Ba();
  Ir();
  za();
  vn();
  Nc = gn();
  Pr = class {
    _viewportRuler;
    _previousHTMLStyles = {
      top: "",
      left: ""
    };
    _previousScrollPosition;
    _isEnabled = !1;
    _document;
    constructor(n, t) {
      this._viewportRuler = n, this._document = t
    }
    attach() {}
    enable() {
      if (this._canBeEnabled()) {
        let n = this._document.documentElement;
        this._previousScrollPosition = this._viewportRuler.getViewportScrollPosition(), this._previousHTMLStyles.left = n.style.left || "", this._previousHTMLStyles.top = n.style.top || "", n.style.left = Y(-this._previousScrollPosition.left), n.style.top = Y(-this._previousScrollPosition.top), n.classList.add("cdk-global-scrollblock"), this._isEnabled = !0
      }
    }
    disable() {
      if (this._isEnabled) {
        let n = this._document.documentElement,
          t = this._document.body,
          e = n.style,
          r = t.style,
          o = e.scrollBehavior || "",
          a = r.scrollBehavior || "";
        this._isEnabled = !1, e.left = this._previousHTMLStyles.left, e.top = this._previousHTMLStyles.top, n.classList.remove("cdk-global-scrollblock"), Nc && (e.scrollBehavior = r.scrollBehavior = "auto"), window.scroll(this._previousScrollPosition.left, this._previousScrollPosition.top), Nc && (e.scrollBehavior = o, r.scrollBehavior = a)
      }
    }
    _canBeEnabled() {
      if (this._document.documentElement.classList.contains("cdk-global-scrollblock") || this._isEnabled) return !1;
      let t = this._document.documentElement,
        e = this._viewportRuler.getViewportSize();
      return t.scrollHeight > e.height || t.scrollWidth > e.width
    }
  };
  Lr = class {
    _scrollDispatcher;
    _ngZone;
    _viewportRuler;
    _config;
    _scrollSubscription = null;
    _overlayRef;
    _initialScrollPosition;
    constructor(n, t, e, r) {
      this._scrollDispatcher = n, this._ngZone = t, this._viewportRuler = e, this._config = r
    }
    attach(n) {
      this._overlayRef, this._overlayRef = n
    }
    enable() {
      if (this._scrollSubscription) return;
      let n = this._scrollDispatcher.scrolled(0).pipe(K(t => !t || !this._overlayRef.overlayElement.contains(t.getElementRef().nativeElement)));
      this._config && this._config.threshold && this._config.threshold > 1 ? (this._initialScrollPosition = this._viewportRuler.getViewportScrollPosition().top, this._scrollSubscription = n.subscribe(() => {
        let t = this._viewportRuler.getViewportScrollPosition().top;
        Math.abs(t - this._initialScrollPosition) > this._config.threshold ? this._detach() : this._overlayRef.updatePosition()
      })) : this._scrollSubscription = n.subscribe(this._detach)
    }
    disable() {
      this._scrollSubscription && (this._scrollSubscription.unsubscribe(), this._scrollSubscription = null)
    }
    detach() {
      this.disable(), this._overlayRef = null
    }
    _detach = () => {
      this.disable(), this._overlayRef.hasAttached() && this._ngZone.run(() => this._overlayRef.detach())
    }
  }, yn = class {
    enable() {}
    disable() {}
    attach() {}
  };
  Vr = class {
    _scrollDispatcher;
    _viewportRuler;
    _ngZone;
    _config;
    _scrollSubscription = null;
    _overlayRef;
    constructor(n, t, e, r) {
      this._scrollDispatcher = n, this._viewportRuler = t, this._ngZone = e, this._config = r
    }
    attach(n) {
      this._overlayRef, this._overlayRef = n
    }
    enable() {
      if (!this._scrollSubscription) {
        let n = this._config ? this._config.scrollThrottle : 0;
        this._scrollSubscription = this._scrollDispatcher.scrolled(n).subscribe(() => {
          if (this._overlayRef.updatePosition(), this._config && this._config.autoClose) {
            let t = this._overlayRef.overlayElement.getBoundingClientRect(),
              {
                width: e,
                height: r
              } = this._viewportRuler.getViewportSize();
            Ua(t, [{
              width: e,
              height: r,
              bottom: r,
              right: e,
              top: 0,
              left: 0
            }]) && (this.disable(), this._ngZone.run(() => this._overlayRef.detach()))
          }
        })
      }
    }
    disable() {
      this._scrollSubscription && (this._scrollSubscription.unsubscribe(), this._scrollSubscription = null)
    }
    detach() {
      this.disable(), this._overlayRef = null
    }
  }, $c = (() => {
    class i {
      _injector = l(N);
      constructor() {}
      noop = () => new yn;
      close = t => Hc(this._injector, t);
      block = () => Uc(this._injector);
      reposition = t => Hr(this._injector, t);
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), We = class {
    positionStrategy;
    scrollStrategy = new yn;
    panelClass = "";
    hasBackdrop = !1;
    backdropClass = "cdk-overlay-dark-backdrop";
    disableAnimations;
    width;
    height;
    minWidth;
    minHeight;
    maxWidth;
    maxHeight;
    direction;
    disposeOnNavigation = !1;
    constructor(n) {
      if (n) {
        let t = Object.keys(n);
        for (let e of t) n[e] !== void 0 && (this[e] = n[e])
      }
    }
  }, jr = class {
    connectionPair;
    scrollableViewProperties;
    constructor(n, t) {
      this.connectionPair = n, this.scrollableViewProperties = t
    }
  }, Wc = (() => {
    class i {
      _attachedOverlays = [];
      _document = l(O);
      _isAttached;
      constructor() {}
      ngOnDestroy() {
        this.detach()
      }
      add(t) {
        this.remove(t), this._attachedOverlays.push(t)
      }
      remove(t) {
        let e = this._attachedOverlays.indexOf(t);
        e > -1 && this._attachedOverlays.splice(e, 1), this._attachedOverlays.length === 0 && this.detach()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Gc = (() => {
    class i extends Wc {
      _ngZone = l(E);
      _renderer = l(kt).createRenderer(null, null);
      _cleanupKeydown;
      add(t) {
        super.add(t), this._isAttached || (this._ngZone.runOutsideAngular(() => {
          this._cleanupKeydown = this._renderer.listen("body", "keydown", this._keydownListener)
        }), this._isAttached = !0)
      }
      detach() {
        this._isAttached && (this._cleanupKeydown?.(), this._isAttached = !1)
      }
      _keydownListener = t => {
        let e = this._attachedOverlays;
        for (let r = e.length - 1; r > -1; r--)
          if (e[r]._keydownEvents.observers.length > 0) {
            this._ngZone.run(() => e[r]._keydownEvents.next(t));
            break
          }
      };
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), qc = (() => {
    class i extends Wc {
      _platform = l(T);
      _ngZone = l(E);
      _renderer = l(kt).createRenderer(null, null);
      _cursorOriginalValue;
      _cursorStyleIsSet = !1;
      _pointerDownEventTarget;
      _cleanups;
      add(t) {
        if (super.add(t), !this._isAttached) {
          let e = this._document.body,
            r = {
              capture: !0
            },
            o = this._renderer;
          this._cleanups = this._ngZone.runOutsideAngular(() => [o.listen(e, "pointerdown", this._pointerDownListener, r), o.listen(e, "click", this._clickListener, r), o.listen(e, "auxclick", this._clickListener, r), o.listen(e, "contextmenu", this._clickListener, r)]), this._platform.IOS && !this._cursorStyleIsSet && (this._cursorOriginalValue = e.style.cursor, e.style.cursor = "pointer", this._cursorStyleIsSet = !0), this._isAttached = !0
        }
      }
      detach() {
        this._isAttached && (this._cleanups?.forEach(t => t()), this._cleanups = void 0, this._platform.IOS && this._cursorStyleIsSet && (this._document.body.style.cursor = this._cursorOriginalValue, this._cursorStyleIsSet = !1), this._isAttached = !1)
      }
      _pointerDownListener = t => {
        this._pointerDownEventTarget = xt(t)
      };
      _clickListener = t => {
        let e = xt(t),
          r = t.type === "click" && this._pointerDownEventTarget ? this._pointerDownEventTarget : e;
        this._pointerDownEventTarget = null;
        let o = this._attachedOverlays.slice();
        for (let a = o.length - 1; a > -1; a--) {
          let s = o[a];
          if (s._outsidePointerEvents.observers.length < 1 || !s.hasAttached()) continue;
          if (Lc(s.overlayElement, e) || Lc(s.overlayElement, r)) break;
          let c = s._outsidePointerEvents;
          this._ngZone ? this._ngZone.run(() => c.next(t)) : c.next(t)
        }
      };
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })();
  Yc = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["ng-component"]
        ],
        hostAttrs: ["cdk-overlay-style-loader", ""],
        decls: 0,
        vars: 0,
        template: function(e, r) {},
        styles: [`.cdk-overlay-container,.cdk-global-overlay-wrapper{pointer-events:none;top:0;left:0;height:100%;width:100%}.cdk-overlay-container{position:fixed}@layer cdk-overlay{.cdk-overlay-container{z-index:1000}}.cdk-overlay-container:empty{display:none}.cdk-global-overlay-wrapper{display:flex;position:absolute}@layer cdk-overlay{.cdk-global-overlay-wrapper{z-index:1000}}.cdk-overlay-pane{position:absolute;pointer-events:auto;box-sizing:border-box;display:flex;max-width:100%;max-height:100%}@layer cdk-overlay{.cdk-overlay-pane{z-index:1000}}.cdk-overlay-backdrop{position:absolute;top:0;bottom:0;left:0;right:0;pointer-events:auto;-webkit-tap-highlight-color:rgba(0,0,0,0);opacity:0;touch-action:manipulation}@layer cdk-overlay{.cdk-overlay-backdrop{z-index:1000;transition:opacity 400ms cubic-bezier(0.25, 0.8, 0.25, 1)}}@media(prefers-reduced-motion){.cdk-overlay-backdrop{transition-duration:1ms}}.cdk-overlay-backdrop-showing{opacity:1}@media(forced-colors: active){.cdk-overlay-backdrop-showing{opacity:.6}}@layer cdk-overlay{.cdk-overlay-dark-backdrop{background:rgba(0,0,0,.32)}}.cdk-overlay-transparent-backdrop{transition:visibility 1ms linear,opacity 1ms linear;visibility:hidden;opacity:1}.cdk-overlay-transparent-backdrop.cdk-overlay-backdrop-showing,.cdk-high-contrast-active .cdk-overlay-transparent-backdrop{opacity:0;visibility:visible}.cdk-overlay-backdrop-noop-animation{transition:none}.cdk-overlay-connected-position-bounding-box{position:absolute;display:flex;flex-direction:column;min-width:1px;min-height:1px}@layer cdk-overlay{.cdk-overlay-connected-position-bounding-box{z-index:1000}}.cdk-global-scrollblock{position:fixed;width:100%;overflow-y:scroll}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), Wa = (() => {
    class i {
      _platform = l(T);
      _containerElement;
      _document = l(O);
      _styleLoader = l(Mt);
      constructor() {}
      ngOnDestroy() {
        this._containerElement?.remove()
      }
      getContainerElement() {
        return this._loadStyles(), this._containerElement || this._createContainer(), this._containerElement
      }
      _createContainer() {
        let t = "cdk-overlay-container";
        if (this._platform.isBrowser || Ma()) {
          let r = this._document.querySelectorAll(`.${t}[platform="server"], .${t}[platform="test"]`);
          for (let o = 0; o < r.length; o++) r[o].remove()
        }
        let e = this._document.createElement("div");
        e.classList.add(t), Ma() ? e.setAttribute("platform", "test") : this._platform.isBrowser || e.setAttribute("platform", "server"), this._document.body.appendChild(e), this._containerElement = e
      }
      _loadStyles() {
        this._styleLoader.load(Yc)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Ha = class {
    _renderer;
    _ngZone;
    element;
    _cleanupClick;
    _cleanupTransitionEnd;
    _fallbackTimeout;
    constructor(n, t, e, r) {
      this._renderer = t, this._ngZone = e, this.element = n.createElement("div"), this.element.classList.add("cdk-overlay-backdrop"), this._cleanupClick = t.listen(this.element, "click", r)
    }
    detach() {
      this._ngZone.runOutsideAngular(() => {
        let n = this.element;
        clearTimeout(this._fallbackTimeout), this._cleanupTransitionEnd?.(), this._cleanupTransitionEnd = this._renderer.listen(n, "transitionend", this.dispose), this._fallbackTimeout = setTimeout(this.dispose, 500), n.style.pointerEvents = "none", n.classList.remove("cdk-overlay-backdrop-showing")
      })
    }
    dispose = () => {
      clearTimeout(this._fallbackTimeout), this._cleanupClick?.(), this._cleanupTransitionEnd?.(), this._cleanupClick = this._cleanupTransitionEnd = this._fallbackTimeout = void 0, this.element.remove()
    }
  }, Br = class {
    _portalOutlet;
    _host;
    _pane;
    _config;
    _ngZone;
    _keyboardDispatcher;
    _document;
    _location;
    _outsideClickDispatcher;
    _animationsDisabled;
    _injector;
    _renderer;
    _backdropClick = new y;
    _attachments = new y;
    _detachments = new y;
    _positionStrategy;
    _scrollStrategy;
    _locationChanges = ft.EMPTY;
    _backdropRef = null;
    _detachContentMutationObserver;
    _detachContentAfterRenderRef;
    _previousHostParent;
    _keydownEvents = new y;
    _outsidePointerEvents = new y;
    _afterNextRenderRef;
    constructor(n, t, e, r, o, a, s, c, d, u = !1, x, j) {
      this._portalOutlet = n, this._host = t, this._pane = e, this._config = r, this._ngZone = o, this._keyboardDispatcher = a, this._document = s, this._location = c, this._outsideClickDispatcher = d, this._animationsDisabled = u, this._injector = x, this._renderer = j, r.scrollStrategy && (this._scrollStrategy = r.scrollStrategy, this._scrollStrategy.attach(this)), this._positionStrategy = r.positionStrategy
    }
    get overlayElement() {
      return this._pane
    }
    get backdropElement() {
      return this._backdropRef?.element || null
    }
    get hostElement() {
      return this._host
    }
    attach(n) {
      !this._host.parentElement && this._previousHostParent && this._previousHostParent.appendChild(this._host);
      let t = this._portalOutlet.attach(n);
      return this._positionStrategy && this._positionStrategy.attach(this), this._updateStackingOrder(), this._updateElementSize(), this._updateElementDirection(), this._scrollStrategy && this._scrollStrategy.enable(), this._afterNextRenderRef?.destroy(), this._afterNextRenderRef = Ot(() => {
        this.hasAttached() && this.updatePosition()
      }, {
        injector: this._injector
      }), this._togglePointerEvents(!0), this._config.hasBackdrop && this._attachBackdrop(), this._config.panelClass && this._toggleClasses(this._pane, this._config.panelClass, !0), this._attachments.next(), this._completeDetachContent(), this._keyboardDispatcher.add(this), this._config.disposeOnNavigation && (this._locationChanges = this._location.subscribe(() => this.dispose())), this._outsideClickDispatcher.add(this), typeof t?.onDestroy == "function" && t.onDestroy(() => {
        this.hasAttached() && this._ngZone.runOutsideAngular(() => Promise.resolve().then(() => this.detach()))
      }), t
    }
    detach() {
      if (!this.hasAttached()) return;
      this.detachBackdrop(), this._togglePointerEvents(!1), this._positionStrategy && this._positionStrategy.detach && this._positionStrategy.detach(), this._scrollStrategy && this._scrollStrategy.disable();
      let n = this._portalOutlet.detach();
      return this._detachments.next(), this._completeDetachContent(), this._keyboardDispatcher.remove(this), this._detachContentWhenEmpty(), this._locationChanges.unsubscribe(), this._outsideClickDispatcher.remove(this), n
    }
    dispose() {
      let n = this.hasAttached();
      this._positionStrategy && this._positionStrategy.dispose(), this._disposeScrollStrategy(), this._backdropRef?.dispose(), this._locationChanges.unsubscribe(), this._keyboardDispatcher.remove(this), this._portalOutlet.dispose(), this._attachments.complete(), this._backdropClick.complete(), this._keydownEvents.complete(), this._outsidePointerEvents.complete(), this._outsideClickDispatcher.remove(this), this._host?.remove(), this._afterNextRenderRef?.destroy(), this._previousHostParent = this._pane = this._host = this._backdropRef = null, n && this._detachments.next(), this._detachments.complete(), this._completeDetachContent()
    }
    hasAttached() {
      return this._portalOutlet.hasAttached()
    }
    backdropClick() {
      return this._backdropClick
    }
    attachments() {
      return this._attachments
    }
    detachments() {
      return this._detachments
    }
    keydownEvents() {
      return this._keydownEvents
    }
    outsidePointerEvents() {
      return this._outsidePointerEvents
    }
    getConfig() {
      return this._config
    }
    updatePosition() {
      this._positionStrategy && this._positionStrategy.apply()
    }
    updatePositionStrategy(n) {
      n !== this._positionStrategy && (this._positionStrategy && this._positionStrategy.dispose(), this._positionStrategy = n, this.hasAttached() && (n.attach(this), this.updatePosition()))
    }
    updateSize(n) {
      this._config = h(h({}, this._config), n), this._updateElementSize()
    }
    setDirection(n) {
      this._config = $(h({}, this._config), {
        direction: n
      }), this._updateElementDirection()
    }
    addPanelClass(n) {
      this._pane && this._toggleClasses(this._pane, n, !0)
    }
    removePanelClass(n) {
      this._pane && this._toggleClasses(this._pane, n, !1)
    }
    getDirection() {
      let n = this._config.direction;
      return n ? typeof n == "string" ? n : n.value : "ltr"
    }
    updateScrollStrategy(n) {
      n !== this._scrollStrategy && (this._disposeScrollStrategy(), this._scrollStrategy = n, this.hasAttached() && (n.attach(this), n.enable()))
    }
    _updateElementDirection() {
      this._host.setAttribute("dir", this.getDirection())
    }
    _updateElementSize() {
      if (!this._pane) return;
      let n = this._pane.style;
      n.width = Y(this._config.width), n.height = Y(this._config.height), n.minWidth = Y(this._config.minWidth), n.minHeight = Y(this._config.minHeight), n.maxWidth = Y(this._config.maxWidth), n.maxHeight = Y(this._config.maxHeight)
    }
    _togglePointerEvents(n) {
      this._pane.style.pointerEvents = n ? "" : "none"
    }
    _attachBackdrop() {
      let n = "cdk-overlay-backdrop-showing";
      this._backdropRef?.dispose(), this._backdropRef = new Ha(this._document, this._renderer, this._ngZone, t => {
        this._backdropClick.next(t)
      }), this._animationsDisabled && this._backdropRef.element.classList.add("cdk-overlay-backdrop-noop-animation"), this._config.backdropClass && this._toggleClasses(this._backdropRef.element, this._config.backdropClass, !0), this._host.parentElement.insertBefore(this._backdropRef.element, this._host), !this._animationsDisabled && typeof requestAnimationFrame < "u" ? this._ngZone.runOutsideAngular(() => {
        requestAnimationFrame(() => this._backdropRef?.element.classList.add(n))
      }) : this._backdropRef.element.classList.add(n)
    }
    _updateStackingOrder() {
      this._host.nextSibling && this._host.parentNode.appendChild(this._host)
    }
    detachBackdrop() {
      this._animationsDisabled ? (this._backdropRef?.dispose(), this._backdropRef = null) : this._backdropRef?.detach()
    }
    _toggleClasses(n, t, e) {
      let r = wi(t || []).filter(o => !!o);
      r.length && (e ? n.classList.add(...r) : n.classList.remove(...r))
    }
    _detachContentWhenEmpty() {
      let n = !1;
      try {
        this._detachContentAfterRenderRef = Ot(() => {
          n = !0, this._detachContent()
        }, {
          injector: this._injector
        })
      } catch (t) {
        if (n) throw t;
        this._detachContent()
      }
      globalThis.MutationObserver && this._pane && (this._detachContentMutationObserver ||= new globalThis.MutationObserver(() => {
        this._detachContent()
      }), this._detachContentMutationObserver.observe(this._pane, {
        childList: !0
      }))
    }
    _detachContent() {
      (!this._pane || !this._host || this._pane.children.length === 0) && (this._pane && this._config.panelClass && this._toggleClasses(this._pane, this._config.panelClass, !1), this._host && this._host.parentElement && (this._previousHostParent = this._host.parentElement, this._host.remove()), this._completeDetachContent())
    }
    _completeDetachContent() {
      this._detachContentAfterRenderRef?.destroy(), this._detachContentAfterRenderRef = void 0, this._detachContentMutationObserver?.disconnect()
    }
    _disposeScrollStrategy() {
      let n = this._scrollStrategy;
      n?.disable(), n?.detach?.()
    }
  }, Vc = "cdk-overlay-connected-position-bounding-box", tf = /([A-Za-z%]+)$/;
  zr = class {
    _viewportRuler;
    _document;
    _platform;
    _overlayContainer;
    _overlayRef;
    _isInitialRender;
    _lastBoundingBoxSize = {
      width: 0,
      height: 0
    };
    _isPushed = !1;
    _canPush = !0;
    _growAfterOpen = !1;
    _hasFlexibleDimensions = !0;
    _positionLocked = !1;
    _originRect;
    _overlayRect;
    _viewportRect;
    _containerRect;
    _viewportMargin = 0;
    _scrollables = [];
    _preferredPositions = [];
    _origin;
    _pane;
    _isDisposed;
    _boundingBox;
    _lastPosition;
    _lastScrollVisibility;
    _positionChanges = new y;
    _resizeSubscription = ft.EMPTY;
    _offsetX = 0;
    _offsetY = 0;
    _transformOriginSelector;
    _appliedPanelClasses = [];
    _previousPushAmount;
    positionChanges = this._positionChanges;
    get positions() {
      return this._preferredPositions
    }
    constructor(n, t, e, r, o) {
      this._viewportRuler = t, this._document = e, this._platform = r, this._overlayContainer = o, this.setOrigin(n)
    }
    attach(n) {
      this._overlayRef && this._overlayRef, this._validatePositions(), n.hostElement.classList.add(Vc), this._overlayRef = n, this._boundingBox = n.hostElement, this._pane = n.overlayElement, this._isDisposed = !1, this._isInitialRender = !0, this._lastPosition = null, this._resizeSubscription.unsubscribe(), this._resizeSubscription = this._viewportRuler.change().subscribe(() => {
        this._isInitialRender = !0, this.apply()
      })
    }
    apply() {
      if (this._isDisposed || !this._platform.isBrowser) return;
      if (!this._isInitialRender && this._positionLocked && this._lastPosition) {
        this.reapplyLastPosition();
        return
      }
      this._clearPanelClasses(), this._resetOverlayElementStyles(), this._resetBoundingBoxStyles(), this._viewportRect = this._getNarrowedViewportRect(), this._originRect = this._getOriginRect(), this._overlayRect = this._pane.getBoundingClientRect(), this._containerRect = this._overlayContainer.getContainerElement().getBoundingClientRect();
      let n = this._originRect,
        t = this._overlayRect,
        e = this._viewportRect,
        r = this._containerRect,
        o = [],
        a;
      for (let s of this._preferredPositions) {
        let c = this._getOriginPoint(n, r, s),
          d = this._getOverlayPoint(c, t, s),
          u = this._getOverlayFit(d, t, e, s);
        if (u.isCompletelyWithinViewport) {
          this._isPushed = !1, this._applyPosition(s, c);
          return
        }
        if (this._canFitWithFlexibleDimensions(u, d, e)) {
          o.push({
            position: s,
            origin: c,
            overlayRect: t,
            boundingBoxRect: this._calculateBoundingBoxRect(c, s)
          });
          continue
        }(!a || a.overlayFit.visibleArea < u.visibleArea) && (a = {
          overlayFit: u,
          overlayPoint: d,
          originPoint: c,
          position: s,
          overlayRect: t
        })
      }
      if (o.length) {
        let s = null,
          c = -1;
        for (let d of o) {
          let u = d.boundingBoxRect.width * d.boundingBoxRect.height * (d.position.weight || 1);
          u > c && (c = u, s = d)
        }
        this._isPushed = !1, this._applyPosition(s.position, s.origin);
        return
      }
      if (this._canPush) {
        this._isPushed = !0, this._applyPosition(a.position, a.originPoint);
        return
      }
      this._applyPosition(a.position, a.originPoint)
    }
    detach() {
      this._clearPanelClasses(), this._lastPosition = null, this._previousPushAmount = null, this._resizeSubscription.unsubscribe()
    }
    dispose() {
      this._isDisposed || (this._boundingBox && $e(this._boundingBox.style, {
        top: "",
        left: "",
        right: "",
        bottom: "",
        height: "",
        width: "",
        alignItems: "",
        justifyContent: ""
      }), this._pane && this._resetOverlayElementStyles(), this._overlayRef && this._overlayRef.hostElement.classList.remove(Vc), this.detach(), this._positionChanges.complete(), this._overlayRef = this._boundingBox = null, this._isDisposed = !0)
    }
    reapplyLastPosition() {
      if (this._isDisposed || !this._platform.isBrowser) return;
      let n = this._lastPosition;
      if (n) {
        this._originRect = this._getOriginRect(), this._overlayRect = this._pane.getBoundingClientRect(), this._viewportRect = this._getNarrowedViewportRect(), this._containerRect = this._overlayContainer.getContainerElement().getBoundingClientRect();
        let t = this._getOriginPoint(this._originRect, this._containerRect, n);
        this._applyPosition(n, t)
      } else this.apply()
    }
    withScrollableContainers(n) {
      return this._scrollables = n, this
    }
    withPositions(n) {
      return this._preferredPositions = n, n.indexOf(this._lastPosition) === -1 && (this._lastPosition = null), this._validatePositions(), this
    }
    withViewportMargin(n) {
      return this._viewportMargin = n, this
    }
    withFlexibleDimensions(n = !0) {
      return this._hasFlexibleDimensions = n, this
    }
    withGrowAfterOpen(n = !0) {
      return this._growAfterOpen = n, this
    }
    withPush(n = !0) {
      return this._canPush = n, this
    }
    withLockedPosition(n = !0) {
      return this._positionLocked = n, this
    }
    setOrigin(n) {
      return this._origin = n, this
    }
    withDefaultOffsetX(n) {
      return this._offsetX = n, this
    }
    withDefaultOffsetY(n) {
      return this._offsetY = n, this
    }
    withTransformOriginOn(n) {
      return this._transformOriginSelector = n, this
    }
    _getOriginPoint(n, t, e) {
      let r;
      if (e.originX == "center") r = n.left + n.width / 2;
      else {
        let a = this._isRtl() ? n.right : n.left,
          s = this._isRtl() ? n.left : n.right;
        r = e.originX == "start" ? a : s
      }
      t.left < 0 && (r -= t.left);
      let o;
      return e.originY == "center" ? o = n.top + n.height / 2 : o = e.originY == "top" ? n.top : n.bottom, t.top < 0 && (o -= t.top), {
        x: r,
        y: o
      }
    }
    _getOverlayPoint(n, t, e) {
      let r;
      e.overlayX == "center" ? r = -t.width / 2 : e.overlayX === "start" ? r = this._isRtl() ? -t.width : 0 : r = this._isRtl() ? 0 : -t.width;
      let o;
      return e.overlayY == "center" ? o = -t.height / 2 : o = e.overlayY == "top" ? 0 : -t.height, {
        x: n.x + r,
        y: n.y + o
      }
    }
    _getOverlayFit(n, t, e, r) {
      let o = Bc(t),
        {
          x: a,
          y: s
        } = n,
        c = this._getOffset(r, "x"),
        d = this._getOffset(r, "y");
      c && (a += c), d && (s += d);
      let u = 0 - a,
        x = a + o.width - e.width,
        j = 0 - s,
        B = s + o.height - e.height,
        I = this._subtractOverflows(o.width, u, x),
        V = this._subtractOverflows(o.height, j, B),
        bt = I * V;
      return {
        visibleArea: bt,
        isCompletelyWithinViewport: o.width * o.height === bt,
        fitsInViewportVertically: V === o.height,
        fitsInViewportHorizontally: I == o.width
      }
    }
    _canFitWithFlexibleDimensions(n, t, e) {
      if (this._hasFlexibleDimensions) {
        let r = e.bottom - t.y,
          o = e.right - t.x,
          a = jc(this._overlayRef.getConfig().minHeight),
          s = jc(this._overlayRef.getConfig().minWidth),
          c = n.fitsInViewportVertically || a != null && a <= r,
          d = n.fitsInViewportHorizontally || s != null && s <= o;
        return c && d
      }
      return !1
    }
    _pushOverlayOnScreen(n, t, e) {
      if (this._previousPushAmount && this._positionLocked) return {
        x: n.x + this._previousPushAmount.x,
        y: n.y + this._previousPushAmount.y
      };
      let r = Bc(t),
        o = this._viewportRect,
        a = Math.max(n.x + r.width - o.width, 0),
        s = Math.max(n.y + r.height - o.height, 0),
        c = Math.max(o.top - e.top - n.y, 0),
        d = Math.max(o.left - e.left - n.x, 0),
        u = 0,
        x = 0;
      return r.width <= o.width ? u = d || -a : u = n.x < this._viewportMargin ? o.left - e.left - n.x : 0, r.height <= o.height ? x = c || -s : x = n.y < this._viewportMargin ? o.top - e.top - n.y : 0, this._previousPushAmount = {
        x: u,
        y: x
      }, {
        x: n.x + u,
        y: n.y + x
      }
    }
    _applyPosition(n, t) {
      if (this._setTransformOrigin(n), this._setOverlayElementStyles(t, n), this._setBoundingBoxStyles(t, n), n.panelClass && this._addPanelClasses(n.panelClass), this._positionChanges.observers.length) {
        let e = this._getScrollVisibility();
        if (n !== this._lastPosition || !this._lastScrollVisibility || !ef(this._lastScrollVisibility, e)) {
          let r = new jr(n, e);
          this._positionChanges.next(r)
        }
        this._lastScrollVisibility = e
      }
      this._lastPosition = n, this._isInitialRender = !1
    }
    _setTransformOrigin(n) {
      if (!this._transformOriginSelector) return;
      let t = this._boundingBox.querySelectorAll(this._transformOriginSelector),
        e, r = n.overlayY;
      n.overlayX === "center" ? e = "center" : this._isRtl() ? e = n.overlayX === "start" ? "right" : "left" : e = n.overlayX === "start" ? "left" : "right";
      for (let o = 0; o < t.length; o++) t[o].style.transformOrigin = `${e} ${r}`
    }
    _calculateBoundingBoxRect(n, t) {
      let e = this._viewportRect,
        r = this._isRtl(),
        o, a, s;
      if (t.overlayY === "top") a = n.y, o = e.height - a + this._viewportMargin;
      else if (t.overlayY === "bottom") s = e.height - n.y + this._viewportMargin * 2, o = e.height - s + this._viewportMargin;
      else {
        let B = Math.min(e.bottom - n.y + e.top, n.y),
          I = this._lastBoundingBoxSize.height;
        o = B * 2, a = n.y - B, o > I && !this._isInitialRender && !this._growAfterOpen && (a = n.y - I / 2)
      }
      let c = t.overlayX === "start" && !r || t.overlayX === "end" && r,
        d = t.overlayX === "end" && !r || t.overlayX === "start" && r,
        u, x, j;
      if (d) j = e.width - n.x + this._viewportMargin * 2, u = n.x - this._viewportMargin;
      else if (c) x = n.x, u = e.right - n.x;
      else {
        let B = Math.min(e.right - n.x + e.left, n.x),
          I = this._lastBoundingBoxSize.width;
        u = B * 2, x = n.x - B, u > I && !this._isInitialRender && !this._growAfterOpen && (x = n.x - I / 2)
      }
      return {
        top: a,
        left: x,
        bottom: s,
        right: j,
        width: u,
        height: o
      }
    }
    _setBoundingBoxStyles(n, t) {
      let e = this._calculateBoundingBoxRect(n, t);
      !this._isInitialRender && !this._growAfterOpen && (e.height = Math.min(e.height, this._lastBoundingBoxSize.height), e.width = Math.min(e.width, this._lastBoundingBoxSize.width));
      let r = {};
      if (this._hasExactPosition()) r.top = r.left = "0", r.bottom = r.right = r.maxHeight = r.maxWidth = "", r.width = r.height = "100%";
      else {
        let o = this._overlayRef.getConfig().maxHeight,
          a = this._overlayRef.getConfig().maxWidth;
        r.height = Y(e.height), r.top = Y(e.top), r.bottom = Y(e.bottom), r.width = Y(e.width), r.left = Y(e.left), r.right = Y(e.right), t.overlayX === "center" ? r.alignItems = "center" : r.alignItems = t.overlayX === "end" ? "flex-end" : "flex-start", t.overlayY === "center" ? r.justifyContent = "center" : r.justifyContent = t.overlayY === "bottom" ? "flex-end" : "flex-start", o && (r.maxHeight = Y(o)), a && (r.maxWidth = Y(a))
      }
      this._lastBoundingBoxSize = e, $e(this._boundingBox.style, r)
    }
    _resetBoundingBoxStyles() {
      $e(this._boundingBox.style, {
        top: "0",
        left: "0",
        right: "0",
        bottom: "0",
        height: "",
        width: "",
        alignItems: "",
        justifyContent: ""
      })
    }
    _resetOverlayElementStyles() {
      $e(this._pane.style, {
        top: "",
        left: "",
        bottom: "",
        right: "",
        position: "",
        transform: ""
      })
    }
    _setOverlayElementStyles(n, t) {
      let e = {},
        r = this._hasExactPosition(),
        o = this._hasFlexibleDimensions,
        a = this._overlayRef.getConfig();
      if (r) {
        let u = this._viewportRuler.getViewportScrollPosition();
        $e(e, this._getExactOverlayY(t, n, u)), $e(e, this._getExactOverlayX(t, n, u))
      } else e.position = "static";
      let s = "",
        c = this._getOffset(t, "x"),
        d = this._getOffset(t, "y");
      c && (s += `translateX(${c}px) `), d && (s += `translateY(${d}px)`), e.transform = s.trim(), a.maxHeight && (r ? e.maxHeight = Y(a.maxHeight) : o && (e.maxHeight = "")), a.maxWidth && (r ? e.maxWidth = Y(a.maxWidth) : o && (e.maxWidth = "")), $e(this._pane.style, e)
    }
    _getExactOverlayY(n, t, e) {
      let r = {
          top: "",
          bottom: ""
        },
        o = this._getOverlayPoint(t, this._overlayRect, n);
      if (this._isPushed && (o = this._pushOverlayOnScreen(o, this._overlayRect, e)), n.overlayY === "bottom") {
        let a = this._document.documentElement.clientHeight;
        r.bottom = `${a-(o.y+this._overlayRect.height)}px`
      } else r.top = Y(o.y);
      return r
    }
    _getExactOverlayX(n, t, e) {
      let r = {
          left: "",
          right: ""
        },
        o = this._getOverlayPoint(t, this._overlayRect, n);
      this._isPushed && (o = this._pushOverlayOnScreen(o, this._overlayRect, e));
      let a;
      if (this._isRtl() ? a = n.overlayX === "end" ? "left" : "right" : a = n.overlayX === "end" ? "right" : "left", a === "right") {
        let s = this._document.documentElement.clientWidth;
        r.right = `${s-(o.x+this._overlayRect.width)}px`
      } else r.left = Y(o.x);
      return r
    }
    _getScrollVisibility() {
      let n = this._getOriginRect(),
        t = this._pane.getBoundingClientRect(),
        e = this._scrollables.map(r => r.getElementRef().nativeElement.getBoundingClientRect());
      return {
        isOriginClipped: Pc(n, e),
        isOriginOutsideView: Ua(n, e),
        isOverlayClipped: Pc(t, e),
        isOverlayOutsideView: Ua(t, e)
      }
    }
    _subtractOverflows(n, ...t) {
      return t.reduce((e, r) => e - Math.max(r, 0), n)
    }
    _getNarrowedViewportRect() {
      let n = this._document.documentElement.clientWidth,
        t = this._document.documentElement.clientHeight,
        e = this._viewportRuler.getViewportScrollPosition();
      return {
        top: e.top + this._viewportMargin,
        left: e.left + this._viewportMargin,
        right: e.left + n - this._viewportMargin,
        bottom: e.top + t - this._viewportMargin,
        width: n - 2 * this._viewportMargin,
        height: t - 2 * this._viewportMargin
      }
    }
    _isRtl() {
      return this._overlayRef.getDirection() === "rtl"
    }
    _hasExactPosition() {
      return !this._hasFlexibleDimensions || this._isPushed
    }
    _getOffset(n, t) {
      return t === "x" ? n.offsetX == null ? this._offsetX : n.offsetX : n.offsetY == null ? this._offsetY : n.offsetY
    }
    _validatePositions() {}
    _addPanelClasses(n) {
      this._pane && wi(n).forEach(t => {
        t !== "" && this._appliedPanelClasses.indexOf(t) === -1 && (this._appliedPanelClasses.push(t), this._pane.classList.add(t))
      })
    }
    _clearPanelClasses() {
      this._pane && (this._appliedPanelClasses.forEach(n => {
        this._pane.classList.remove(n)
      }), this._appliedPanelClasses = [])
    }
    _getOriginRect() {
      let n = this._origin;
      if (n instanceof D) return n.nativeElement.getBoundingClientRect();
      if (n instanceof Element) return n.getBoundingClientRect();
      let t = n.width || 0,
        e = n.height || 0;
      return {
        top: n.y,
        bottom: n.y + e,
        left: n.x,
        right: n.x + t,
        height: e,
        width: t
      }
    }
  };
  zc = "cdk-global-overlay-wrapper";
  Ur = class {
    _overlayRef;
    _cssPosition = "static";
    _topOffset = "";
    _bottomOffset = "";
    _alignItems = "";
    _xPosition = "";
    _xOffset = "";
    _width = "";
    _height = "";
    _isDisposed = !1;
    attach(n) {
      let t = n.getConfig();
      this._overlayRef = n, this._width && !t.width && n.updateSize({
        width: this._width
      }), this._height && !t.height && n.updateSize({
        height: this._height
      }), n.hostElement.classList.add(zc), this._isDisposed = !1
    }
    top(n = "") {
      return this._bottomOffset = "", this._topOffset = n, this._alignItems = "flex-start", this
    }
    left(n = "") {
      return this._xOffset = n, this._xPosition = "left", this
    }
    bottom(n = "") {
      return this._topOffset = "", this._bottomOffset = n, this._alignItems = "flex-end", this
    }
    right(n = "") {
      return this._xOffset = n, this._xPosition = "right", this
    }
    start(n = "") {
      return this._xOffset = n, this._xPosition = "start", this
    }
    end(n = "") {
      return this._xOffset = n, this._xPosition = "end", this
    }
    width(n = "") {
      return this._overlayRef ? this._overlayRef.updateSize({
        width: n
      }) : this._width = n, this
    }
    height(n = "") {
      return this._overlayRef ? this._overlayRef.updateSize({
        height: n
      }) : this._height = n, this
    }
    centerHorizontally(n = "") {
      return this.left(n), this._xPosition = "center", this
    }
    centerVertically(n = "") {
      return this.top(n), this._alignItems = "center", this
    }
    apply() {
      if (!this._overlayRef || !this._overlayRef.hasAttached()) return;
      let n = this._overlayRef.overlayElement.style,
        t = this._overlayRef.hostElement.style,
        e = this._overlayRef.getConfig(),
        {
          width: r,
          height: o,
          maxWidth: a,
          maxHeight: s
        } = e,
        c = (r === "100%" || r === "100vw") && (!a || a === "100%" || a === "100vw"),
        d = (o === "100%" || o === "100vh") && (!s || s === "100%" || s === "100vh"),
        u = this._xPosition,
        x = this._xOffset,
        j = this._overlayRef.getConfig().direction === "rtl",
        B = "",
        I = "",
        V = "";
      c ? V = "flex-start" : u === "center" ? (V = "center", j ? I = x : B = x) : j ? u === "left" || u === "end" ? (V = "flex-end", B = x) : (u === "right" || u === "start") && (V = "flex-start", I = x) : u === "left" || u === "start" ? (V = "flex-start", B = x) : (u === "right" || u === "end") && (V = "flex-end", I = x), n.position = this._cssPosition, n.marginLeft = c ? "0" : B, n.marginTop = d ? "0" : this._topOffset, n.marginBottom = this._bottomOffset, n.marginRight = c ? "0" : I, t.justifyContent = V, t.alignItems = d ? "flex-start" : this._alignItems
    }
    dispose() {
      if (this._isDisposed || !this._overlayRef) return;
      let n = this._overlayRef.overlayElement.style,
        t = this._overlayRef.hostElement,
        e = t.style;
      t.classList.remove(zc), e.justifyContent = e.alignItems = n.marginTop = n.marginBottom = n.marginLeft = n.marginRight = n.position = "", this._overlayRef = null, this._isDisposed = !0
    }
  }, Kc = (() => {
    class i {
      _injector = l(N);
      constructor() {}
      global() {
        return $r()
      }
      flexibleConnectedTo(t) {
        return Ga(this._injector, t)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })();
  Zc = (() => {
    class i {
      scrollStrategies = l($c);
      _positionBuilder = l(Kc);
      _injector = l(N);
      constructor() {}
      create(t) {
        return Cn(this._injector, t)
      }
      position() {
        return this._positionBuilder
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), nf = [{
    originX: "start",
    originY: "bottom",
    overlayX: "start",
    overlayY: "top"
  }, {
    originX: "start",
    originY: "top",
    overlayX: "start",
    overlayY: "bottom"
  }, {
    originX: "end",
    originY: "top",
    overlayX: "end",
    overlayY: "bottom"
  }, {
    originX: "end",
    originY: "bottom",
    overlayX: "end",
    overlayY: "top"
  }], Xc = new v("cdk-connected-overlay-scroll-strategy", {
    providedIn: "root",
    factory: () => {
      let i = l(N);
      return () => Hr(i)
    }
  }), $a = (() => {
    class i {
      elementRef = l(D);
      constructor() {}
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdk-overlay-origin", ""],
          ["", "overlay-origin", ""],
          ["", "cdkOverlayOrigin", ""]
        ],
        exportAs: ["cdkOverlayOrigin"]
      })
    }
    return i
  })(), rf = (() => {
    class i {
      _dir = l(le, {
        optional: !0
      });
      _injector = l(N);
      _overlayRef;
      _templatePortal;
      _backdropSubscription = ft.EMPTY;
      _attachSubscription = ft.EMPTY;
      _detachSubscription = ft.EMPTY;
      _positionSubscription = ft.EMPTY;
      _offsetX;
      _offsetY;
      _position;
      _scrollStrategyFactory = l(Xc);
      _disposeOnNavigation = !1;
      _ngZone = l(E);
      origin;
      positions;
      positionStrategy;
      get offsetX() {
        return this._offsetX
      }
      set offsetX(t) {
        this._offsetX = t, this._position && this._updatePositionStrategy(this._position)
      }
      get offsetY() {
        return this._offsetY
      }
      set offsetY(t) {
        this._offsetY = t, this._position && this._updatePositionStrategy(this._position)
      }
      width;
      height;
      minWidth;
      minHeight;
      backdropClass;
      panelClass;
      viewportMargin = 0;
      scrollStrategy;
      open = !1;
      disableClose = !1;
      transformOriginSelector;
      hasBackdrop = !1;
      lockPosition = !1;
      flexibleDimensions = !1;
      growAfterOpen = !1;
      push = !1;
      get disposeOnNavigation() {
        return this._disposeOnNavigation
      }
      set disposeOnNavigation(t) {
        this._disposeOnNavigation = t
      }
      backdropClick = new A;
      positionChange = new A;
      attach = new A;
      detach = new A;
      overlayKeydown = new A;
      overlayOutsideClick = new A;
      constructor() {
        let t = l(Oe),
          e = l(me);
        this._templatePortal = new Ce(t, e), this.scrollStrategy = this._scrollStrategyFactory()
      }
      get overlayRef() {
        return this._overlayRef
      }
      get dir() {
        return this._dir ? this._dir.value : "ltr"
      }
      ngOnDestroy() {
        this._attachSubscription.unsubscribe(), this._detachSubscription.unsubscribe(), this._backdropSubscription.unsubscribe(), this._positionSubscription.unsubscribe(), this._overlayRef?.dispose()
      }
      ngOnChanges(t) {
        this._position && (this._updatePositionStrategy(this._position), this._overlayRef?.updateSize({
          width: this.width,
          minWidth: this.minWidth,
          height: this.height,
          minHeight: this.minHeight
        }), t.origin && this.open && this._position.apply()), t.open && (this.open ? this.attachOverlay() : this.detachOverlay())
      }
      _createOverlay() {
        (!this.positions || !this.positions.length) && (this.positions = nf);
        let t = this._overlayRef = Cn(this._injector, this._buildConfig());
        this._attachSubscription = t.attachments().subscribe(() => this.attach.emit()), this._detachSubscription = t.detachments().subscribe(() => this.detach.emit()), t.keydownEvents().subscribe(e => {
          this.overlayKeydown.next(e), e.keyCode === 27 && !this.disableClose && !Nr(e) && (e.preventDefault(), this.detachOverlay())
        }), this._overlayRef.outsidePointerEvents().subscribe(e => {
          let r = this._getOriginElement(),
            o = xt(e);
          (!r || r !== o && !r.contains(o)) && this.overlayOutsideClick.next(e)
        })
      }
      _buildConfig() {
        let t = this._position = this.positionStrategy || this._createPositionStrategy(),
          e = new We({
            direction: this._dir || "ltr",
            positionStrategy: t,
            scrollStrategy: this.scrollStrategy,
            hasBackdrop: this.hasBackdrop,
            disposeOnNavigation: this.disposeOnNavigation
          });
        return (this.width || this.width === 0) && (e.width = this.width), (this.height || this.height === 0) && (e.height = this.height), (this.minWidth || this.minWidth === 0) && (e.minWidth = this.minWidth), (this.minHeight || this.minHeight === 0) && (e.minHeight = this.minHeight), this.backdropClass && (e.backdropClass = this.backdropClass), this.panelClass && (e.panelClass = this.panelClass), e
      }
      _updatePositionStrategy(t) {
        let e = this.positions.map(r => ({
          originX: r.originX,
          originY: r.originY,
          overlayX: r.overlayX,
          overlayY: r.overlayY,
          offsetX: r.offsetX || this.offsetX,
          offsetY: r.offsetY || this.offsetY,
          panelClass: r.panelClass || void 0
        }));
        return t.setOrigin(this._getOrigin()).withPositions(e).withFlexibleDimensions(this.flexibleDimensions).withPush(this.push).withGrowAfterOpen(this.growAfterOpen).withViewportMargin(this.viewportMargin).withLockedPosition(this.lockPosition).withTransformOriginOn(this.transformOriginSelector)
      }
      _createPositionStrategy() {
        let t = Ga(this._injector, this._getOrigin());
        return this._updatePositionStrategy(t), t
      }
      _getOrigin() {
        return this.origin instanceof $a ? this.origin.elementRef : this.origin
      }
      _getOriginElement() {
        return this.origin instanceof $a ? this.origin.elementRef.nativeElement : this.origin instanceof D ? this.origin.nativeElement : typeof Element < "u" && this.origin instanceof Element ? this.origin : null
      }
      attachOverlay() {
        this._overlayRef ? this._overlayRef.getConfig().hasBackdrop = this.hasBackdrop : this._createOverlay(), this._overlayRef.hasAttached() || this._overlayRef.attach(this._templatePortal), this.hasBackdrop ? this._backdropSubscription = this._overlayRef.backdropClick().subscribe(t => {
          this.backdropClick.emit(t)
        }) : this._backdropSubscription.unsubscribe(), this._positionSubscription.unsubscribe(), this.positionChange.observers.length > 0 && (this._positionSubscription = this._position.positionChanges.pipe(Gs(() => this.positionChange.observers.length > 0)).subscribe(t => {
          this._ngZone.run(() => this.positionChange.emit(t)), this.positionChange.observers.length === 0 && this._positionSubscription.unsubscribe()
        })), this.open = !0
      }
      detachOverlay() {
        this._overlayRef?.detach(), this._backdropSubscription.unsubscribe(), this._positionSubscription.unsubscribe(), this.open = !1
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdk-connected-overlay", ""],
          ["", "connected-overlay", ""],
          ["", "cdkConnectedOverlay", ""]
        ],
        inputs: {
          origin: [0, "cdkConnectedOverlayOrigin", "origin"],
          positions: [0, "cdkConnectedOverlayPositions", "positions"],
          positionStrategy: [0, "cdkConnectedOverlayPositionStrategy", "positionStrategy"],
          offsetX: [0, "cdkConnectedOverlayOffsetX", "offsetX"],
          offsetY: [0, "cdkConnectedOverlayOffsetY", "offsetY"],
          width: [0, "cdkConnectedOverlayWidth", "width"],
          height: [0, "cdkConnectedOverlayHeight", "height"],
          minWidth: [0, "cdkConnectedOverlayMinWidth", "minWidth"],
          minHeight: [0, "cdkConnectedOverlayMinHeight", "minHeight"],
          backdropClass: [0, "cdkConnectedOverlayBackdropClass", "backdropClass"],
          panelClass: [0, "cdkConnectedOverlayPanelClass", "panelClass"],
          viewportMargin: [0, "cdkConnectedOverlayViewportMargin", "viewportMargin"],
          scrollStrategy: [0, "cdkConnectedOverlayScrollStrategy", "scrollStrategy"],
          open: [0, "cdkConnectedOverlayOpen", "open"],
          disableClose: [0, "cdkConnectedOverlayDisableClose", "disableClose"],
          transformOriginSelector: [0, "cdkConnectedOverlayTransformOriginOn", "transformOriginSelector"],
          hasBackdrop: [2, "cdkConnectedOverlayHasBackdrop", "hasBackdrop", F],
          lockPosition: [2, "cdkConnectedOverlayLockPosition", "lockPosition", F],
          flexibleDimensions: [2, "cdkConnectedOverlayFlexibleDimensions", "flexibleDimensions", F],
          growAfterOpen: [2, "cdkConnectedOverlayGrowAfterOpen", "growAfterOpen", F],
          push: [2, "cdkConnectedOverlayPush", "push", F],
          disposeOnNavigation: [2, "cdkConnectedOverlayDisposeOnNavigation", "disposeOnNavigation", F]
        },
        outputs: {
          backdropClick: "backdropClick",
          positionChange: "positionChange",
          attach: "attach",
          detach: "detach",
          overlayKeydown: "overlayKeydown",
          overlayOutsideClick: "overlayOutsideClick"
        },
        exportAs: ["cdkConnectedOverlay"],
        features: [mt]
      })
    }
    return i
  })();
  af = {
    provide: Xc,
    useFactory: of
  }, qa = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        providers: [Zc, af],
        imports: [ye, Fr, Fa, Fa]
      })
    }
    return i
  })()
});
var Qc = _(() => {
  Ya();
  Ya();
  Na()
});

function sf(i, n) {
  if (!Jc.has(i)) try {
    Ge || (Ge = document.createElement("style"), n && Ge.setAttribute("nonce", n), Ge.setAttribute("type", "text/css"), document.head.appendChild(Ge)), Ge.sheet && (Ge.sheet.insertRule(`@media ${i} {body{ }}`, 0), Jc.add(i))
  } catch (t) {
    console.error(t)
  }
}

function lf(i) {
  return {
    matches: i === "all" || i === "",
    media: i,
    addListener: () => {},
    removeListener: () => {}
  }
}

function td(i) {
  return i.map(n => n.split(",")).reduce((n, t) => n.concat(t)).map(n => n.trim())
}
var Jc, Ge, Wr, xn, Ka = _(() => {
  f();
  f();
  nt();
  ht();
  se();
  Oa();
  Jc = new Set, Wr = (() => {
    class i {
      _platform = l(T);
      _nonce = l(Qs, {
        optional: !0
      });
      _matchMedia;
      constructor() {
        this._matchMedia = this._platform.isBrowser && window.matchMedia ? window.matchMedia.bind(window) : lf
      }
      matchMedia(t) {
        return (this._platform.WEBKIT || this._platform.BLINK) && sf(t, this._nonce), this._matchMedia(t)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })();
  xn = (() => {
    class i {
      _mediaMatcher = l(Wr);
      _zone = l(E);
      _queries = new Map;
      _destroySubject = new y;
      constructor() {}
      ngOnDestroy() {
        this._destroySubject.next(), this._destroySubject.complete()
      }
      isMatched(t) {
        return td(wi(t)).some(r => this._registerQuery(r).mql.matches)
      }
      observe(t) {
        let r = td(wi(t)).map(a => this._registerQuery(a).observable),
          o = Ke(r);
        return o = Ae(o.pipe(yt(1)), o.pipe(zn(1), Xe(0))), o.pipe(b(a => {
          let s = {
            matches: !1,
            breakpoints: {}
          };
          return a.forEach(({
            matches: c,
            query: d
          }) => {
            s.matches = s.matches || c, s.breakpoints[d] = c
          }), s
        }))
      }
      _registerQuery(t) {
        if (this._queries.has(t)) return this._queries.get(t);
        let e = this._mediaMatcher.matchMedia(t),
          o = {
            observable: new Yt(a => {
              let s = c => this._zone.run(() => a.next(c));
              return e.addListener(s), () => {
                e.removeListener(s)
              }
            }).pipe(Ie(e), b(({
              matches: a
            }) => ({
              query: t,
              matches: a
            })), Dt(this._destroySubject)),
            mql: e
          };
        return this._queries.set(t, o), o
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});
var fy, ed, Za = _(() => {
  f();
  Ka();
  fy = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })(), ed = {
    XSmall: "(max-width: 599.98px)",
    Small: "(min-width: 600px) and (max-width: 959.98px)",
    Medium: "(min-width: 960px) and (max-width: 1279.98px)",
    Large: "(min-width: 1280px) and (max-width: 1919.98px)",
    XLarge: "(min-width: 1920px)",
    Handset: "(max-width: 599.98px) and (orientation: portrait), (max-width: 959.98px) and (orientation: landscape)",
    Tablet: "(min-width: 600px) and (max-width: 839.98px) and (orientation: portrait), (min-width: 960px) and (max-width: 1279.98px) and (orientation: landscape)",
    Web: "(min-width: 840px) and (orientation: portrait), (min-width: 1280px) and (orientation: landscape)",
    HandsetPortrait: "(max-width: 599.98px) and (orientation: portrait)",
    TabletPortrait: "(min-width: 600px) and (max-width: 839.98px) and (orientation: portrait)",
    WebPortrait: "(min-width: 840px) and (orientation: portrait)",
    HandsetLandscape: "(max-width: 959.98px) and (orientation: landscape)",
    TabletLandscape: "(min-width: 960px) and (max-width: 1279.98px) and (orientation: landscape)",
    WebLandscape: "(min-width: 1280px) and (orientation: landscape)"
  }
});

function cf() {
  if (Gr === void 0 && (Gr = null, typeof window < "u")) {
    let i = window;
    i.trustedTypes !== void 0 && (Gr = i.trustedTypes.createPolicy("angular#components", {
      createHTML: n => n
    }))
  }
  return Gr
}

function wn(i) {
  return cf()?.createHTML(i) || i
}

function id(i) {
  return Error(`Unable to find icon with the name "${i}"`)
}

function df() {
  return Error("Could not find HttpClient for use with Angular Material icons. Please add provideHttpClient() to your providers.")
}

function nd(i) {
  return Error(`The URL provided to MatIconRegistry was not trusted as a resource URL via Angular's DomSanitizer. Attempted URL was "${i}".`)
}

function rd(i) {
  return Error(`The literal provided to MatIconRegistry was not trusted as safe HTML by Angular's DomSanitizer. Attempted literal was "${i}".`)
}

function qr(i) {
  return i.cloneNode(!0)
}

function od(i, n) {
  return i + ":" + n
}

function uf(i) {
  return !!(i.url && i.options)
}
var Gr, ce, ad, sd = _(() => {
  Uo();
  f();
  f();
  El();
  nt();
  ht();
  ce = class {
    url;
    svgText;
    options;
    svgElement;
    constructor(n, t, e) {
      this.url = n, this.svgText = t, this.options = e
    }
  }, ad = (() => {
    class i {
      _httpClient;
      _sanitizer;
      _errorHandler;
      _document;
      _svgIconConfigs = new Map;
      _iconSetConfigs = new Map;
      _cachedIconsByUrl = new Map;
      _inProgressUrlFetches = new Map;
      _fontCssClassesByAlias = new Map;
      _resolvers = [];
      _defaultFontSetClass = ["material-icons", "mat-ligature-font"];
      constructor(t, e, r, o) {
        this._httpClient = t, this._sanitizer = e, this._errorHandler = o, this._document = r
      }
      addSvgIcon(t, e, r) {
        return this.addSvgIconInNamespace("", t, e, r)
      }
      addSvgIconLiteral(t, e, r) {
        return this.addSvgIconLiteralInNamespace("", t, e, r)
      }
      addSvgIconInNamespace(t, e, r, o) {
        return this._addSvgIconConfig(t, e, new ce(r, null, o))
      }
      addSvgIconResolver(t) {
        return this._resolvers.push(t), this
      }
      addSvgIconLiteralInNamespace(t, e, r, o) {
        let a = this._sanitizer.sanitize(ti.HTML, r);
        if (!a) throw rd(r);
        let s = wn(a);
        return this._addSvgIconConfig(t, e, new ce("", s, o))
      }
      addSvgIconSet(t, e) {
        return this.addSvgIconSetInNamespace("", t, e)
      }
      addSvgIconSetLiteral(t, e) {
        return this.addSvgIconSetLiteralInNamespace("", t, e)
      }
      addSvgIconSetInNamespace(t, e, r) {
        return this._addSvgIconSetConfig(t, new ce(e, null, r))
      }
      addSvgIconSetLiteralInNamespace(t, e, r) {
        let o = this._sanitizer.sanitize(ti.HTML, e);
        if (!o) throw rd(e);
        let a = wn(o);
        return this._addSvgIconSetConfig(t, new ce("", a, r))
      }
      registerFontClassAlias(t, e = t) {
        return this._fontCssClassesByAlias.set(t, e), this
      }
      classNameForFontAlias(t) {
        return this._fontCssClassesByAlias.get(t) || t
      }
      setDefaultFontSetClass(...t) {
        return this._defaultFontSetClass = t, this
      }
      getDefaultFontSetClass() {
        return this._defaultFontSetClass
      }
      getSvgIconFromUrl(t) {
        let e = this._sanitizer.sanitize(ti.RESOURCE_URL, t);
        if (!e) throw nd(t);
        let r = this._cachedIconsByUrl.get(e);
        return r ? g(qr(r)) : this._loadSvgIconFromConfig(new ce(t, null)).pipe(W(o => this._cachedIconsByUrl.set(e, o)), b(o => qr(o)))
      }
      getNamedSvgIcon(t, e = "") {
        let r = od(e, t),
          o = this._svgIconConfigs.get(r);
        if (o) return this._getSvgFromConfig(o);
        if (o = this._getIconConfigFromResolvers(e, t), o) return this._svgIconConfigs.set(r, o), this._getSvgFromConfig(o);
        let a = this._iconSetConfigs.get(e);
        return a ? this._getSvgFromIconSetConfigs(t, a) : Re(id(r))
      }
      ngOnDestroy() {
        this._resolvers = [], this._svgIconConfigs.clear(), this._iconSetConfigs.clear(), this._cachedIconsByUrl.clear()
      }
      _getSvgFromConfig(t) {
        return t.svgText ? g(qr(this._svgElementFromConfig(t))) : this._loadSvgIconFromConfig(t).pipe(b(e => qr(e)))
      }
      _getSvgFromIconSetConfigs(t, e) {
        let r = this._extractIconWithNameFromAnySet(t, e);
        if (r) return g(r);
        let o = e.filter(a => !a.svgText).map(a => this._loadSvgIconSetFromConfig(a).pipe(at(s => {
          let d = `Loading icon set URL: ${this._sanitizer.sanitize(ti.RESOURCE_URL,a.url)} failed: ${s.message}`;
          return this._errorHandler.handleError(new Error(d)), g(null)
        })));
        return Ze(o).pipe(b(() => {
          let a = this._extractIconWithNameFromAnySet(t, e);
          if (!a) throw id(t);
          return a
        }))
      }
      _extractIconWithNameFromAnySet(t, e) {
        for (let r = e.length - 1; r >= 0; r--) {
          let o = e[r];
          if (o.svgText && o.svgText.toString().indexOf(t) > -1) {
            let a = this._svgElementFromConfig(o),
              s = this._extractSvgIconFromSet(a, t, o.options);
            if (s) return s
          }
        }
        return null
      }
      _loadSvgIconFromConfig(t) {
        return this._fetchIcon(t).pipe(W(e => t.svgText = e), b(() => this._svgElementFromConfig(t)))
      }
      _loadSvgIconSetFromConfig(t) {
        return t.svgText ? g(null) : this._fetchIcon(t).pipe(W(e => t.svgText = e))
      }
      _extractSvgIconFromSet(t, e, r) {
        let o = t.querySelector(`[id="${e}"]`);
        if (!o) return null;
        let a = o.cloneNode(!0);
        if (a.removeAttribute("id"), a.nodeName.toLowerCase() === "svg") return this._setSvgAttributes(a, r);
        if (a.nodeName.toLowerCase() === "symbol") return this._setSvgAttributes(this._toSvgElement(a), r);
        let s = this._svgElementFromString(wn("<svg></svg>"));
        return s.appendChild(a), this._setSvgAttributes(s, r)
      }
      _svgElementFromString(t) {
        let e = this._document.createElement("DIV");
        e.innerHTML = t;
        let r = e.querySelector("svg");
        if (!r) throw Error("<svg> tag not found");
        return r
      }
      _toSvgElement(t) {
        let e = this._svgElementFromString(wn("<svg></svg>")),
          r = t.attributes;
        for (let o = 0; o < r.length; o++) {
          let {
            name: a,
            value: s
          } = r[o];
          a !== "id" && e.setAttribute(a, s)
        }
        for (let o = 0; o < t.childNodes.length; o++) t.childNodes[o].nodeType === this._document.ELEMENT_NODE && e.appendChild(t.childNodes[o].cloneNode(!0));
        return e
      }
      _setSvgAttributes(t, e) {
        return t.setAttribute("fit", ""), t.setAttribute("height", "100%"), t.setAttribute("width", "100%"), t.setAttribute("preserveAspectRatio", "xMidYMid meet"), t.setAttribute("focusable", "false"), e && e.viewBox && t.setAttribute("viewBox", e.viewBox), t
      }
      _fetchIcon(t) {
        let {
          url: e,
          options: r
        } = t, o = r?.withCredentials ?? !1;
        if (!this._httpClient) throw df();
        if (e == null) throw Error(`Cannot fetch icon from URL "${e}".`);
        let a = this._sanitizer.sanitize(ti.RESOURCE_URL, e);
        if (!a) throw nd(e);
        let s = this._inProgressUrlFetches.get(a);
        if (s) return s;
        let c = this._httpClient.get(a, {
          responseType: "text",
          withCredentials: o
        }).pipe(b(d => wn(d)), Qe(() => this._inProgressUrlFetches.delete(a)), Ws());
        return this._inProgressUrlFetches.set(a, c), c
      }
      _addSvgIconConfig(t, e, r) {
        return this._svgIconConfigs.set(od(t, e), r), this
      }
      _addSvgIconSetConfig(t, e) {
        let r = this._iconSetConfigs.get(t);
        return r ? r.push(e) : this._iconSetConfigs.set(t, [e]), this
      }
      _svgElementFromConfig(t) {
        if (!t.svgElement) {
          let e = this._svgElementFromString(t.svgText);
          this._setSvgAttributes(e, t.options), t.svgElement = e
        }
        return t.svgElement
      }
      _getIconConfigFromResolvers(t, e) {
        for (let r = 0; r < this._resolvers.length; r++) {
          let o = this._resolvers[r](e, t);
          if (o) return uf(o) ? new ce(o.url, null, o.options) : new ce(o, null)
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)(G(ni, 8), G(wl), G(O, 8), G(zi))
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});

function En(i) {
  return i.buttons === 0 || i.detail === 0
}

function Sn(i) {
  let n = i.touches && i.touches[0] || i.changedTouches && i.changedTouches[0];
  return !!n && n.identifier === -1 && (n.radiusX == null || n.radiusX === 1) && (n.radiusY == null || n.radiusY === 1)
}
var Xa = _(() => {});

function ld() {
  if (Dn == null && typeof window < "u") try {
    window.addEventListener("test", null, Object.defineProperty({}, "passive", {
      get: () => Dn = !0
    }))
  } finally {
    Dn = Dn || !1
  }
  return Dn
}

function Ai(i) {
  return ld() ? i : !!i.capture
}
var Dn, Qa = _(() => {});
var cd, dd, ud, Ja, hd, Rn, md, Yr, Kr, hf, fd = _(() => {
  f();
  f();
  nt();
  ht();
  Xa();
  fn();
  se();
  Qa();
  Ei();
  cd = new v("cdk-input-modality-detector-options"), dd = {
    ignoreKeys: [18, 17, 224, 91, 16]
  }, ud = 650, Ja = {
    passive: !0,
    capture: !0
  }, hd = (() => {
    class i {
      _platform = l(T);
      _listenerCleanups;
      modalityDetected;
      modalityChanged;
      get mostRecentModality() {
        return this._modality.value
      }
      _mostRecentTarget = null;
      _modality = new Et(null);
      _options;
      _lastTouchMs = 0;
      _onKeydown = t => {
        this._options?.ignoreKeys?.some(e => e === t.keyCode) || (this._modality.next("keyboard"), this._mostRecentTarget = xt(t))
      };
      _onMousedown = t => {
        Date.now() - this._lastTouchMs < ud || (this._modality.next(En(t) ? "keyboard" : "mouse"), this._mostRecentTarget = xt(t))
      };
      _onTouchstart = t => {
        if (Sn(t)) {
          this._modality.next("keyboard");
          return
        }
        this._lastTouchMs = Date.now(), this._modality.next("touch"), this._mostRecentTarget = xt(t)
      };
      constructor() {
        let t = l(E),
          e = l(O),
          r = l(cd, {
            optional: !0
          });
        if (this._options = h(h({}, dd), r), this.modalityDetected = this._modality.pipe(zn(1)), this.modalityChanged = this.modalityDetected.pipe(ko()), this._platform.isBrowser) {
          let o = l(kt).createRenderer(null, null);
          this._listenerCleanups = t.runOutsideAngular(() => [o.listen(e, "keydown", this._onKeydown, Ja), o.listen(e, "mousedown", this._onMousedown, Ja), o.listen(e, "touchstart", this._onTouchstart, Ja)])
        }
      }
      ngOnDestroy() {
        this._modality.complete(), this._listenerCleanups?.forEach(t => t())
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Rn = (function(i) {
    return i[i.IMMEDIATE = 0] = "IMMEDIATE", i[i.EVENTUAL = 1] = "EVENTUAL", i
  })(Rn || {}), md = new v("cdk-focus-monitor-default-options"), Yr = Ai({
    passive: !0,
    capture: !0
  }), Kr = (() => {
    class i {
      _ngZone = l(E);
      _platform = l(T);
      _inputModalityDetector = l(hd);
      _origin = null;
      _lastFocusOrigin;
      _windowFocused = !1;
      _windowFocusTimeoutId;
      _originTimeoutId;
      _originFromTouchInteraction = !1;
      _elementInfo = new Map;
      _monitoredElementCount = 0;
      _rootNodeFocusListenerCount = new Map;
      _detectionMode;
      _windowFocusListener = () => {
        this._windowFocused = !0, this._windowFocusTimeoutId = setTimeout(() => this._windowFocused = !1)
      };
      _document = l(O);
      _stopInputModalityDetector = new y;
      constructor() {
        let t = l(md, {
          optional: !0
        });
        this._detectionMode = t?.detectionMode || Rn.IMMEDIATE
      }
      _rootNodeFocusAndBlurListener = t => {
        let e = xt(t);
        for (let r = e; r; r = r.parentElement) t.type === "focus" ? this._onFocus(t, r) : this._onBlur(t, r)
      };
      monitor(t, e = !1) {
        let r = wt(t);
        if (!this._platform.isBrowser || r.nodeType !== 1) return g();
        let o = Ra(r) || this._document,
          a = this._elementInfo.get(r);
        if (a) return e && (a.checkChildren = !0), a.subject;
        let s = {
          checkChildren: e,
          subject: new y,
          rootNode: o
        };
        return this._elementInfo.set(r, s), this._registerGlobalListeners(s), s.subject
      }
      stopMonitoring(t) {
        let e = wt(t),
          r = this._elementInfo.get(e);
        r && (r.subject.complete(), this._setClasses(e), this._elementInfo.delete(e), this._removeGlobalListeners(r))
      }
      focusVia(t, e, r) {
        let o = wt(t),
          a = this._document.activeElement;
        o === a ? this._getClosestElementsInfo(o).forEach(([s, c]) => this._originChanged(s, e, c)) : (this._setOrigin(e), typeof o.focus == "function" && o.focus(r))
      }
      ngOnDestroy() {
        this._elementInfo.forEach((t, e) => this.stopMonitoring(e))
      }
      _getWindow() {
        return this._document.defaultView || window
      }
      _getFocusOrigin(t) {
        return this._origin ? this._originFromTouchInteraction ? this._shouldBeAttributedToTouch(t) ? "touch" : "program" : this._origin : this._windowFocused && this._lastFocusOrigin ? this._lastFocusOrigin : t && this._isLastInteractionFromInputLabel(t) ? "mouse" : "program"
      }
      _shouldBeAttributedToTouch(t) {
        return this._detectionMode === Rn.EVENTUAL || !!t?.contains(this._inputModalityDetector._mostRecentTarget)
      }
      _setClasses(t, e) {
        t.classList.toggle("cdk-focused", !!e), t.classList.toggle("cdk-touch-focused", e === "touch"), t.classList.toggle("cdk-keyboard-focused", e === "keyboard"), t.classList.toggle("cdk-mouse-focused", e === "mouse"), t.classList.toggle("cdk-program-focused", e === "program")
      }
      _setOrigin(t, e = !1) {
        this._ngZone.runOutsideAngular(() => {
          if (this._origin = t, this._originFromTouchInteraction = t === "touch" && e, this._detectionMode === Rn.IMMEDIATE) {
            clearTimeout(this._originTimeoutId);
            let r = this._originFromTouchInteraction ? ud : 1;
            this._originTimeoutId = setTimeout(() => this._origin = null, r)
          }
        })
      }
      _onFocus(t, e) {
        let r = this._elementInfo.get(e),
          o = xt(t);
        !r || !r.checkChildren && e !== o || this._originChanged(e, this._getFocusOrigin(o), r)
      }
      _onBlur(t, e) {
        let r = this._elementInfo.get(e);
        !r || r.checkChildren && t.relatedTarget instanceof Node && e.contains(t.relatedTarget) || (this._setClasses(e), this._emitOrigin(r, null))
      }
      _emitOrigin(t, e) {
        t.subject.observers.length && this._ngZone.run(() => t.subject.next(e))
      }
      _registerGlobalListeners(t) {
        if (!this._platform.isBrowser) return;
        let e = t.rootNode,
          r = this._rootNodeFocusListenerCount.get(e) || 0;
        r || this._ngZone.runOutsideAngular(() => {
          e.addEventListener("focus", this._rootNodeFocusAndBlurListener, Yr), e.addEventListener("blur", this._rootNodeFocusAndBlurListener, Yr)
        }), this._rootNodeFocusListenerCount.set(e, r + 1), ++this._monitoredElementCount === 1 && (this._ngZone.runOutsideAngular(() => {
          this._getWindow().addEventListener("focus", this._windowFocusListener)
        }), this._inputModalityDetector.modalityDetected.pipe(Dt(this._stopInputModalityDetector)).subscribe(o => {
          this._setOrigin(o, !0)
        }))
      }
      _removeGlobalListeners(t) {
        let e = t.rootNode;
        if (this._rootNodeFocusListenerCount.has(e)) {
          let r = this._rootNodeFocusListenerCount.get(e);
          r > 1 ? this._rootNodeFocusListenerCount.set(e, r - 1) : (e.removeEventListener("focus", this._rootNodeFocusAndBlurListener, Yr), e.removeEventListener("blur", this._rootNodeFocusAndBlurListener, Yr), this._rootNodeFocusListenerCount.delete(e))
        }--this._monitoredElementCount || (this._getWindow().removeEventListener("focus", this._windowFocusListener), this._stopInputModalityDetector.next(), clearTimeout(this._windowFocusTimeoutId), clearTimeout(this._originTimeoutId))
      }
      _originChanged(t, e, r) {
        this._setClasses(t, e), this._emitOrigin(r, e), this._lastFocusOrigin = e
      }
      _getClosestElementsInfo(t) {
        let e = [];
        return this._elementInfo.forEach((r, o) => {
          (o === t || r.checkChildren && o.contains(t)) && e.push([o, r])
        }), e
      }
      _isLastInteractionFromInputLabel(t) {
        let {
          _mostRecentTarget: e,
          mostRecentModality: r
        } = this._inputModalityDetector;
        if (r !== "mouse" || !e || e === t || t.nodeName !== "INPUT" && t.nodeName !== "TEXTAREA" || t.disabled) return !1;
        let o = t.labels;
        if (o) {
          for (let a = 0; a < o.length; a++)
            if (o[a].contains(e)) return !0
        }
        return !1
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), hf = (() => {
    class i {
      _elementRef = l(D);
      _focusMonitor = l(Kr);
      _monitorSubscription;
      _focusOrigin = null;
      cdkFocusChange = new A;
      constructor() {}
      get focusOrigin() {
        return this._focusOrigin
      }
      ngAfterViewInit() {
        let t = this._elementRef.nativeElement;
        this._monitorSubscription = this._focusMonitor.monitor(t, t.nodeType === 1 && t.hasAttribute("cdkMonitorSubtreeFocus")).subscribe(e => {
          this._focusOrigin = e, this.cdkFocusChange.emit(e)
        })
      }
      ngOnDestroy() {
        this._focusMonitor.stopMonitoring(this._elementRef), this._monitorSubscription && this._monitorSubscription.unsubscribe()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdkMonitorElementFocus", ""],
          ["", "cdkMonitorSubtreeFocus", ""]
        ],
        outputs: {
          cdkFocusChange: "cdkFocusChange"
        },
        exportAs: ["cdkMonitorFocus"]
      })
    }
    return i
  })()
});
var Zr, An = _(() => {
  xi();
  f();
  Zr = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["ng-component"]
        ],
        exportAs: ["cdkVisuallyHidden"],
        decls: 0,
        vars: 0,
        template: function(e, r) {},
        styles: [`.cdk-visually-hidden{border:0;clip:rect(0 0 0 0);height:1px;margin:-1px;overflow:hidden;padding:0;position:absolute;width:1px;white-space:nowrap;outline:0;-webkit-appearance:none;-moz-appearance:none;left:0}[dir=rtl] .cdk-visually-hidden{left:auto;right:0}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })()
});

function mf(i) {
  if (i.type === "characterData" && i.target instanceof Comment) return !0;
  if (i.type === "childList") {
    for (let n = 0; n < i.addedNodes.length; n++)
      if (!(i.addedNodes[n] instanceof Comment)) return !1;
    for (let n = 0; n < i.removedNodes.length; n++)
      if (!(i.removedNodes[n] instanceof Comment)) return !1;
    return !0
  }
  return !1
}
var pd, gd, iC, Xr, ts = _(() => {
  f();
  f();
  nt();
  ht();
  Ei();
  pd = (() => {
    class i {
      create(t) {
        return typeof MutationObserver > "u" ? null : new MutationObserver(t)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), gd = (() => {
    class i {
      _mutationObserverFactory = l(pd);
      _observedElements = new Map;
      _ngZone = l(E);
      constructor() {}
      ngOnDestroy() {
        this._observedElements.forEach((t, e) => this._cleanupObserver(e))
      }
      observe(t) {
        let e = wt(t);
        return new Yt(r => {
          let a = this._observeElement(e).pipe(b(s => s.filter(c => !mf(c))), K(s => !!s.length)).subscribe(s => {
            this._ngZone.run(() => {
              r.next(s)
            })
          });
          return () => {
            a.unsubscribe(), this._unobserveElement(e)
          }
        })
      }
      _observeElement(t) {
        return this._ngZone.runOutsideAngular(() => {
          if (this._observedElements.has(t)) this._observedElements.get(t).count++;
          else {
            let e = new y,
              r = this._mutationObserverFactory.create(o => e.next(o));
            r && r.observe(t, {
              characterData: !0,
              childList: !0,
              subtree: !0
            }), this._observedElements.set(t, {
              observer: r,
              stream: e,
              count: 1
            })
          }
          return this._observedElements.get(t).stream
        })
      }
      _unobserveElement(t) {
        this._observedElements.has(t) && (this._observedElements.get(t).count--, this._observedElements.get(t).count || this._cleanupObserver(t))
      }
      _cleanupObserver(t) {
        if (this._observedElements.has(t)) {
          let {
            observer: e,
            stream: r
          } = this._observedElements.get(t);
          e && e.disconnect(), r.complete(), this._observedElements.delete(t)
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), iC = (() => {
    class i {
      _contentObserver = l(gd);
      _elementRef = l(D);
      event = new A;
      get disabled() {
        return this._disabled
      }
      set disabled(t) {
        this._disabled = t, this._disabled ? this._unsubscribe() : this._subscribe()
      }
      _disabled = !1;
      get debounce() {
        return this._debounce
      }
      set debounce(t) {
        this._debounce = pn(t), this._subscribe()
      }
      _debounce;
      _currentSubscription = null;
      constructor() {}
      ngAfterContentInit() {
        !this._currentSubscription && !this.disabled && this._subscribe()
      }
      ngOnDestroy() {
        this._unsubscribe()
      }
      _subscribe() {
        this._unsubscribe();
        let t = this._contentObserver.observe(this._elementRef);
        this._currentSubscription = (this.debounce ? t.pipe(Xe(this.debounce)) : t).subscribe(this.event)
      }
      _unsubscribe() {
        this._currentSubscription?.unsubscribe()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdkObserveContent", ""]
        ],
        inputs: {
          disabled: [2, "cdkObserveContentDisabled", "disabled", F],
          debounce: "debounce"
        },
        outputs: {
          event: "cdkObserveContent"
        },
        exportAs: ["cdkObserveContent"]
      })
    }
    return i
  })(), Xr = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        providers: [pd]
      })
    }
    return i
  })()
});

function ff(i) {
  try {
    return i.frameElement
  } catch {
    return null
  }
}

function pf(i) {
  return !!(i.offsetWidth || i.offsetHeight || typeof i.getClientRects == "function" && i.getClientRects().length)
}

function gf(i) {
  let n = i.nodeName.toLowerCase();
  return n === "input" || n === "select" || n === "button" || n === "textarea"
}

function vf(i) {
  return bf(i) && i.type == "hidden"
}

function _f(i) {
  return yf(i) && i.hasAttribute("href")
}

function bf(i) {
  return i.nodeName.toLowerCase() == "input"
}

function yf(i) {
  return i.nodeName.toLowerCase() == "a"
}

function Cd(i) {
  if (!i.hasAttribute("tabindex") || i.tabIndex === void 0) return !1;
  let n = i.getAttribute("tabindex");
  return !!(n && !isNaN(parseInt(n, 10)))
}

function vd(i) {
  if (!Cd(i)) return null;
  let n = parseInt(i.getAttribute("tabindex") || "", 10);
  return isNaN(n) ? -1 : n
}

function Cf(i) {
  let n = i.nodeName.toLowerCase(),
    t = n === "input" && i.type;
  return t === "text" || t === "password" || n === "select" || n === "textarea"
}

function xf(i) {
  return vf(i) ? !1 : gf(i) || _f(i) || i.hasAttribute("contenteditable") || Cd(i)
}

function wf(i) {
  return i.ownerDocument && i.ownerDocument.defaultView || window
}

function Ed() {
  return null
}
var yd, Qr, xd, Ef, wd, Sd, Sf, is, xe, _d, bd, es, Jr, Df, ns = _(() => {
  f();
  f();
  se();
  fn();
  xi();
  An();
  Ka();
  ts();
  yd = (() => {
    class i {
      _platform = l(T);
      constructor() {}
      isDisabled(t) {
        return t.hasAttribute("disabled")
      }
      isVisible(t) {
        return pf(t) && getComputedStyle(t).visibility === "visible"
      }
      isTabbable(t) {
        if (!this._platform.isBrowser) return !1;
        let e = ff(wf(t));
        if (e && (vd(e) === -1 || !this.isVisible(e))) return !1;
        let r = t.nodeName.toLowerCase(),
          o = vd(t);
        return t.hasAttribute("contenteditable") ? o !== -1 : r === "iframe" || r === "object" || this._platform.WEBKIT && this._platform.IOS && !Cf(t) ? !1 : r === "audio" ? t.hasAttribute("controls") ? o !== -1 : !1 : r === "video" ? o === -1 ? !1 : o !== null ? !0 : this._platform.FIREFOX || t.hasAttribute("controls") : t.tabIndex >= 0
      }
      isFocusable(t, e) {
        return xf(t) && !this.isDisabled(t) && (e?.ignoreVisibility || this.isVisible(t))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })();
  Qr = class {
    _element;
    _checker;
    _ngZone;
    _document;
    _injector;
    _startAnchor;
    _endAnchor;
    _hasAttached = !1;
    startAnchorListener = () => this.focusLastTabbableElement();
    endAnchorListener = () => this.focusFirstTabbableElement();
    get enabled() {
      return this._enabled
    }
    set enabled(n) {
      this._enabled = n, this._startAnchor && this._endAnchor && (this._toggleAnchorTabIndex(n, this._startAnchor), this._toggleAnchorTabIndex(n, this._endAnchor))
    }
    _enabled = !0;
    constructor(n, t, e, r, o = !1, a) {
      this._element = n, this._checker = t, this._ngZone = e, this._document = r, this._injector = a, o || this.attachAnchors()
    }
    destroy() {
      let n = this._startAnchor,
        t = this._endAnchor;
      n && (n.removeEventListener("focus", this.startAnchorListener), n.remove()), t && (t.removeEventListener("focus", this.endAnchorListener), t.remove()), this._startAnchor = this._endAnchor = null, this._hasAttached = !1
    }
    attachAnchors() {
      return this._hasAttached ? !0 : (this._ngZone.runOutsideAngular(() => {
        this._startAnchor || (this._startAnchor = this._createAnchor(), this._startAnchor.addEventListener("focus", this.startAnchorListener)), this._endAnchor || (this._endAnchor = this._createAnchor(), this._endAnchor.addEventListener("focus", this.endAnchorListener))
      }), this._element.parentNode && (this._element.parentNode.insertBefore(this._startAnchor, this._element), this._element.parentNode.insertBefore(this._endAnchor, this._element.nextSibling), this._hasAttached = !0), this._hasAttached)
    }
    focusInitialElementWhenReady(n) {
      return new Promise(t => {
        this._executeOnStable(() => t(this.focusInitialElement(n)))
      })
    }
    focusFirstTabbableElementWhenReady(n) {
      return new Promise(t => {
        this._executeOnStable(() => t(this.focusFirstTabbableElement(n)))
      })
    }
    focusLastTabbableElementWhenReady(n) {
      return new Promise(t => {
        this._executeOnStable(() => t(this.focusLastTabbableElement(n)))
      })
    }
    _getRegionBoundary(n) {
      let t = this._element.querySelectorAll(`[cdk-focus-region-${n}], [cdkFocusRegion${n}], [cdk-focus-${n}]`);
      return n == "start" ? t.length ? t[0] : this._getFirstTabbableElement(this._element) : t.length ? t[t.length - 1] : this._getLastTabbableElement(this._element)
    }
    focusInitialElement(n) {
      let t = this._element.querySelector("[cdk-focus-initial], [cdkFocusInitial]");
      if (t) {
        if (!this._checker.isFocusable(t)) {
          let e = this._getFirstTabbableElement(t);
          return e?.focus(n), !!e
        }
        return t.focus(n), !0
      }
      return this.focusFirstTabbableElement(n)
    }
    focusFirstTabbableElement(n) {
      let t = this._getRegionBoundary("start");
      return t && t.focus(n), !!t
    }
    focusLastTabbableElement(n) {
      let t = this._getRegionBoundary("end");
      return t && t.focus(n), !!t
    }
    hasAttached() {
      return this._hasAttached
    }
    _getFirstTabbableElement(n) {
      if (this._checker.isFocusable(n) && this._checker.isTabbable(n)) return n;
      let t = n.children;
      for (let e = 0; e < t.length; e++) {
        let r = t[e].nodeType === this._document.ELEMENT_NODE ? this._getFirstTabbableElement(t[e]) : null;
        if (r) return r
      }
      return null
    }
    _getLastTabbableElement(n) {
      if (this._checker.isFocusable(n) && this._checker.isTabbable(n)) return n;
      let t = n.children;
      for (let e = t.length - 1; e >= 0; e--) {
        let r = t[e].nodeType === this._document.ELEMENT_NODE ? this._getLastTabbableElement(t[e]) : null;
        if (r) return r
      }
      return null
    }
    _createAnchor() {
      let n = this._document.createElement("div");
      return this._toggleAnchorTabIndex(this._enabled, n), n.classList.add("cdk-visually-hidden"), n.classList.add("cdk-focus-trap-anchor"), n.setAttribute("aria-hidden", "true"), n
    }
    _toggleAnchorTabIndex(n, t) {
      n ? t.setAttribute("tabindex", "0") : t.removeAttribute("tabindex")
    }
    toggleAnchors(n) {
      this._startAnchor && this._endAnchor && (this._toggleAnchorTabIndex(n, this._startAnchor), this._toggleAnchorTabIndex(n, this._endAnchor))
    }
    _executeOnStable(n) {
      this._injector ? Ot(n, {
        injector: this._injector
      }) : setTimeout(n)
    }
  }, xd = (() => {
    class i {
      _checker = l(yd);
      _ngZone = l(E);
      _document = l(O);
      _injector = l(N);
      constructor() {
        l(Mt).load(Zr)
      }
      create(t, e = !1) {
        return new Qr(t, this._checker, this._ngZone, this._document, e, this._injector)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Ef = (() => {
    class i {
      _elementRef = l(D);
      _focusTrapFactory = l(xd);
      focusTrap;
      _previouslyFocusedElement = null;
      get enabled() {
        return this.focusTrap?.enabled || !1
      }
      set enabled(t) {
        this.focusTrap && (this.focusTrap.enabled = t)
      }
      autoCapture;
      constructor() {
        l(T).isBrowser && (this.focusTrap = this._focusTrapFactory.create(this._elementRef.nativeElement, !0))
      }
      ngOnDestroy() {
        this.focusTrap?.destroy(), this._previouslyFocusedElement && (this._previouslyFocusedElement.focus(), this._previouslyFocusedElement = null)
      }
      ngAfterContentInit() {
        this.focusTrap?.attachAnchors(), this.autoCapture && this._captureFocus()
      }
      ngDoCheck() {
        this.focusTrap && !this.focusTrap.hasAttached() && this.focusTrap.attachAnchors()
      }
      ngOnChanges(t) {
        let e = t.autoCapture;
        e && !e.firstChange && this.autoCapture && this.focusTrap?.hasAttached() && this._captureFocus()
      }
      _captureFocus() {
        this._previouslyFocusedElement = Aa(), this.focusTrap?.focusInitialElementWhenReady()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "cdkTrapFocus", ""]
        ],
        inputs: {
          enabled: [2, "cdkTrapFocus", "enabled", F],
          autoCapture: [2, "cdkTrapFocusAutoCapture", "autoCapture", F]
        },
        exportAs: ["cdkTrapFocus"],
        features: [mt]
      })
    }
    return i
  })(), wd = new v("liveAnnouncerElement", {
    providedIn: "root",
    factory: Ed
  });
  Sd = new v("LIVE_ANNOUNCER_DEFAULT_OPTIONS"), Sf = 0, is = (() => {
    class i {
      _ngZone = l(E);
      _defaultOptions = l(Sd, {
        optional: !0
      });
      _liveElement;
      _document = l(O);
      _previousTimeout;
      _currentPromise;
      _currentResolve;
      constructor() {
        let t = l(wd, {
          optional: !0
        });
        this._liveElement = t || this._createLiveElement()
      }
      announce(t, ...e) {
        let r = this._defaultOptions,
          o, a;
        return e.length === 1 && typeof e[0] == "number" ? a = e[0] : [o, a] = e, this.clear(), clearTimeout(this._previousTimeout), o || (o = r && r.politeness ? r.politeness : "polite"), a == null && r && (a = r.duration), this._liveElement.setAttribute("aria-live", o), this._liveElement.id && this._exposeAnnouncerToModals(this._liveElement.id), this._ngZone.runOutsideAngular(() => (this._currentPromise || (this._currentPromise = new Promise(s => this._currentResolve = s)), clearTimeout(this._previousTimeout), this._previousTimeout = setTimeout(() => {
          this._liveElement.textContent = t, typeof a == "number" && (this._previousTimeout = setTimeout(() => this.clear(), a)), this._currentResolve?.(), this._currentPromise = this._currentResolve = void 0
        }, 100), this._currentPromise))
      }
      clear() {
        this._liveElement && (this._liveElement.textContent = "")
      }
      ngOnDestroy() {
        clearTimeout(this._previousTimeout), this._liveElement?.remove(), this._liveElement = null, this._currentResolve?.(), this._currentPromise = this._currentResolve = void 0
      }
      _createLiveElement() {
        let t = "cdk-live-announcer-element",
          e = this._document.getElementsByClassName(t),
          r = this._document.createElement("div");
        for (let o = 0; o < e.length; o++) e[o].remove();
        return r.classList.add(t), r.classList.add("cdk-visually-hidden"), r.setAttribute("aria-atomic", "true"), r.setAttribute("aria-live", "polite"), r.id = `cdk-live-announcer-${Sf++}`, this._document.body.appendChild(r), r
      }
      _exposeAnnouncerToModals(t) {
        let e = this._document.querySelectorAll('body > .cdk-overlay-container [aria-modal="true"]');
        for (let r = 0; r < e.length; r++) {
          let o = e[r],
            a = o.getAttribute("aria-owns");
          a ? a.indexOf(t) === -1 && o.setAttribute("aria-owns", a + " " + t) : o.setAttribute("aria-owns", t)
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), xe = (function(i) {
    return i[i.NONE = 0] = "NONE", i[i.BLACK_ON_WHITE = 1] = "BLACK_ON_WHITE", i[i.WHITE_ON_BLACK = 2] = "WHITE_ON_BLACK", i
  })(xe || {}), _d = "cdk-high-contrast-black-on-white", bd = "cdk-high-contrast-white-on-black", es = "cdk-high-contrast-active", Jr = (() => {
    class i {
      _platform = l(T);
      _hasCheckedHighContrastMode;
      _document = l(O);
      _breakpointSubscription;
      constructor() {
        this._breakpointSubscription = l(xn).observe("(forced-colors: active)").subscribe(() => {
          this._hasCheckedHighContrastMode && (this._hasCheckedHighContrastMode = !1, this._applyBodyHighContrastModeCssClasses())
        })
      }
      getHighContrastMode() {
        if (!this._platform.isBrowser) return xe.NONE;
        let t = this._document.createElement("div");
        t.style.backgroundColor = "rgb(1,2,3)", t.style.position = "absolute", this._document.body.appendChild(t);
        let e = this._document.defaultView || window,
          r = e && e.getComputedStyle ? e.getComputedStyle(t) : null,
          o = (r && r.backgroundColor || "").replace(/ /g, "");
        switch (t.remove(), o) {
          case "rgb(0,0,0)":
          case "rgb(45,50,54)":
          case "rgb(32,32,32)":
            return xe.WHITE_ON_BLACK;
          case "rgb(255,255,255)":
          case "rgb(255,250,239)":
            return xe.BLACK_ON_WHITE
        }
        return xe.NONE
      }
      ngOnDestroy() {
        this._breakpointSubscription.unsubscribe()
      }
      _applyBodyHighContrastModeCssClasses() {
        if (!this._hasCheckedHighContrastMode && this._platform.isBrowser && this._document.body) {
          let t = this._document.body.classList;
          t.remove(es, _d, bd), this._hasCheckedHighContrastMode = !0;
          let e = this.getHighContrastMode();
          e === xe.BLACK_ON_WHITE ? t.add(es, _d) : e === xe.WHITE_ON_BLACK && t.add(es, bd)
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Df = (() => {
    class i {
      constructor() {
        l(Jr)._applyBodyHighContrastModeCssClasses()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [Xr]
      })
    }
    return i
  })()
});
var Rf, to, Dd = _(() => {
  nt();
  ht();
  Rf = 200, to = class {
    _letterKeyStream = new y;
    _items = [];
    _selectedItemIndex = -1;
    _pressedLetters = [];
    _skipPredicateFn;
    _selectedItem = new y;
    selectedItem = this._selectedItem;
    constructor(n, t) {
      let e = typeof t?.debounceInterval == "number" ? t.debounceInterval : Rf;
      t?.skipPredicate && (this._skipPredicateFn = t.skipPredicate), this.setItems(n), this._setupKeyHandler(e)
    }
    destroy() {
      this._pressedLetters = [], this._letterKeyStream.complete(), this._selectedItem.complete()
    }
    setCurrentSelectedItemIndex(n) {
      this._selectedItemIndex = n
    }
    setItems(n) {
      this._items = n
    }
    handleKey(n) {
      let t = n.keyCode;
      n.key && n.key.length === 1 ? this._letterKeyStream.next(n.key.toLocaleUpperCase()) : (t >= 65 && t <= 90 || t >= 48 && t <= 57) && this._letterKeyStream.next(String.fromCharCode(t))
    }
    isTyping() {
      return this._pressedLetters.length > 0
    }
    reset() {
      this._pressedLetters = []
    }
    _setupKeyHandler(n) {
      this._letterKeyStream.pipe(W(t => this._pressedLetters.push(t)), Xe(n), K(() => this._pressedLetters.length > 0), b(() => this._pressedLetters.join("").toLocaleUpperCase())).subscribe(t => {
        for (let e = 1; e < this._items.length + 1; e++) {
          let r = (this._selectedItemIndex + e) % this._items.length,
            o = this._items[r];
          if (!this._skipPredicateFn?.(o) && o.getLabel?.().toLocaleUpperCase().trim().indexOf(t) === 0) {
            this._selectedItem.next(o);
            break
          }
        }
        this._pressedLetters = []
      })
    }
  }
});
var Mi, rs = _(() => {
  f();
  nt();
  Dd();
  za();
  Mi = class {
    _items;
    _activeItemIndex = J(-1);
    _activeItem = J(null);
    _wrap = !1;
    _typeaheadSubscription = ft.EMPTY;
    _itemChangesSubscription;
    _vertical = !0;
    _horizontal;
    _allowedModifierKeys = [];
    _homeAndEnd = !1;
    _pageUpAndDown = {
      enabled: !1,
      delta: 10
    };
    _effectRef;
    _typeahead;
    _skipPredicateFn = n => n.disabled;
    constructor(n, t) {
      this._items = n, n instanceof No ? this._itemChangesSubscription = n.changes.subscribe(e => this._itemsChanged(e.toArray())) : Ui(n) && (this._effectRef = Ne(() => this._itemsChanged(n()), {
        injector: t
      }))
    }
    tabOut = new y;
    change = new y;
    skipPredicate(n) {
      return this._skipPredicateFn = n, this
    }
    withWrap(n = !0) {
      return this._wrap = n, this
    }
    withVerticalOrientation(n = !0) {
      return this._vertical = n, this
    }
    withHorizontalOrientation(n) {
      return this._horizontal = n, this
    }
    withAllowedModifierKeys(n) {
      return this._allowedModifierKeys = n, this
    }
    withTypeAhead(n = 200) {
      this._typeaheadSubscription.unsubscribe();
      let t = this._getItemsArray();
      return this._typeahead = new to(t, {
        debounceInterval: typeof n == "number" ? n : void 0,
        skipPredicate: e => this._skipPredicateFn(e)
      }), this._typeaheadSubscription = this._typeahead.selectedItem.subscribe(e => {
        this.setActiveItem(e)
      }), this
    }
    cancelTypeahead() {
      return this._typeahead?.reset(), this
    }
    withHomeAndEnd(n = !0) {
      return this._homeAndEnd = n, this
    }
    withPageUpDown(n = !0, t = 10) {
      return this._pageUpAndDown = {
        enabled: n,
        delta: t
      }, this
    }
    setActiveItem(n) {
      let t = this._activeItem();
      this.updateActiveItem(n), this._activeItem() !== t && this.change.next(this._activeItemIndex())
    }
    onKeydown(n) {
      let t = n.keyCode,
        r = ["altKey", "ctrlKey", "metaKey", "shiftKey"].every(o => !n[o] || this._allowedModifierKeys.indexOf(o) > -1);
      switch (t) {
        case 9:
          this.tabOut.next();
          return;
        case 40:
          if (this._vertical && r) {
            this.setNextItemActive();
            break
          } else return;
        case 38:
          if (this._vertical && r) {
            this.setPreviousItemActive();
            break
          } else return;
        case 39:
          if (this._horizontal && r) {
            this._horizontal === "rtl" ? this.setPreviousItemActive() : this.setNextItemActive();
            break
          } else return;
        case 37:
          if (this._horizontal && r) {
            this._horizontal === "rtl" ? this.setNextItemActive() : this.setPreviousItemActive();
            break
          } else return;
        case 36:
          if (this._homeAndEnd && r) {
            this.setFirstItemActive();
            break
          } else return;
        case 35:
          if (this._homeAndEnd && r) {
            this.setLastItemActive();
            break
          } else return;
        case 33:
          if (this._pageUpAndDown.enabled && r) {
            let o = this._activeItemIndex() - this._pageUpAndDown.delta;
            this._setActiveItemByIndex(o > 0 ? o : 0, 1);
            break
          } else return;
        case 34:
          if (this._pageUpAndDown.enabled && r) {
            let o = this._activeItemIndex() + this._pageUpAndDown.delta,
              a = this._getItemsArray().length;
            this._setActiveItemByIndex(o < a ? o : a - 1, -1);
            break
          } else return;
        default:
          (r || Nr(n, "shiftKey")) && this._typeahead?.handleKey(n);
          return
      }
      this._typeahead?.reset(), n.preventDefault()
    }
    get activeItemIndex() {
      return this._activeItemIndex()
    }
    get activeItem() {
      return this._activeItem()
    }
    isTyping() {
      return !!this._typeahead && this._typeahead.isTyping()
    }
    setFirstItemActive() {
      this._setActiveItemByIndex(0, 1)
    }
    setLastItemActive() {
      this._setActiveItemByIndex(this._getItemsArray().length - 1, -1)
    }
    setNextItemActive() {
      this._activeItemIndex() < 0 ? this.setFirstItemActive() : this._setActiveItemByDelta(1)
    }
    setPreviousItemActive() {
      this._activeItemIndex() < 0 && this._wrap ? this.setLastItemActive() : this._setActiveItemByDelta(-1)
    }
    updateActiveItem(n) {
      let t = this._getItemsArray(),
        e = typeof n == "number" ? n : t.indexOf(n),
        r = t[e];
      this._activeItem.set(r ?? null), this._activeItemIndex.set(e), this._typeahead?.setCurrentSelectedItemIndex(e)
    }
    destroy() {
      this._typeaheadSubscription.unsubscribe(), this._itemChangesSubscription?.unsubscribe(), this._effectRef?.destroy(), this._typeahead?.destroy(), this.tabOut.complete(), this.change.complete()
    }
    _setActiveItemByDelta(n) {
      this._wrap ? this._setActiveInWrapMode(n) : this._setActiveInDefaultMode(n)
    }
    _setActiveInWrapMode(n) {
      let t = this._getItemsArray();
      for (let e = 1; e <= t.length; e++) {
        let r = (this._activeItemIndex() + n * e + t.length) % t.length,
          o = t[r];
        if (!this._skipPredicateFn(o)) {
          this.setActiveItem(r);
          return
        }
      }
    }
    _setActiveInDefaultMode(n) {
      this._setActiveItemByIndex(this._activeItemIndex() + n, n)
    }
    _setActiveItemByIndex(n, t) {
      let e = this._getItemsArray();
      if (e[n]) {
        for (; this._skipPredicateFn(e[n]);)
          if (n += t, !e[n]) return;
        this.setActiveItem(n)
      }
    }
    _getItemsArray() {
      return Ui(this._items) ? this._items() : this._items instanceof No ? this._items.toArray() : this._items
    }
    _itemsChanged(n) {
      this._typeahead?.setItems(n);
      let t = this._activeItem();
      if (t) {
        let e = n.indexOf(t);
        e > -1 && e !== this._activeItemIndex() && (this._activeItemIndex.set(e), this._typeahead?.setCurrentSelectedItemIndex(e))
      }
    }
  }
});
var os, Rd = _(() => {
  rs();
  os = class extends Mi {
    setActiveItem(n) {
      this.activeItem && this.activeItem.setInactiveStyles(), super.setActiveItem(n), this.activeItem && this.activeItem.setActiveStyles()
    }
  }
});
var as, Ad = _(() => {
  rs();
  as = class extends Mi {
    _origin = "program";
    setFocusOrigin(n) {
      return this._origin = n, this
    }
    setActiveItem(n) {
      super.setActiveItem(n), this.activeItem && this.activeItem.focus(this._origin)
    }
  }
});

function Af(i, n, t) {
  let e = io(i, n);
  t = t.trim(), !e.some(r => r.trim() === t) && (e.push(t), i.setAttribute(n, e.join(Id)))
}

function Mf(i, n, t) {
  let e = io(i, n);
  t = t.trim();
  let r = e.filter(o => o !== t);
  r.length ? i.setAttribute(n, r.join(Id)) : i.removeAttribute(n)
}

function io(i, n) {
  return i.getAttribute(n)?.match(/\S+/g) ?? []
}

function ss(i, n) {
  return typeof i == "string" ? `${n||""}/${i}` : i
}

function Md(i, n) {
  i.id || (i.id = `${Od}-${n}-${ls++}`)
}
var Id, Od, eo, ls, KC, qe = _(() => {
  fd();
  ns();
  ns();
  Ba();
  f();
  f();
  se();
  xi();
  An();
  Rd();
  Ad();
  Xa();
  Id = " ";
  Od = "cdk-describedby-message", eo = "cdk-describedby-host", ls = 0, KC = (() => {
    class i {
      _platform = l(T);
      _document = l(O);
      _messageRegistry = new Map;
      _messagesContainer = null;
      _id = `${ls++}`;
      constructor() {
        l(Mt).load(Zr), this._id = l(Wn) + "-" + ls++
      }
      describe(t, e, r) {
        if (!this._canBeDescribed(t, e)) return;
        let o = ss(e, r);
        typeof e != "string" ? (Md(e, this._id), this._messageRegistry.set(o, {
          messageElement: e,
          referenceCount: 0
        })) : this._messageRegistry.has(o) || this._createMessageElement(e, r), this._isElementDescribedByMessage(t, o) || this._addMessageReference(t, o)
      }
      removeDescription(t, e, r) {
        if (!e || !this._isElementNode(t)) return;
        let o = ss(e, r);
        if (this._isElementDescribedByMessage(t, o) && this._removeMessageReference(t, o), typeof e == "string") {
          let a = this._messageRegistry.get(o);
          a && a.referenceCount === 0 && this._deleteMessageElement(o)
        }
        this._messagesContainer?.childNodes.length === 0 && (this._messagesContainer.remove(), this._messagesContainer = null)
      }
      ngOnDestroy() {
        let t = this._document.querySelectorAll(`[${eo}="${this._id}"]`);
        for (let e = 0; e < t.length; e++) this._removeCdkDescribedByReferenceIds(t[e]), t[e].removeAttribute(eo);
        this._messagesContainer?.remove(), this._messagesContainer = null, this._messageRegistry.clear()
      }
      _createMessageElement(t, e) {
        let r = this._document.createElement("div");
        Md(r, this._id), r.textContent = t, e && r.setAttribute("role", e), this._createMessagesContainer(), this._messagesContainer.appendChild(r), this._messageRegistry.set(ss(t, e), {
          messageElement: r,
          referenceCount: 0
        })
      }
      _deleteMessageElement(t) {
        this._messageRegistry.get(t)?.messageElement?.remove(), this._messageRegistry.delete(t)
      }
      _createMessagesContainer() {
        if (this._messagesContainer) return;
        let t = "cdk-describedby-message-container",
          e = this._document.querySelectorAll(`.${t}[platform="server"]`);
        for (let o = 0; o < e.length; o++) e[o].remove();
        let r = this._document.createElement("div");
        r.style.visibility = "hidden", r.classList.add(t), r.classList.add("cdk-visually-hidden"), this._platform.isBrowser || r.setAttribute("platform", "server"), this._document.body.appendChild(r), this._messagesContainer = r
      }
      _removeCdkDescribedByReferenceIds(t) {
        let e = io(t, "aria-describedby").filter(r => r.indexOf(Od) != 0);
        t.setAttribute("aria-describedby", e.join(" "))
      }
      _addMessageReference(t, e) {
        let r = this._messageRegistry.get(e);
        Af(t, "aria-describedby", r.messageElement.id), t.setAttribute(eo, this._id), r.referenceCount++
      }
      _removeMessageReference(t, e) {
        let r = this._messageRegistry.get(e);
        r.referenceCount--, Mf(t, "aria-describedby", r.messageElement.id), t.removeAttribute(eo)
      }
      _isElementDescribedByMessage(t, e) {
        let r = io(t, "aria-describedby"),
          o = this._messageRegistry.get(e),
          a = o && o.messageElement.id;
        return !!a && r.indexOf(a) != -1
      }
      _canBeDescribed(t, e) {
        if (!this._isElementNode(t)) return !1;
        if (e && typeof e == "object") return !0;
        let r = e == null ? "" : `${e}`.trim(),
          o = t.getAttribute("aria-label");
        return r ? !o || o.trim() !== r : !1
      }
      _isElementNode(t) {
        return t.nodeType === this._document.ELEMENT_NODE
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});
var X, we = _(() => {
  qe();
  vn();
  f();
  f();
  X = (() => {
    class i {
      constructor() {
        l(Jr)._applyBodyHighContrastModeCssClasses()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [ye, ye]
      })
    }
    return i
  })()
});

function Tf() {
  let i = l(O),
    n = i ? i.location : null;
  return {
    getPathname: () => n ? n.pathname + n.search : ""
  }
}
var If, Of, kf, kd, Ff, Nf, _x, bx, Pf = _(() => {
  f();
  f();
  nt();
  ht();
  sd();
  we();
  If = ["*"], Of = new v("MAT_ICON_DEFAULT_OPTIONS"), kf = new v("mat-icon-location", {
    providedIn: "root",
    factory: Tf
  });
  kd = ["clip-path", "color-profile", "src", "cursor", "fill", "filter", "marker", "marker-start", "marker-mid", "marker-end", "mask", "stroke"], Ff = kd.map(i => `[${i}]`).join(", "), Nf = /^url\(['"]?#(.*?)['"]?\)$/, _x = (() => {
    class i {
      _elementRef = l(D);
      _iconRegistry = l(ad);
      _location = l(kf);
      _errorHandler = l(zi);
      _defaultColor;
      get color() {
        return this._color || this._defaultColor
      }
      set color(t) {
        this._color = t
      }
      _color;
      inline = !1;
      get svgIcon() {
        return this._svgIcon
      }
      set svgIcon(t) {
        t !== this._svgIcon && (t ? this._updateSvgIcon(t) : this._svgIcon && this._clearSvgElement(), this._svgIcon = t)
      }
      _svgIcon;
      get fontSet() {
        return this._fontSet
      }
      set fontSet(t) {
        let e = this._cleanupFontValue(t);
        e !== this._fontSet && (this._fontSet = e, this._updateFontIconClasses())
      }
      _fontSet;
      get fontIcon() {
        return this._fontIcon
      }
      set fontIcon(t) {
        let e = this._cleanupFontValue(t);
        e !== this._fontIcon && (this._fontIcon = e, this._updateFontIconClasses())
      }
      _fontIcon;
      _previousFontSetClass = [];
      _previousFontIconClass;
      _svgName;
      _svgNamespace;
      _previousPath;
      _elementsWithExternalReferences;
      _currentIconFetch = ft.EMPTY;
      constructor() {
        let t = l(new Xn("aria-hidden"), {
            optional: !0
          }),
          e = l(Of, {
            optional: !0
          });
        e && (e.color && (this.color = this._defaultColor = e.color), e.fontSet && (this.fontSet = e.fontSet)), t || this._elementRef.nativeElement.setAttribute("aria-hidden", "true")
      }
      _splitIconName(t) {
        if (!t) return ["", ""];
        let e = t.split(":");
        switch (e.length) {
          case 1:
            return ["", e[0]];
          case 2:
            return e;
          default:
            throw Error(`Invalid icon name: "${t}"`)
        }
      }
      ngOnInit() {
        this._updateFontIconClasses()
      }
      ngAfterViewChecked() {
        let t = this._elementsWithExternalReferences;
        if (t && t.size) {
          let e = this._location.getPathname();
          e !== this._previousPath && (this._previousPath = e, this._prependPathToReferences(e))
        }
      }
      ngOnDestroy() {
        this._currentIconFetch.unsubscribe(), this._elementsWithExternalReferences && this._elementsWithExternalReferences.clear()
      }
      _usingFontIcon() {
        return !this.svgIcon
      }
      _setSvgElement(t) {
        this._clearSvgElement();
        let e = this._location.getPathname();
        this._previousPath = e, this._cacheChildrenWithExternalReferences(t), this._prependPathToReferences(e), this._elementRef.nativeElement.appendChild(t)
      }
      _clearSvgElement() {
        let t = this._elementRef.nativeElement,
          e = t.childNodes.length;
        for (this._elementsWithExternalReferences && this._elementsWithExternalReferences.clear(); e--;) {
          let r = t.childNodes[e];
          (r.nodeType !== 1 || r.nodeName.toLowerCase() === "svg") && r.remove()
        }
      }
      _updateFontIconClasses() {
        if (!this._usingFontIcon()) return;
        let t = this._elementRef.nativeElement,
          e = (this.fontSet ? this._iconRegistry.classNameForFontAlias(this.fontSet).split(/ +/) : this._iconRegistry.getDefaultFontSetClass()).filter(r => r.length > 0);
        this._previousFontSetClass.forEach(r => t.classList.remove(r)), e.forEach(r => t.classList.add(r)), this._previousFontSetClass = e, this.fontIcon !== this._previousFontIconClass && !e.includes("mat-ligature-font") && (this._previousFontIconClass && t.classList.remove(this._previousFontIconClass), this.fontIcon && t.classList.add(this.fontIcon), this._previousFontIconClass = this.fontIcon)
      }
      _cleanupFontValue(t) {
        return typeof t == "string" ? t.trim().split(" ")[0] : t
      }
      _prependPathToReferences(t) {
        let e = this._elementsWithExternalReferences;
        e && e.forEach((r, o) => {
          r.forEach(a => {
            o.setAttribute(a.name, `url('${t}#${a.value}')`)
          })
        })
      }
      _cacheChildrenWithExternalReferences(t) {
        let e = t.querySelectorAll(Ff),
          r = this._elementsWithExternalReferences = this._elementsWithExternalReferences || new Map;
        for (let o = 0; o < e.length; o++) kd.forEach(a => {
          let s = e[o],
            c = s.getAttribute(a),
            d = c ? c.match(Nf) : null;
          if (d) {
            let u = r.get(s);
            u || (u = [], r.set(s, u)), u.push({
              name: a,
              value: d[1]
            })
          }
        })
      }
      _updateSvgIcon(t) {
        if (this._svgNamespace = null, this._svgName = null, this._currentIconFetch.unsubscribe(), t) {
          let [e, r] = this._splitIconName(t);
          e && (this._svgNamespace = e), r && (this._svgName = r), this._currentIconFetch = this._iconRegistry.getNamedSvgIcon(r, e).pipe(yt(1)).subscribe(o => this._setSvgElement(o), o => {
            let a = `Error retrieving icon ${e}:${r}! ${o.message}`;
            this._errorHandler.handleError(new Error(a))
          })
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["mat-icon"]
        ],
        hostAttrs: ["role", "img", 1, "mat-icon", "notranslate"],
        hostVars: 10,
        hostBindings: function(e, r) {
          e & 2 && (tt("data-mat-icon-type", r._usingFontIcon() ? "font" : "svg")("data-mat-icon-name", r._svgName || r.fontIcon)("data-mat-icon-namespace", r._svgNamespace || r.fontSet)("fontIcon", r._usingFontIcon() ? r.fontIcon : null), Zn(r.color ? "mat-" + r.color : ""), H("mat-icon-inline", r.inline)("mat-icon-no-color", r.color !== "primary" && r.color !== "accent" && r.color !== "warn"))
        },
        inputs: {
          color: "color",
          inline: [2, "inline", "inline", F],
          svgIcon: "svgIcon",
          fontSet: "fontSet",
          fontIcon: "fontIcon"
        },
        exportAs: ["matIcon"],
        ngContentSelectors: If,
        decls: 1,
        vars: 0,
        template: function(e, r) {
          e & 1 && (Tt(), U(0))
        },
        styles: [`mat-icon,mat-icon.mat-primary,mat-icon.mat-accent,mat-icon.mat-warn{color:var(--mat-icon-color, inherit)}.mat-icon{-webkit-user-select:none;user-select:none;background-repeat:no-repeat;display:inline-block;fill:currentColor;height:24px;width:24px;overflow:hidden}.mat-icon.mat-icon-inline{font-size:inherit;height:inherit;line-height:inherit;width:inherit}.mat-icon.mat-ligature-font[fontIcon]::before{content:attr(fontIcon)}[dir=rtl] .mat-icon-rtl-mirror{transform:scale(-1, 1)}.mat-form-field:not(.mat-form-field-appearance-legacy) .mat-form-field-prefix .mat-icon,.mat-form-field:not(.mat-form-field-appearance-legacy) .mat-form-field-suffix .mat-icon{display:block}.mat-form-field:not(.mat-form-field-appearance-legacy) .mat-form-field-prefix .mat-icon-button .mat-icon,.mat-form-field:not(.mat-form-field-appearance-legacy) .mat-form-field-suffix .mat-icon-button .mat-icon{margin:auto}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), bx = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [X, X]
      })
    }
    return i
  })()
});

function cs() {
  if (Ii) return Ii;
  if (typeof document != "object" || !document) return Ii = new Set(Td), Ii;
  let i = document.createElement("input");
  return Ii = new Set(Td.filter(n => (i.setAttribute("type", n), i.type === n))), Ii
}
var Ii, Td, Oi = _(() => {
  se();
  Qa();
  kr();
  fn();
  Td = ["color", "button", "checkbox", "date", "datetime-local", "email", "file", "hidden", "image", "month", "number", "password", "radio", "range", "reset", "search", "submit", "tel", "text", "time", "url", "week"]
});

function ki(i) {
  return i != null && `${i}` != "false"
}

function Dx(i, n = /\s+/) {
  let t = [];
  if (i != null) {
    let e = Array.isArray(i) ? i : `${i}`.split(n);
    for (let r of e) {
      let o = `${r}`.trim();
      o && t.push(o)
    }
  }
  return t
}
var no = _(() => {
  Ei();
  Ia()
});

function Vf() {
  return l(Lf, {
    optional: !0
  })?.animationsDisabled || l(Gn, {
    optional: !0
  }) === "NoopAnimations" ? "di-disabled" : (Fd ??= l(Wr).matchMedia("(prefers-reduced-motion)").matches, Fd ? "reduced-motion" : "enabled")
}

function Gt() {
  return Vf() !== "enabled"
}
var Lf, Fd, Ti = _(() => {
  Za();
  f();
  Lf = new v("MATERIAL_ANIMATIONS"), Fd = null
});

function zf(i, n, t) {
  let e = Math.max(Math.abs(i - t.left), Math.abs(i - t.right)),
    r = Math.max(Math.abs(n - t.top), Math.abs(n - t.bottom));
  return Math.sqrt(e * e + r * r)
}
var zt, ds, Nd, us, Mn, jf, Pd, Ld, Vd, Bf, In, hs, $x, jd = _(() => {
  Oi();
  f();
  f();
  qe();
  no();
  An();
  Ti();
  zt = (function(i) {
    return i[i.FADING_IN = 0] = "FADING_IN", i[i.VISIBLE = 1] = "VISIBLE", i[i.FADING_OUT = 2] = "FADING_OUT", i[i.HIDDEN = 3] = "HIDDEN", i
  })(zt || {}), ds = class {
    _renderer;
    element;
    config;
    _animationForciblyDisabledThroughCss;
    state = zt.HIDDEN;
    constructor(n, t, e, r = !1) {
      this._renderer = n, this.element = t, this.config = e, this._animationForciblyDisabledThroughCss = r
    }
    fadeOut() {
      this._renderer.fadeOutRipple(this)
    }
  }, Nd = Ai({
    passive: !0,
    capture: !0
  }), us = class {
    _events = new Map;
    addHandler(n, t, e, r) {
      let o = this._events.get(t);
      if (o) {
        let a = o.get(e);
        a ? a.add(r) : o.set(e, new Set([r]))
      } else this._events.set(t, new Map([
        [e, new Set([r])]
      ])), n.runOutsideAngular(() => {
        document.addEventListener(t, this._delegateEventHandler, Nd)
      })
    }
    removeHandler(n, t, e) {
      let r = this._events.get(n);
      if (!r) return;
      let o = r.get(t);
      o && (o.delete(e), o.size === 0 && r.delete(t), r.size === 0 && (this._events.delete(n), document.removeEventListener(n, this._delegateEventHandler, Nd)))
    }
    _delegateEventHandler = n => {
      let t = xt(n);
      t && this._events.get(n.type)?.forEach((e, r) => {
        (r === t || r.contains(t)) && e.forEach(o => o.handleEvent(n))
      })
    }
  }, Mn = {
    enterDuration: 225,
    exitDuration: 150
  }, jf = 800, Pd = Ai({
    passive: !0,
    capture: !0
  }), Ld = ["mousedown", "touchstart"], Vd = ["mouseup", "mouseleave", "touchend", "touchcancel"], Bf = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["ng-component"]
        ],
        hostAttrs: ["mat-ripple-style-loader", ""],
        decls: 0,
        vars: 0,
        template: function(e, r) {},
        styles: [`.mat-ripple{overflow:hidden;position:relative}.mat-ripple:not(:empty){transform:translateZ(0)}.mat-ripple.mat-ripple-unbounded{overflow:visible}.mat-ripple-element{position:absolute;border-radius:50%;pointer-events:none;transition:opacity,transform 0ms cubic-bezier(0, 0, 0.2, 1);transform:scale3d(0, 0, 0);background-color:var(--mat-ripple-color, color-mix(in srgb, var(--mat-sys-on-surface) 10%, transparent))}@media(forced-colors: active){.mat-ripple-element{display:none}}.cdk-drag-preview .mat-ripple-element,.cdk-drag-placeholder .mat-ripple-element{display:none}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), In = class i {
    _target;
    _ngZone;
    _platform;
    _containerElement;
    _triggerElement;
    _isPointerDown = !1;
    _activeRipples = new Map;
    _mostRecentTransientRipple;
    _lastTouchStartEvent;
    _pointerUpEventsRegistered = !1;
    _containerRect;
    static _eventManager = new us;
    constructor(n, t, e, r, o) {
      this._target = n, this._ngZone = t, this._platform = r, r.isBrowser && (this._containerElement = wt(e)), o && o.get(Mt).load(Bf)
    }
    fadeInRipple(n, t, e = {}) {
      let r = this._containerRect = this._containerRect || this._containerElement.getBoundingClientRect(),
        o = h(h({}, Mn), e.animation);
      e.centered && (n = r.left + r.width / 2, t = r.top + r.height / 2);
      let a = e.radius || zf(n, t, r),
        s = n - r.left,
        c = t - r.top,
        d = o.enterDuration,
        u = document.createElement("div");
      u.classList.add("mat-ripple-element"), u.style.left = `${s-a}px`, u.style.top = `${c-a}px`, u.style.height = `${a*2}px`, u.style.width = `${a*2}px`, e.color != null && (u.style.backgroundColor = e.color), u.style.transitionDuration = `${d}ms`, this._containerElement.appendChild(u);
      let x = window.getComputedStyle(u),
        j = x.transitionProperty,
        B = x.transitionDuration,
        I = j === "none" || B === "0s" || B === "0s, 0s" || r.width === 0 && r.height === 0,
        V = new ds(this, u, e, I);
      u.style.transform = "scale3d(1, 1, 1)", V.state = zt.FADING_IN, e.persistent || (this._mostRecentTransientRipple = V);
      let bt = null;
      return !I && (d || o.exitDuration) && this._ngZone.runOutsideAngular(() => {
        let Ye = () => {
            bt && (bt.fallbackTimer = null), clearTimeout(De), this._finishRippleTransition(V)
          },
          Vi = () => this._destroyRipple(V),
          De = setTimeout(Vi, d + 100);
        u.addEventListener("transitionend", Ye), u.addEventListener("transitioncancel", Vi), bt = {
          onTransitionEnd: Ye,
          onTransitionCancel: Vi,
          fallbackTimer: De
        }
      }), this._activeRipples.set(V, bt), (I || !d) && this._finishRippleTransition(V), V
    }
    fadeOutRipple(n) {
      if (n.state === zt.FADING_OUT || n.state === zt.HIDDEN) return;
      let t = n.element,
        e = h(h({}, Mn), n.config.animation);
      t.style.transitionDuration = `${e.exitDuration}ms`, t.style.opacity = "0", n.state = zt.FADING_OUT, (n._animationForciblyDisabledThroughCss || !e.exitDuration) && this._finishRippleTransition(n)
    }
    fadeOutAll() {
      this._getActiveRipples().forEach(n => n.fadeOut())
    }
    fadeOutAllNonPersistent() {
      this._getActiveRipples().forEach(n => {
        n.config.persistent || n.fadeOut()
      })
    }
    setupTriggerEvents(n) {
      let t = wt(n);
      !this._platform.isBrowser || !t || t === this._triggerElement || (this._removeTriggerEvents(), this._triggerElement = t, Ld.forEach(e => {
        i._eventManager.addHandler(this._ngZone, e, t, this)
      }))
    }
    handleEvent(n) {
      n.type === "mousedown" ? this._onMousedown(n) : n.type === "touchstart" ? this._onTouchStart(n) : this._onPointerUp(), this._pointerUpEventsRegistered || (this._ngZone.runOutsideAngular(() => {
        Vd.forEach(t => {
          this._triggerElement.addEventListener(t, this, Pd)
        })
      }), this._pointerUpEventsRegistered = !0)
    }
    _finishRippleTransition(n) {
      n.state === zt.FADING_IN ? this._startFadeOutTransition(n) : n.state === zt.FADING_OUT && this._destroyRipple(n)
    }
    _startFadeOutTransition(n) {
      let t = n === this._mostRecentTransientRipple,
        {
          persistent: e
        } = n.config;
      n.state = zt.VISIBLE, !e && (!t || !this._isPointerDown) && n.fadeOut()
    }
    _destroyRipple(n) {
      let t = this._activeRipples.get(n) ?? null;
      this._activeRipples.delete(n), this._activeRipples.size || (this._containerRect = null), n === this._mostRecentTransientRipple && (this._mostRecentTransientRipple = null), n.state = zt.HIDDEN, t !== null && (n.element.removeEventListener("transitionend", t.onTransitionEnd), n.element.removeEventListener("transitioncancel", t.onTransitionCancel), t.fallbackTimer !== null && clearTimeout(t.fallbackTimer)), n.element.remove()
    }
    _onMousedown(n) {
      let t = En(n),
        e = this._lastTouchStartEvent && Date.now() < this._lastTouchStartEvent + jf;
      !this._target.rippleDisabled && !t && !e && (this._isPointerDown = !0, this.fadeInRipple(n.clientX, n.clientY, this._target.rippleConfig))
    }
    _onTouchStart(n) {
      if (!this._target.rippleDisabled && !Sn(n)) {
        this._lastTouchStartEvent = Date.now(), this._isPointerDown = !0;
        let t = n.changedTouches;
        if (t)
          for (let e = 0; e < t.length; e++) this.fadeInRipple(t[e].clientX, t[e].clientY, this._target.rippleConfig)
      }
    }
    _onPointerUp() {
      this._isPointerDown && (this._isPointerDown = !1, this._getActiveRipples().forEach(n => {
        let t = n.state === zt.VISIBLE || n.config.terminateOnPointerUp && n.state === zt.FADING_IN;
        !n.config.persistent && t && n.fadeOut()
      }))
    }
    _getActiveRipples() {
      return Array.from(this._activeRipples.keys())
    }
    _removeTriggerEvents() {
      let n = this._triggerElement;
      n && (Ld.forEach(t => i._eventManager.removeHandler(t, n, this)), this._pointerUpEventsRegistered && (Vd.forEach(t => n.removeEventListener(t, this, Pd)), this._pointerUpEventsRegistered = !1))
    }
  };
  hs = new v("mat-ripple-global-options"), $x = (() => {
    class i {
      _elementRef = l(D);
      _animationsDisabled = Gt();
      color;
      unbounded;
      centered;
      radius = 0;
      animation;
      get disabled() {
        return this._disabled
      }
      set disabled(t) {
        t && this.fadeOutAllNonPersistent(), this._disabled = t, this._setupTriggerEventsIfEnabled()
      }
      _disabled = !1;
      get trigger() {
        return this._trigger || this._elementRef.nativeElement
      }
      set trigger(t) {
        this._trigger = t, this._setupTriggerEventsIfEnabled()
      }
      _trigger;
      _rippleRenderer;
      _globalOptions;
      _isInitialized = !1;
      constructor() {
        let t = l(E),
          e = l(T),
          r = l(hs, {
            optional: !0
          }),
          o = l(N);
        this._globalOptions = r || {}, this._rippleRenderer = new In(this, t, this._elementRef, e, o)
      }
      ngOnInit() {
        this._isInitialized = !0, this._setupTriggerEventsIfEnabled()
      }
      ngOnDestroy() {
        this._rippleRenderer._removeTriggerEvents()
      }
      fadeOutAll() {
        this._rippleRenderer.fadeOutAll()
      }
      fadeOutAllNonPersistent() {
        this._rippleRenderer.fadeOutAllNonPersistent()
      }
      get rippleConfig() {
        return {
          centered: this.centered,
          radius: this.radius,
          color: this.color,
          animation: h(h(h({}, this._globalOptions.animation), this._animationsDisabled ? {
            enterDuration: 0,
            exitDuration: 0
          } : {}), this.animation),
          terminateOnPointerUp: this._globalOptions.terminateOnPointerUp
        }
      }
      get rippleDisabled() {
        return this.disabled || !!this._globalOptions.disabled
      }
      _setupTriggerEventsIfEnabled() {
        !this.disabled && this._isInitialized && this._rippleRenderer.setupTriggerEvents(this.trigger)
      }
      launch(t, e = 0, r) {
        return typeof t == "number" ? this._rippleRenderer.fadeInRipple(t, e, h(h({}, this.rippleConfig), r)) : this._rippleRenderer.fadeInRipple(0, 0, h(h({}, this.rippleConfig), t))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "mat-ripple", ""],
          ["", "matRipple", ""]
        ],
        hostAttrs: [1, "mat-ripple"],
        hostVars: 2,
        hostBindings: function(e, r) {
          e & 2 && H("mat-ripple-unbounded", r.unbounded)
        },
        inputs: {
          color: [0, "matRippleColor", "color"],
          unbounded: [0, "matRippleUnbounded", "unbounded"],
          centered: [0, "matRippleCentered", "centered"],
          radius: [0, "matRippleRadius", "radius"],
          animation: [0, "matRippleAnimation", "animation"],
          disabled: [0, "matRippleDisabled", "disabled"],
          trigger: [0, "matRippleTrigger", "trigger"]
        },
        exportAs: ["matRipple"]
      })
    }
    return i
  })()
});
var Bd, zd = _(() => {
  f();
  we();
  Bd = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [X, X]
      })
    }
    return i
  })()
});
var Uf, Hf, ms, fs, Ud, ro, Hd, $d = _(() => {
  f();
  f();
  Oi();
  Ti();
  jd();
  Uf = {
    capture: !0
  }, Hf = ["focus", "mousedown", "mouseenter", "touchstart"], ms = "mat-ripple-loader-uninitialized", fs = "mat-ripple-loader-class-name", Ud = "mat-ripple-loader-centered", ro = "mat-ripple-loader-disabled", Hd = (() => {
    class i {
      _document = l(O);
      _animationsDisabled = Gt();
      _globalRippleOptions = l(hs, {
        optional: !0
      });
      _platform = l(T);
      _ngZone = l(E);
      _injector = l(N);
      _eventCleanups;
      _hosts = new Map;
      constructor() {
        let t = l(kt).createRenderer(null, null);
        this._eventCleanups = this._ngZone.runOutsideAngular(() => Hf.map(e => t.listen(this._document, e, this._onInteraction, Uf)))
      }
      ngOnDestroy() {
        let t = this._hosts.keys();
        for (let e of t) this.destroyRipple(e);
        this._eventCleanups.forEach(e => e())
      }
      configureRipple(t, e) {
        t.setAttribute(ms, this._globalRippleOptions?.namespace ?? ""), (e.className || !t.hasAttribute(fs)) && t.setAttribute(fs, e.className || ""), e.centered && t.setAttribute(Ud, ""), e.disabled && t.setAttribute(ro, "")
      }
      setDisabled(t, e) {
        let r = this._hosts.get(t);
        r ? (r.target.rippleDisabled = e, !e && !r.hasSetUpEvents && (r.hasSetUpEvents = !0, r.renderer.setupTriggerEvents(t))) : e ? t.setAttribute(ro, "") : t.removeAttribute(ro)
      }
      _onInteraction = t => {
        let e = xt(t);
        if (e instanceof HTMLElement) {
          let r = e.closest(`[${ms}="${this._globalRippleOptions?.namespace??""}"]`);
          r && this._createRipple(r)
        }
      };
      _createRipple(t) {
        if (!this._document || this._hosts.has(t)) return;
        t.querySelector(".mat-ripple")?.remove();
        let e = this._document.createElement("span");
        e.classList.add("mat-ripple", t.getAttribute(fs)), t.append(e);
        let r = this._globalRippleOptions,
          o = this._animationsDisabled ? 0 : r?.animation?.enterDuration ?? Mn.enterDuration,
          a = this._animationsDisabled ? 0 : r?.animation?.exitDuration ?? Mn.exitDuration,
          s = {
            rippleDisabled: this._animationsDisabled || r?.disabled || t.hasAttribute(ro),
            rippleConfig: {
              centered: t.hasAttribute(Ud),
              terminateOnPointerUp: r?.terminateOnPointerUp,
              animation: {
                enterDuration: o,
                exitDuration: a
              }
            }
          },
          c = new In(s, this._ngZone, e, this._platform, this._injector),
          d = !s.rippleDisabled;
        d && c.setupTriggerEvents(t), this._hosts.set(t, {
          target: s,
          renderer: c,
          hasSetUpEvents: d
        }), t.removeAttribute(ms)
      }
      destroyRipple(t) {
        let e = this._hosts.get(t);
        e && (e.renderer._removeTriggerEvents(), this._hosts.delete(t))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});
var Wd, Gd = _(() => {
  f();
  Wd = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["structural-styles"]
        ],
        decls: 0,
        vars: 0,
        template: function(e, r) {},
        styles: [`.mat-focus-indicator{position:relative}.mat-focus-indicator::before{top:0;left:0;right:0;bottom:0;position:absolute;box-sizing:border-box;pointer-events:none;display:var(--mat-focus-indicator-display, none);border-width:var(--mat-focus-indicator-border-width, 3px);border-style:var(--mat-focus-indicator-border-style, solid);border-color:var(--mat-focus-indicator-border-color, transparent);border-radius:var(--mat-focus-indicator-border-radius, 4px)}.mat-focus-indicator:focus::before{content:""}@media(forced-colors: active){html{--mat-focus-indicator-display: block}}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })()
});

function qd(i) {
  return i == null ? void 0 : ml(i)
}
var $f, Wf, Gf, ps, qf, Yd = _(() => {
  f();
  f();
  qe();
  An();
  $d();
  Gd();
  Ti();
  $f = ["mat-icon-button", ""], Wf = ["*"], Gf = new v("MAT_BUTTON_CONFIG");
  ps = (() => {
    class i {
      _elementRef = l(D);
      _ngZone = l(E);
      _animationsDisabled = Gt();
      _config = l(Gf, {
        optional: !0
      });
      _focusMonitor = l(Kr);
      _cleanupClick;
      _renderer = l(lt);
      _rippleLoader = l(Hd);
      _isAnchor;
      _isFab = !1;
      color;
      get disableRipple() {
        return this._disableRipple
      }
      set disableRipple(t) {
        this._disableRipple = t, this._updateRippleDisabled()
      }
      _disableRipple = !1;
      get disabled() {
        return this._disabled
      }
      set disabled(t) {
        this._disabled = t, this._updateRippleDisabled()
      }
      _disabled = !1;
      ariaDisabled;
      disabledInteractive;
      tabIndex;
      set _tabindex(t) {
        this.tabIndex = t
      }
      constructor() {
        l(Mt).load(Wd);
        let t = this._elementRef.nativeElement;
        this._isAnchor = t.tagName === "A", this.disabledInteractive = this._config?.disabledInteractive ?? !1, this.color = this._config?.color ?? null, this._rippleLoader?.configureRipple(t, {
          className: "mat-mdc-button-ripple"
        })
      }
      ngAfterViewInit() {
        this._focusMonitor.monitor(this._elementRef, !0), this._isAnchor && this._setupAsAnchor()
      }
      ngOnDestroy() {
        this._cleanupClick?.(), this._focusMonitor.stopMonitoring(this._elementRef), this._rippleLoader?.destroyRipple(this._elementRef.nativeElement)
      }
      focus(t = "program", e) {
        t ? this._focusMonitor.focusVia(this._elementRef.nativeElement, t, e) : this._elementRef.nativeElement.focus(e)
      }
      _getAriaDisabled() {
        return this.ariaDisabled != null ? this.ariaDisabled : this._isAnchor ? this.disabled || null : this.disabled && this.disabledInteractive ? !0 : null
      }
      _getDisabledAttribute() {
        return this.disabledInteractive || !this.disabled ? null : !0
      }
      _updateRippleDisabled() {
        this._rippleLoader?.setDisabled(this._elementRef.nativeElement, this.disableRipple || this.disabled)
      }
      _getTabIndex() {
        return this._isAnchor ? this.disabled && !this.disabledInteractive ? -1 : this.tabIndex : this.tabIndex
      }
      _setupAsAnchor() {
        this._cleanupClick = this._ngZone.runOutsideAngular(() => this._renderer.listen(this._elementRef.nativeElement, "click", t => {
          this.disabled && (t.preventDefault(), t.stopImmediatePropagation())
        }))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        hostAttrs: [1, "mat-mdc-button-base"],
        hostVars: 13,
        hostBindings: function(e, r) {
          e & 2 && (tt("disabled", r._getDisabledAttribute())("aria-disabled", r._getAriaDisabled())("tabindex", r._getTabIndex()), Zn(r.color ? "mat-" + r.color : ""), H("mat-mdc-button-disabled", r.disabled)("mat-mdc-button-disabled-interactive", r.disabledInteractive)("mat-unthemed", !r.color)("_mat-animation-noopable", r._animationsDisabled))
        },
        inputs: {
          color: "color",
          disableRipple: [2, "disableRipple", "disableRipple", F],
          disabled: [2, "disabled", "disabled", F],
          ariaDisabled: [2, "aria-disabled", "ariaDisabled", F],
          disabledInteractive: [2, "disabledInteractive", "disabledInteractive", F],
          tabIndex: [2, "tabIndex", "tabIndex", qd],
          _tabindex: [2, "tabindex", "_tabindex", qd]
        }
      })
    }
    return i
  })(), qf = (() => {
    class i extends ps {
      constructor() {
        super(), this._rippleLoader.configureRipple(this._elementRef.nativeElement, {
          centered: !0
        })
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["button", "mat-icon-button", ""],
          ["a", "mat-icon-button", ""],
          ["button", "matIconButton", ""],
          ["a", "matIconButton", ""]
        ],
        hostAttrs: [1, "mdc-icon-button", "mat-mdc-icon-button"],
        exportAs: ["matButton", "matAnchor"],
        features: [L],
        attrs: $f,
        ngContentSelectors: Wf,
        decls: 4,
        vars: 0,
        consts: [
          [1, "mat-mdc-button-persistent-ripple", "mdc-icon-button__ripple"],
          [1, "mat-focus-indicator"],
          [1, "mat-mdc-button-touch-target"]
        ],
        template: function(e, r) {
          e & 1 && (Tt(), Kt(0, "span", 0), U(1), Kt(2, "span", 1)(3, "span", 2))
        },
        styles: [`.mat-mdc-icon-button{-webkit-user-select:none;user-select:none;display:inline-block;position:relative;box-sizing:border-box;border:none;outline:none;background-color:rgba(0,0,0,0);fill:currentColor;text-decoration:none;cursor:pointer;z-index:0;overflow:visible;border-radius:var(--mat-icon-button-container-shape, var(--mat-sys-corner-full, 50%));flex-shrink:0;text-align:center;width:var(--mat-icon-button-state-layer-size, 40px);height:var(--mat-icon-button-state-layer-size, 40px);padding:calc(calc(var(--mat-icon-button-state-layer-size, 40px) - var(--mat-icon-button-icon-size, 24px)) / 2);font-size:var(--mat-icon-button-icon-size, 24px);color:var(--mat-icon-button-icon-color, var(--mat-sys-on-surface-variant));-webkit-tap-highlight-color:rgba(0,0,0,0)}.mat-mdc-icon-button .mat-mdc-button-ripple,.mat-mdc-icon-button .mat-mdc-button-persistent-ripple,.mat-mdc-icon-button .mat-mdc-button-persistent-ripple::before{top:0;left:0;right:0;bottom:0;position:absolute;pointer-events:none;border-radius:inherit}.mat-mdc-icon-button .mat-mdc-button-ripple{overflow:hidden}.mat-mdc-icon-button .mat-mdc-button-persistent-ripple::before{content:"";opacity:0}.mat-mdc-icon-button .mdc-button__label,.mat-mdc-icon-button .mat-icon{z-index:1;position:relative}.mat-mdc-icon-button .mat-focus-indicator{top:0;left:0;right:0;bottom:0;position:absolute;border-radius:inherit}.mat-mdc-icon-button:focus>.mat-focus-indicator::before{content:"";border-radius:inherit}.mat-mdc-icon-button .mat-ripple-element{background-color:var(--mat-icon-button-ripple-color, color-mix(in srgb, var(--mat-sys-on-surface-variant) calc(var(--mat-sys-pressed-state-layer-opacity) * 100%), transparent))}.mat-mdc-icon-button .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-icon-button-state-layer-color, var(--mat-sys-on-surface-variant))}.mat-mdc-icon-button.mat-mdc-button-disabled .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-icon-button-disabled-state-layer-color, var(--mat-sys-on-surface-variant))}.mat-mdc-icon-button:hover>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-icon-button-hover-state-layer-opacity, var(--mat-sys-hover-state-layer-opacity))}.mat-mdc-icon-button.cdk-program-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-icon-button.cdk-keyboard-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-icon-button.mat-mdc-button-disabled-interactive:focus>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-icon-button-focus-state-layer-opacity, var(--mat-sys-focus-state-layer-opacity))}.mat-mdc-icon-button:active>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-icon-button-pressed-state-layer-opacity, var(--mat-sys-pressed-state-layer-opacity))}.mat-mdc-icon-button .mat-mdc-button-touch-target{position:absolute;top:50%;height:var(--mat-icon-button-touch-target-size, 48px);display:var(--mat-icon-button-touch-target-display, block);left:50%;width:var(--mat-icon-button-touch-target-size, 48px);transform:translate(-50%, -50%)}.mat-mdc-icon-button._mat-animation-noopable{transition:none !important;animation:none !important}.mat-mdc-icon-button[disabled],.mat-mdc-icon-button.mat-mdc-button-disabled{cursor:default;pointer-events:none;color:var(--mat-icon-button-disabled-icon-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-mdc-icon-button.mat-mdc-button-disabled-interactive{pointer-events:auto}.mat-mdc-icon-button img,.mat-mdc-icon-button svg{width:var(--mat-icon-button-icon-size, 24px);height:var(--mat-icon-button-icon-size, 24px);vertical-align:baseline}.mat-mdc-icon-button .mat-mdc-button-persistent-ripple{border-radius:var(--mat-icon-button-container-shape, var(--mat-sys-corner-full, 50%))}.mat-mdc-icon-button[hidden]{display:none}.mat-mdc-icon-button.mat-unthemed:not(.mdc-ripple-upgraded):focus::before,.mat-mdc-icon-button.mat-primary:not(.mdc-ripple-upgraded):focus::before,.mat-mdc-icon-button.mat-accent:not(.mdc-ripple-upgraded):focus::before,.mat-mdc-icon-button.mat-warn:not(.mdc-ripple-upgraded):focus::before{background:rgba(0,0,0,0);opacity:1}
`, `@media(forced-colors: active){.mat-mdc-button:not(.mdc-button--outlined),.mat-mdc-unelevated-button:not(.mdc-button--outlined),.mat-mdc-raised-button:not(.mdc-button--outlined),.mat-mdc-outlined-button:not(.mdc-button--outlined),.mat-mdc-button-base.mat-tonal-button,.mat-mdc-icon-button.mat-mdc-icon-button,.mat-mdc-outlined-button .mdc-button__ripple{outline:solid 1px}}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })()
});

function Xf(i) {
  return i.hasAttribute("mat-raised-button") ? "elevated" : i.hasAttribute("mat-stroked-button") ? "outlined" : i.hasAttribute("mat-flat-button") ? "filled" : i.hasAttribute("mat-button") ? "text" : null
}
var Yf, Kf, Zf, Kd, Zd, Xd, Qd = _(() => {
  Yd();
  f();
  zd();
  we();
  Yf = ["matButton", ""], Kf = [
    [
      ["", 8, "material-icons", 3, "iconPositionEnd", ""],
      ["mat-icon", 3, "iconPositionEnd", ""],
      ["", "matButtonIcon", "", 3, "iconPositionEnd", ""]
    ], "*", [
      ["", "iconPositionEnd", "", 8, "material-icons"],
      ["mat-icon", "iconPositionEnd", ""],
      ["", "matButtonIcon", "", "iconPositionEnd", ""]
    ]
  ], Zf = [".material-icons:not([iconPositionEnd]), mat-icon:not([iconPositionEnd]), [matButtonIcon]:not([iconPositionEnd])", "*", ".material-icons[iconPositionEnd], mat-icon[iconPositionEnd], [matButtonIcon][iconPositionEnd]"], Kd = new Map([
    ["text", ["mat-mdc-button"]],
    ["filled", ["mdc-button--unelevated", "mat-mdc-unelevated-button"]],
    ["elevated", ["mdc-button--raised", "mat-mdc-raised-button"]],
    ["outlined", ["mdc-button--outlined", "mat-mdc-outlined-button"]],
    ["tonal", ["mat-tonal-button"]]
  ]), Zd = (() => {
    class i extends ps {
      get appearance() {
        return this._appearance
      }
      set appearance(t) {
        this.setAppearance(t || this._config?.defaultAppearance || "text")
      }
      _appearance = null;constructor() {
        super();
        let t = Xf(this._elementRef.nativeElement);
        t && this.setAppearance(t)
      }
      setAppearance(t) {
        if (t === this._appearance) return;
        let e = this._elementRef.nativeElement.classList,
          r = this._appearance ? Kd.get(this._appearance) : null,
          o = Kd.get(t);
        r && e.remove(...r), e.add(...o), this._appearance = t
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };static \u0275cmp = P({
        type: i,
        selectors: [
          ["button", "matButton", ""],
          ["a", "matButton", ""],
          ["button", "mat-button", ""],
          ["button", "mat-raised-button", ""],
          ["button", "mat-flat-button", ""],
          ["button", "mat-stroked-button", ""],
          ["a", "mat-button", ""],
          ["a", "mat-raised-button", ""],
          ["a", "mat-flat-button", ""],
          ["a", "mat-stroked-button", ""]
        ],
        hostAttrs: [1, "mdc-button"],
        inputs: {
          appearance: [0, "matButton", "appearance"]
        },
        exportAs: ["matButton", "matAnchor"],
        features: [L],
        attrs: Yf,
        ngContentSelectors: Zf,
        decls: 7,
        vars: 4,
        consts: [
          [1, "mat-mdc-button-persistent-ripple"],
          [1, "mdc-button__label"],
          [1, "mat-focus-indicator"],
          [1, "mat-mdc-button-touch-target"]
        ],
        template: function(e, r) {
          e & 1 && (Tt(Kf), Kt(0, "span", 0), U(1), ke(2, "span", 1), U(3, 1), Te(), U(4, 2), Kt(5, "span", 2)(6, "span", 3)), e & 2 && H("mdc-button__ripple", !r._isFab)("mdc-fab__ripple", r._isFab)
        },
        styles: [`.mat-mdc-button-base{text-decoration:none}.mat-mdc-button-base .mat-icon{min-height:fit-content;flex-shrink:0}.mdc-button{-webkit-user-select:none;user-select:none;position:relative;display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;min-width:64px;border:none;outline:none;line-height:inherit;-webkit-appearance:none;overflow:visible;vertical-align:middle;background:rgba(0,0,0,0);padding:0 8px}.mdc-button::-moz-focus-inner{padding:0;border:0}.mdc-button:active{outline:none}.mdc-button:hover{cursor:pointer}.mdc-button:disabled{cursor:default;pointer-events:none}.mdc-button[hidden]{display:none}.mdc-button .mdc-button__label{position:relative}.mat-mdc-button{padding:0 var(--mat-button-text-horizontal-padding, 12px);height:var(--mat-button-text-container-height, 40px);font-family:var(--mat-button-text-label-text-font, var(--mat-sys-label-large-font));font-size:var(--mat-button-text-label-text-size, var(--mat-sys-label-large-size));letter-spacing:var(--mat-button-text-label-text-tracking, var(--mat-sys-label-large-tracking));text-transform:var(--mat-button-text-label-text-transform);font-weight:var(--mat-button-text-label-text-weight, var(--mat-sys-label-large-weight))}.mat-mdc-button,.mat-mdc-button .mdc-button__ripple{border-radius:var(--mat-button-text-container-shape, var(--mat-sys-corner-full))}.mat-mdc-button:not(:disabled){color:var(--mat-button-text-label-text-color, var(--mat-sys-primary))}.mat-mdc-button[disabled],.mat-mdc-button.mat-mdc-button-disabled{cursor:default;pointer-events:none;color:var(--mat-button-text-disabled-label-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-mdc-button.mat-mdc-button-disabled-interactive{pointer-events:auto}.mat-mdc-button:has(.material-icons,mat-icon,[matButtonIcon]){padding:0 var(--mat-button-text-with-icon-horizontal-padding, 16px)}.mat-mdc-button>.mat-icon{margin-right:var(--mat-button-text-icon-spacing, 8px);margin-left:var(--mat-button-text-icon-offset, -4px)}[dir=rtl] .mat-mdc-button>.mat-icon{margin-right:var(--mat-button-text-icon-offset, -4px);margin-left:var(--mat-button-text-icon-spacing, 8px)}.mat-mdc-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-text-icon-offset, -4px);margin-left:var(--mat-button-text-icon-spacing, 8px)}[dir=rtl] .mat-mdc-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-text-icon-spacing, 8px);margin-left:var(--mat-button-text-icon-offset, -4px)}.mat-mdc-button .mat-ripple-element{background-color:var(--mat-button-text-ripple-color, color-mix(in srgb, var(--mat-sys-primary) calc(var(--mat-sys-pressed-state-layer-opacity) * 100%), transparent))}.mat-mdc-button .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-text-state-layer-color, var(--mat-sys-primary))}.mat-mdc-button.mat-mdc-button-disabled .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-text-disabled-state-layer-color, var(--mat-sys-on-surface-variant))}.mat-mdc-button:hover>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-text-hover-state-layer-opacity, var(--mat-sys-hover-state-layer-opacity))}.mat-mdc-button.cdk-program-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-button.cdk-keyboard-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-button.mat-mdc-button-disabled-interactive:focus>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-text-focus-state-layer-opacity, var(--mat-sys-focus-state-layer-opacity))}.mat-mdc-button:active>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-text-pressed-state-layer-opacity, var(--mat-sys-pressed-state-layer-opacity))}.mat-mdc-button .mat-mdc-button-touch-target{position:absolute;top:50%;height:var(--mat-button-text-touch-target-size, 48px);display:var(--mat-button-text-touch-target-display, block);left:0;right:0;transform:translateY(-50%)}.mat-mdc-unelevated-button{transition:box-shadow 280ms cubic-bezier(0.4, 0, 0.2, 1);height:var(--mat-button-filled-container-height, 40px);font-family:var(--mat-button-filled-label-text-font, var(--mat-sys-label-large-font));font-size:var(--mat-button-filled-label-text-size, var(--mat-sys-label-large-size));letter-spacing:var(--mat-button-filled-label-text-tracking, var(--mat-sys-label-large-tracking));text-transform:var(--mat-button-filled-label-text-transform);font-weight:var(--mat-button-filled-label-text-weight, var(--mat-sys-label-large-weight));padding:0 var(--mat-button-filled-horizontal-padding, 24px)}.mat-mdc-unelevated-button>.mat-icon{margin-right:var(--mat-button-filled-icon-spacing, 8px);margin-left:var(--mat-button-filled-icon-offset, -8px)}[dir=rtl] .mat-mdc-unelevated-button>.mat-icon{margin-right:var(--mat-button-filled-icon-offset, -8px);margin-left:var(--mat-button-filled-icon-spacing, 8px)}.mat-mdc-unelevated-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-filled-icon-offset, -8px);margin-left:var(--mat-button-filled-icon-spacing, 8px)}[dir=rtl] .mat-mdc-unelevated-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-filled-icon-spacing, 8px);margin-left:var(--mat-button-filled-icon-offset, -8px)}.mat-mdc-unelevated-button .mat-ripple-element{background-color:var(--mat-button-filled-ripple-color, color-mix(in srgb, var(--mat-sys-on-primary) calc(var(--mat-sys-pressed-state-layer-opacity) * 100%), transparent))}.mat-mdc-unelevated-button .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-filled-state-layer-color, var(--mat-sys-on-primary))}.mat-mdc-unelevated-button.mat-mdc-button-disabled .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-filled-disabled-state-layer-color, var(--mat-sys-on-surface-variant))}.mat-mdc-unelevated-button:hover>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-filled-hover-state-layer-opacity, var(--mat-sys-hover-state-layer-opacity))}.mat-mdc-unelevated-button.cdk-program-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-unelevated-button.cdk-keyboard-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-unelevated-button.mat-mdc-button-disabled-interactive:focus>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-filled-focus-state-layer-opacity, var(--mat-sys-focus-state-layer-opacity))}.mat-mdc-unelevated-button:active>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-filled-pressed-state-layer-opacity, var(--mat-sys-pressed-state-layer-opacity))}.mat-mdc-unelevated-button .mat-mdc-button-touch-target{position:absolute;top:50%;height:var(--mat-button-filled-touch-target-size, 48px);display:var(--mat-button-filled-touch-target-display, block);left:0;right:0;transform:translateY(-50%)}.mat-mdc-unelevated-button:not(:disabled){color:var(--mat-button-filled-label-text-color, var(--mat-sys-on-primary));background-color:var(--mat-button-filled-container-color, var(--mat-sys-primary))}.mat-mdc-unelevated-button,.mat-mdc-unelevated-button .mdc-button__ripple{border-radius:var(--mat-button-filled-container-shape, var(--mat-sys-corner-full))}.mat-mdc-unelevated-button[disabled],.mat-mdc-unelevated-button.mat-mdc-button-disabled{cursor:default;pointer-events:none;color:var(--mat-button-filled-disabled-label-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent));background-color:var(--mat-button-filled-disabled-container-color, color-mix(in srgb, var(--mat-sys-on-surface) 12%, transparent))}.mat-mdc-unelevated-button.mat-mdc-button-disabled-interactive{pointer-events:auto}.mat-mdc-raised-button{transition:box-shadow 280ms cubic-bezier(0.4, 0, 0.2, 1);box-shadow:var(--mat-button-protected-container-elevation-shadow, var(--mat-sys-level1));height:var(--mat-button-protected-container-height, 40px);font-family:var(--mat-button-protected-label-text-font, var(--mat-sys-label-large-font));font-size:var(--mat-button-protected-label-text-size, var(--mat-sys-label-large-size));letter-spacing:var(--mat-button-protected-label-text-tracking, var(--mat-sys-label-large-tracking));text-transform:var(--mat-button-protected-label-text-transform);font-weight:var(--mat-button-protected-label-text-weight, var(--mat-sys-label-large-weight));padding:0 var(--mat-button-protected-horizontal-padding, 24px)}.mat-mdc-raised-button>.mat-icon{margin-right:var(--mat-button-protected-icon-spacing, 8px);margin-left:var(--mat-button-protected-icon-offset, -8px)}[dir=rtl] .mat-mdc-raised-button>.mat-icon{margin-right:var(--mat-button-protected-icon-offset, -8px);margin-left:var(--mat-button-protected-icon-spacing, 8px)}.mat-mdc-raised-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-protected-icon-offset, -8px);margin-left:var(--mat-button-protected-icon-spacing, 8px)}[dir=rtl] .mat-mdc-raised-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-protected-icon-spacing, 8px);margin-left:var(--mat-button-protected-icon-offset, -8px)}.mat-mdc-raised-button .mat-ripple-element{background-color:var(--mat-button-protected-ripple-color, color-mix(in srgb, var(--mat-sys-primary) calc(var(--mat-sys-pressed-state-layer-opacity) * 100%), transparent))}.mat-mdc-raised-button .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-protected-state-layer-color, var(--mat-sys-primary))}.mat-mdc-raised-button.mat-mdc-button-disabled .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-protected-disabled-state-layer-color, var(--mat-sys-on-surface-variant))}.mat-mdc-raised-button:hover>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-protected-hover-state-layer-opacity, var(--mat-sys-hover-state-layer-opacity))}.mat-mdc-raised-button.cdk-program-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-raised-button.cdk-keyboard-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-raised-button.mat-mdc-button-disabled-interactive:focus>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-protected-focus-state-layer-opacity, var(--mat-sys-focus-state-layer-opacity))}.mat-mdc-raised-button:active>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-protected-pressed-state-layer-opacity, var(--mat-sys-pressed-state-layer-opacity))}.mat-mdc-raised-button .mat-mdc-button-touch-target{position:absolute;top:50%;height:var(--mat-button-protected-touch-target-size, 48px);display:var(--mat-button-protected-touch-target-display, block);left:0;right:0;transform:translateY(-50%)}.mat-mdc-raised-button:not(:disabled){color:var(--mat-button-protected-label-text-color, var(--mat-sys-primary));background-color:var(--mat-button-protected-container-color, var(--mat-sys-surface))}.mat-mdc-raised-button,.mat-mdc-raised-button .mdc-button__ripple{border-radius:var(--mat-button-protected-container-shape, var(--mat-sys-corner-full))}.mat-mdc-raised-button:hover{box-shadow:var(--mat-button-protected-hover-container-elevation-shadow, var(--mat-sys-level2))}.mat-mdc-raised-button:focus{box-shadow:var(--mat-button-protected-focus-container-elevation-shadow, var(--mat-sys-level1))}.mat-mdc-raised-button:active,.mat-mdc-raised-button:focus:active{box-shadow:var(--mat-button-protected-pressed-container-elevation-shadow, var(--mat-sys-level1))}.mat-mdc-raised-button[disabled],.mat-mdc-raised-button.mat-mdc-button-disabled{cursor:default;pointer-events:none;color:var(--mat-button-protected-disabled-label-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent));background-color:var(--mat-button-protected-disabled-container-color, color-mix(in srgb, var(--mat-sys-on-surface) 12%, transparent))}.mat-mdc-raised-button[disabled].mat-mdc-button-disabled,.mat-mdc-raised-button.mat-mdc-button-disabled.mat-mdc-button-disabled{box-shadow:var(--mat-button-protected-disabled-container-elevation-shadow, var(--mat-sys-level0))}.mat-mdc-raised-button.mat-mdc-button-disabled-interactive{pointer-events:auto}.mat-mdc-outlined-button{border-style:solid;transition:border 280ms cubic-bezier(0.4, 0, 0.2, 1);height:var(--mat-button-outlined-container-height, 40px);font-family:var(--mat-button-outlined-label-text-font, var(--mat-sys-label-large-font));font-size:var(--mat-button-outlined-label-text-size, var(--mat-sys-label-large-size));letter-spacing:var(--mat-button-outlined-label-text-tracking, var(--mat-sys-label-large-tracking));text-transform:var(--mat-button-outlined-label-text-transform);font-weight:var(--mat-button-outlined-label-text-weight, var(--mat-sys-label-large-weight));border-radius:var(--mat-button-outlined-container-shape, var(--mat-sys-corner-full));border-width:var(--mat-button-outlined-outline-width, 1px);padding:0 var(--mat-button-outlined-horizontal-padding, 24px)}.mat-mdc-outlined-button>.mat-icon{margin-right:var(--mat-button-outlined-icon-spacing, 8px);margin-left:var(--mat-button-outlined-icon-offset, -8px)}[dir=rtl] .mat-mdc-outlined-button>.mat-icon{margin-right:var(--mat-button-outlined-icon-offset, -8px);margin-left:var(--mat-button-outlined-icon-spacing, 8px)}.mat-mdc-outlined-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-outlined-icon-offset, -8px);margin-left:var(--mat-button-outlined-icon-spacing, 8px)}[dir=rtl] .mat-mdc-outlined-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-outlined-icon-spacing, 8px);margin-left:var(--mat-button-outlined-icon-offset, -8px)}.mat-mdc-outlined-button .mat-ripple-element{background-color:var(--mat-button-outlined-ripple-color, color-mix(in srgb, var(--mat-sys-primary) calc(var(--mat-sys-pressed-state-layer-opacity) * 100%), transparent))}.mat-mdc-outlined-button .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-outlined-state-layer-color, var(--mat-sys-primary))}.mat-mdc-outlined-button.mat-mdc-button-disabled .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-outlined-disabled-state-layer-color, var(--mat-sys-on-surface-variant))}.mat-mdc-outlined-button:hover>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-outlined-hover-state-layer-opacity, var(--mat-sys-hover-state-layer-opacity))}.mat-mdc-outlined-button.cdk-program-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-outlined-button.cdk-keyboard-focused>.mat-mdc-button-persistent-ripple::before,.mat-mdc-outlined-button.mat-mdc-button-disabled-interactive:focus>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-outlined-focus-state-layer-opacity, var(--mat-sys-focus-state-layer-opacity))}.mat-mdc-outlined-button:active>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-outlined-pressed-state-layer-opacity, var(--mat-sys-pressed-state-layer-opacity))}.mat-mdc-outlined-button .mat-mdc-button-touch-target{position:absolute;top:50%;height:var(--mat-button-outlined-touch-target-size, 48px);display:var(--mat-button-outlined-touch-target-display, block);left:0;right:0;transform:translateY(-50%)}.mat-mdc-outlined-button:not(:disabled){color:var(--mat-button-outlined-label-text-color, var(--mat-sys-primary));border-color:var(--mat-button-outlined-outline-color, var(--mat-sys-outline))}.mat-mdc-outlined-button[disabled],.mat-mdc-outlined-button.mat-mdc-button-disabled{cursor:default;pointer-events:none;color:var(--mat-button-outlined-disabled-label-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent));border-color:var(--mat-button-outlined-disabled-outline-color, color-mix(in srgb, var(--mat-sys-on-surface) 12%, transparent))}.mat-mdc-outlined-button.mat-mdc-button-disabled-interactive{pointer-events:auto}.mat-tonal-button{transition:box-shadow 280ms cubic-bezier(0.4, 0, 0.2, 1);height:var(--mat-button-tonal-container-height, 40px);font-family:var(--mat-button-tonal-label-text-font, var(--mat-sys-label-large-font));font-size:var(--mat-button-tonal-label-text-size, var(--mat-sys-label-large-size));letter-spacing:var(--mat-button-tonal-label-text-tracking, var(--mat-sys-label-large-tracking));text-transform:var(--mat-button-tonal-label-text-transform);font-weight:var(--mat-button-tonal-label-text-weight, var(--mat-sys-label-large-weight));padding:0 var(--mat-button-tonal-horizontal-padding, 24px)}.mat-tonal-button:not(:disabled){color:var(--mat-button-tonal-label-text-color, var(--mat-sys-on-secondary-container));background-color:var(--mat-button-tonal-container-color, var(--mat-sys-secondary-container))}.mat-tonal-button,.mat-tonal-button .mdc-button__ripple{border-radius:var(--mat-button-tonal-container-shape, var(--mat-sys-corner-full))}.mat-tonal-button[disabled],.mat-tonal-button.mat-mdc-button-disabled{cursor:default;pointer-events:none;color:var(--mat-button-tonal-disabled-label-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent));background-color:var(--mat-button-tonal-disabled-container-color, color-mix(in srgb, var(--mat-sys-on-surface) 12%, transparent))}.mat-tonal-button.mat-mdc-button-disabled-interactive{pointer-events:auto}.mat-tonal-button>.mat-icon{margin-right:var(--mat-button-tonal-icon-spacing, 8px);margin-left:var(--mat-button-tonal-icon-offset, -8px)}[dir=rtl] .mat-tonal-button>.mat-icon{margin-right:var(--mat-button-tonal-icon-offset, -8px);margin-left:var(--mat-button-tonal-icon-spacing, 8px)}.mat-tonal-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-tonal-icon-offset, -8px);margin-left:var(--mat-button-tonal-icon-spacing, 8px)}[dir=rtl] .mat-tonal-button .mdc-button__label+.mat-icon{margin-right:var(--mat-button-tonal-icon-spacing, 8px);margin-left:var(--mat-button-tonal-icon-offset, -8px)}.mat-tonal-button .mat-ripple-element{background-color:var(--mat-button-tonal-ripple-color, color-mix(in srgb, var(--mat-sys-on-secondary-container) calc(var(--mat-sys-pressed-state-layer-opacity) * 100%), transparent))}.mat-tonal-button .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-tonal-state-layer-color, var(--mat-sys-on-secondary-container))}.mat-tonal-button.mat-mdc-button-disabled .mat-mdc-button-persistent-ripple::before{background-color:var(--mat-button-tonal-disabled-state-layer-color, var(--mat-sys-on-surface-variant))}.mat-tonal-button:hover>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-tonal-hover-state-layer-opacity, var(--mat-sys-hover-state-layer-opacity))}.mat-tonal-button.cdk-program-focused>.mat-mdc-button-persistent-ripple::before,.mat-tonal-button.cdk-keyboard-focused>.mat-mdc-button-persistent-ripple::before,.mat-tonal-button.mat-mdc-button-disabled-interactive:focus>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-tonal-focus-state-layer-opacity, var(--mat-sys-focus-state-layer-opacity))}.mat-tonal-button:active>.mat-mdc-button-persistent-ripple::before{opacity:var(--mat-button-tonal-pressed-state-layer-opacity, var(--mat-sys-pressed-state-layer-opacity))}.mat-tonal-button .mat-mdc-button-touch-target{position:absolute;top:50%;height:var(--mat-button-tonal-touch-target-size, 48px);display:var(--mat-button-tonal-touch-target-display, block);left:0;right:0;transform:translateY(-50%)}.mat-mdc-button,.mat-mdc-unelevated-button,.mat-mdc-raised-button,.mat-mdc-outlined-button,.mat-tonal-button{-webkit-tap-highlight-color:rgba(0,0,0,0)}.mat-mdc-button .mat-mdc-button-ripple,.mat-mdc-button .mat-mdc-button-persistent-ripple,.mat-mdc-button .mat-mdc-button-persistent-ripple::before,.mat-mdc-unelevated-button .mat-mdc-button-ripple,.mat-mdc-unelevated-button .mat-mdc-button-persistent-ripple,.mat-mdc-unelevated-button .mat-mdc-button-persistent-ripple::before,.mat-mdc-raised-button .mat-mdc-button-ripple,.mat-mdc-raised-button .mat-mdc-button-persistent-ripple,.mat-mdc-raised-button .mat-mdc-button-persistent-ripple::before,.mat-mdc-outlined-button .mat-mdc-button-ripple,.mat-mdc-outlined-button .mat-mdc-button-persistent-ripple,.mat-mdc-outlined-button .mat-mdc-button-persistent-ripple::before,.mat-tonal-button .mat-mdc-button-ripple,.mat-tonal-button .mat-mdc-button-persistent-ripple,.mat-tonal-button .mat-mdc-button-persistent-ripple::before{top:0;left:0;right:0;bottom:0;position:absolute;pointer-events:none;border-radius:inherit}.mat-mdc-button .mat-mdc-button-ripple,.mat-mdc-unelevated-button .mat-mdc-button-ripple,.mat-mdc-raised-button .mat-mdc-button-ripple,.mat-mdc-outlined-button .mat-mdc-button-ripple,.mat-tonal-button .mat-mdc-button-ripple{overflow:hidden}.mat-mdc-button .mat-mdc-button-persistent-ripple::before,.mat-mdc-unelevated-button .mat-mdc-button-persistent-ripple::before,.mat-mdc-raised-button .mat-mdc-button-persistent-ripple::before,.mat-mdc-outlined-button .mat-mdc-button-persistent-ripple::before,.mat-tonal-button .mat-mdc-button-persistent-ripple::before{content:"";opacity:0}.mat-mdc-button .mdc-button__label,.mat-mdc-button .mat-icon,.mat-mdc-unelevated-button .mdc-button__label,.mat-mdc-unelevated-button .mat-icon,.mat-mdc-raised-button .mdc-button__label,.mat-mdc-raised-button .mat-icon,.mat-mdc-outlined-button .mdc-button__label,.mat-mdc-outlined-button .mat-icon,.mat-tonal-button .mdc-button__label,.mat-tonal-button .mat-icon{z-index:1;position:relative}.mat-mdc-button .mat-focus-indicator,.mat-mdc-unelevated-button .mat-focus-indicator,.mat-mdc-raised-button .mat-focus-indicator,.mat-mdc-outlined-button .mat-focus-indicator,.mat-tonal-button .mat-focus-indicator{top:0;left:0;right:0;bottom:0;position:absolute;border-radius:inherit}.mat-mdc-button:focus>.mat-focus-indicator::before,.mat-mdc-unelevated-button:focus>.mat-focus-indicator::before,.mat-mdc-raised-button:focus>.mat-focus-indicator::before,.mat-mdc-outlined-button:focus>.mat-focus-indicator::before,.mat-tonal-button:focus>.mat-focus-indicator::before{content:"";border-radius:inherit}.mat-mdc-button._mat-animation-noopable,.mat-mdc-unelevated-button._mat-animation-noopable,.mat-mdc-raised-button._mat-animation-noopable,.mat-mdc-outlined-button._mat-animation-noopable,.mat-tonal-button._mat-animation-noopable{transition:none !important;animation:none !important}.mat-mdc-button>.mat-icon,.mat-mdc-unelevated-button>.mat-icon,.mat-mdc-raised-button>.mat-icon,.mat-mdc-outlined-button>.mat-icon,.mat-tonal-button>.mat-icon{display:inline-block;position:relative;vertical-align:top;font-size:1.125rem;height:1.125rem;width:1.125rem}.mat-mdc-outlined-button .mat-mdc-button-ripple,.mat-mdc-outlined-button .mdc-button__ripple{top:-1px;left:-1px;bottom:-1px;right:-1px}.mat-mdc-unelevated-button .mat-focus-indicator::before,.mat-tonal-button .mat-focus-indicator::before,.mat-mdc-raised-button .mat-focus-indicator::before{margin:calc(calc(var(--mat-focus-indicator-border-width, 3px) + 2px)*-1)}.mat-mdc-outlined-button .mat-focus-indicator::before{margin:calc(calc(var(--mat-focus-indicator-border-width, 3px) + 3px)*-1)}
`, `@media(forced-colors: active){.mat-mdc-button:not(.mdc-button--outlined),.mat-mdc-unelevated-button:not(.mdc-button--outlined),.mat-mdc-raised-button:not(.mdc-button--outlined),.mat-mdc-outlined-button:not(.mdc-button--outlined),.mat-mdc-button-base.mat-tonal-button,.mat-mdc-icon-button.mat-mdc-icon-button,.mat-mdc-outlined-button .mdc-button__ripple{outline:solid 1px}}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })();
  Xd = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [X, Bd, X]
      })
    }
    return i
  })()
});
var Qf, Jf, tp, ep, D0, R0, A0, M0, I0, O0, k0, ip = _(() => {
  f();
  f();
  we();
  Qf = ["*"], Jf = [
    [
      ["", "mat-card-avatar", ""],
      ["", "matCardAvatar", ""]
    ],
    [
      ["mat-card-title"],
      ["mat-card-subtitle"],
      ["", "mat-card-title", ""],
      ["", "mat-card-subtitle", ""],
      ["", "matCardTitle", ""],
      ["", "matCardSubtitle", ""]
    ], "*"
  ], tp = ["[mat-card-avatar], [matCardAvatar]", `mat-card-title, mat-card-subtitle,
      [mat-card-title], [mat-card-subtitle],
      [matCardTitle], [matCardSubtitle]`, "*"], ep = new v("MAT_CARD_CONFIG"), D0 = (() => {
    class i {
      appearance;
      constructor() {
        let t = l(ep, {
          optional: !0
        });
        this.appearance = t?.appearance || "raised"
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["mat-card"]
        ],
        hostAttrs: [1, "mat-mdc-card", "mdc-card"],
        hostVars: 8,
        hostBindings: function(e, r) {
          e & 2 && H("mat-mdc-card-outlined", r.appearance === "outlined")("mdc-card--outlined", r.appearance === "outlined")("mat-mdc-card-filled", r.appearance === "filled")("mdc-card--filled", r.appearance === "filled")
        },
        inputs: {
          appearance: "appearance"
        },
        exportAs: ["matCard"],
        ngContentSelectors: Qf,
        decls: 1,
        vars: 0,
        template: function(e, r) {
          e & 1 && (Tt(), U(0))
        },
        styles: [`.mat-mdc-card{display:flex;flex-direction:column;box-sizing:border-box;position:relative;border-style:solid;border-width:0;background-color:var(--mat-card-elevated-container-color, var(--mat-sys-surface-container-low));border-color:var(--mat-card-elevated-container-color, var(--mat-sys-surface-container-low));border-radius:var(--mat-card-elevated-container-shape, var(--mat-sys-corner-medium));box-shadow:var(--mat-card-elevated-container-elevation, var(--mat-sys-level1))}.mat-mdc-card::after{position:absolute;top:0;left:0;width:100%;height:100%;border:solid 1px rgba(0,0,0,0);content:"";display:block;pointer-events:none;box-sizing:border-box;border-radius:var(--mat-card-elevated-container-shape, var(--mat-sys-corner-medium))}.mat-mdc-card-outlined{background-color:var(--mat-card-outlined-container-color, var(--mat-sys-surface));border-radius:var(--mat-card-outlined-container-shape, var(--mat-sys-corner-medium));border-width:var(--mat-card-outlined-outline-width, 1px);border-color:var(--mat-card-outlined-outline-color, var(--mat-sys-outline-variant));box-shadow:var(--mat-card-outlined-container-elevation, var(--mat-sys-level0))}.mat-mdc-card-outlined::after{border:none}.mat-mdc-card-filled{background-color:var(--mat-card-filled-container-color, var(--mat-sys-surface-container-highest));border-radius:var(--mat-card-filled-container-shape, var(--mat-sys-corner-medium));box-shadow:var(--mat-card-filled-container-elevation, var(--mat-sys-level0))}.mdc-card__media{position:relative;box-sizing:border-box;background-repeat:no-repeat;background-position:center;background-size:cover}.mdc-card__media::before{display:block;content:""}.mdc-card__media:first-child{border-top-left-radius:inherit;border-top-right-radius:inherit}.mdc-card__media:last-child{border-bottom-left-radius:inherit;border-bottom-right-radius:inherit}.mat-mdc-card-actions{display:flex;flex-direction:row;align-items:center;box-sizing:border-box;min-height:52px;padding:8px}.mat-mdc-card-title{font-family:var(--mat-card-title-text-font, var(--mat-sys-title-large-font));line-height:var(--mat-card-title-text-line-height, var(--mat-sys-title-large-line-height));font-size:var(--mat-card-title-text-size, var(--mat-sys-title-large-size));letter-spacing:var(--mat-card-title-text-tracking, var(--mat-sys-title-large-tracking));font-weight:var(--mat-card-title-text-weight, var(--mat-sys-title-large-weight))}.mat-mdc-card-subtitle{color:var(--mat-card-subtitle-text-color, var(--mat-sys-on-surface));font-family:var(--mat-card-subtitle-text-font, var(--mat-sys-title-medium-font));line-height:var(--mat-card-subtitle-text-line-height, var(--mat-sys-title-medium-line-height));font-size:var(--mat-card-subtitle-text-size, var(--mat-sys-title-medium-size));letter-spacing:var(--mat-card-subtitle-text-tracking, var(--mat-sys-title-medium-tracking));font-weight:var(--mat-card-subtitle-text-weight, var(--mat-sys-title-medium-weight))}.mat-mdc-card-title,.mat-mdc-card-subtitle{display:block;margin:0}.mat-mdc-card-avatar~.mat-mdc-card-header-text .mat-mdc-card-title,.mat-mdc-card-avatar~.mat-mdc-card-header-text .mat-mdc-card-subtitle{padding:16px 16px 0}.mat-mdc-card-header{display:flex;padding:16px 16px 0}.mat-mdc-card-content{display:block;padding:0 16px}.mat-mdc-card-content:first-child{padding-top:16px}.mat-mdc-card-content:last-child{padding-bottom:16px}.mat-mdc-card-title-group{display:flex;justify-content:space-between;width:100%}.mat-mdc-card-avatar{height:40px;width:40px;border-radius:50%;flex-shrink:0;margin-bottom:16px;object-fit:cover}.mat-mdc-card-avatar~.mat-mdc-card-header-text .mat-mdc-card-subtitle,.mat-mdc-card-avatar~.mat-mdc-card-header-text .mat-mdc-card-title{line-height:normal}.mat-mdc-card-sm-image{width:80px;height:80px}.mat-mdc-card-md-image{width:112px;height:112px}.mat-mdc-card-lg-image{width:152px;height:152px}.mat-mdc-card-xl-image{width:240px;height:240px}.mat-mdc-card-subtitle~.mat-mdc-card-title,.mat-mdc-card-title~.mat-mdc-card-subtitle,.mat-mdc-card-header .mat-mdc-card-header-text .mat-mdc-card-title,.mat-mdc-card-header .mat-mdc-card-header-text .mat-mdc-card-subtitle,.mat-mdc-card-title-group .mat-mdc-card-title,.mat-mdc-card-title-group .mat-mdc-card-subtitle{padding-top:0}.mat-mdc-card-content>:last-child:not(.mat-mdc-card-footer){margin-bottom:0}.mat-mdc-card-actions-align-end{justify-content:flex-end}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), R0 = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["mat-card-title"],
          ["", "mat-card-title", ""],
          ["", "matCardTitle", ""]
        ],
        hostAttrs: [1, "mat-mdc-card-title"]
      })
    }
    return i
  })(), A0 = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["mat-card-content"]
        ],
        hostAttrs: [1, "mat-mdc-card-content"]
      })
    }
    return i
  })(), M0 = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["mat-card-subtitle"],
          ["", "mat-card-subtitle", ""],
          ["", "matCardSubtitle", ""]
        ],
        hostAttrs: [1, "mat-mdc-card-subtitle"]
      })
    }
    return i
  })(), I0 = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["mat-card-header"]
        ],
        hostAttrs: [1, "mat-mdc-card-header"],
        ngContentSelectors: tp,
        decls: 4,
        vars: 0,
        consts: [
          [1, "mat-mdc-card-header-text"]
        ],
        template: function(e, r) {
          e & 1 && (Tt(Jf), U(0), ke(1, "div", 0), U(2, 1), Te(), U(3, 2))
        },
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), O0 = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "mat-card-image", ""],
          ["", "matCardImage", ""]
        ],
        hostAttrs: [1, "mat-mdc-card-image", "mdc-card__media"]
      })
    }
    return i
  })(), k0 = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [X, X]
      })
    }
    return i
  })()
});

function np(i, n) {
  if (i & 1) {
    let t = Kn();
    ct(0, "div", 1)(1, "button", 2), dt("click", function() {
      Un(t);
      let r = Ht();
      return Hn(r.action())
    }), Wi(2), rt()()
  }
  if (i & 2) {
    let t = Ht();
    q(2), Bo(" ", t.data.action, " ")
  }
}

function op(i, n) {}

function up() {
  return new Fi
}
var rp, ap, On, Jd, Fi, sp, lp, cp, tu, gs, vs, dp, hp, _s, Q0, eu = _(() => {
  f();
  f();
  nt();
  Qd();
  qe();
  Oi();
  Va();
  Ti();
  Za();
  Qc();
  ht();
  we();
  rp = ["label"];
  ap = Math.pow(2, 31) - 1, On = class {
    _overlayRef;
    instance;
    containerInstance;
    _afterDismissed = new y;
    _afterOpened = new y;
    _onAction = new y;
    _durationTimeoutId;
    _dismissedByAction = !1;
    constructor(n, t) {
      this._overlayRef = t, this.containerInstance = n, n._onExit.subscribe(() => this._finishDismiss())
    }
    dismiss() {
      this._afterDismissed.closed || this.containerInstance.exit(), clearTimeout(this._durationTimeoutId)
    }
    dismissWithAction() {
      this._onAction.closed || (this._dismissedByAction = !0, this._onAction.next(), this._onAction.complete(), this.dismiss()), clearTimeout(this._durationTimeoutId)
    }
    closeWithAction() {
      this.dismissWithAction()
    }
    _dismissAfter(n) {
      this._durationTimeoutId = setTimeout(() => this.dismiss(), Math.min(n, ap))
    }
    _open() {
      this._afterOpened.closed || (this._afterOpened.next(), this._afterOpened.complete())
    }
    _finishDismiss() {
      this._overlayRef.dispose(), this._onAction.closed || this._onAction.complete(), this._afterDismissed.next({
        dismissedByAction: this._dismissedByAction
      }), this._afterDismissed.complete(), this._dismissedByAction = !1
    }
    afterDismissed() {
      return this._afterDismissed
    }
    afterOpened() {
      return this.containerInstance._onEnter
    }
    onAction() {
      return this._onAction
    }
  }, Jd = new v("MatSnackBarData"), Fi = class {
    politeness = "polite";
    announcementMessage = "";
    viewContainerRef;
    duration = 0;
    panelClass;
    direction;
    data = null;
    horizontalPosition = "center";
    verticalPosition = "bottom"
  }, sp = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "matSnackBarLabel", ""]
        ],
        hostAttrs: [1, "mat-mdc-snack-bar-label", "mdc-snackbar__label"]
      })
    }
    return i
  })(), lp = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "matSnackBarActions", ""]
        ],
        hostAttrs: [1, "mat-mdc-snack-bar-actions", "mdc-snackbar__actions"]
      })
    }
    return i
  })(), cp = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "matSnackBarAction", ""]
        ],
        hostAttrs: [1, "mat-mdc-snack-bar-action", "mdc-snackbar__action"]
      })
    }
    return i
  })(), tu = (() => {
    class i {
      snackBarRef = l(On);
      data = l(Jd);
      constructor() {}
      action() {
        this.snackBarRef.dismissWithAction()
      }
      get hasAction() {
        return !!this.data.action
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["simple-snack-bar"]
        ],
        hostAttrs: [1, "mat-mdc-simple-snack-bar"],
        exportAs: ["matSnackBar"],
        decls: 3,
        vars: 2,
        consts: [
          ["matSnackBarLabel", ""],
          ["matSnackBarActions", ""],
          ["matButton", "", "matSnackBarAction", "", 3, "click"]
        ],
        template: function(e, r) {
          e & 1 && (ct(0, "div", 0), Wi(1), rt(), vt(2, np, 3, 1, "div", 1)), e & 2 && (q(), Bo(" ", r.data.message, `
`), q(), _t(r.hasAction ? 2 : -1))
        },
        dependencies: [Zd, sp, lp, cp],
        styles: [`.mat-mdc-simple-snack-bar{display:flex}.mat-mdc-simple-snack-bar .mat-mdc-snack-bar-label{max-height:50vh;overflow:auto}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), gs = "_mat-snack-bar-enter", vs = "_mat-snack-bar-exit", dp = (() => {
    class i extends Ri {
      _ngZone = l(E);
      _elementRef = l(D);
      _changeDetectorRef = l(At);
      _platform = l(T);
      _animationsDisabled = Gt();
      snackBarConfig = l(Fi);
      _document = l(O);
      _trackedModals = new Set;
      _enterFallback;
      _exitFallback;
      _injector = l(N);
      _announceDelay = 150;
      _announceTimeoutId;
      _destroyed = !1;
      _portalOutlet;
      _onAnnounce = new y;
      _onExit = new y;
      _onEnter = new y;
      _animationState = "void";
      _live;
      _label;
      _role;
      _liveElementId = l(Wt).getId("mat-snack-bar-container-live-");
      constructor() {
        super();
        let t = this.snackBarConfig;
        t.politeness === "assertive" && !t.announcementMessage ? this._live = "assertive" : t.politeness === "off" ? this._live = "off" : this._live = "polite", this._platform.FIREFOX && (this._live === "polite" && (this._role = "status"), this._live === "assertive" && (this._role = "alert"))
      }
      attachComponentPortal(t) {
        this._assertNotAttached();
        let e = this._portalOutlet.attachComponentPortal(t);
        return this._afterPortalAttached(), e
      }
      attachTemplatePortal(t) {
        this._assertNotAttached();
        let e = this._portalOutlet.attachTemplatePortal(t);
        return this._afterPortalAttached(), e
      }
      attachDomPortal = t => {
        this._assertNotAttached();
        let e = this._portalOutlet.attachDomPortal(t);
        return this._afterPortalAttached(), e
      };
      onAnimationEnd(t) {
        t === vs ? this._completeExit() : t === gs && (clearTimeout(this._enterFallback), this._ngZone.run(() => {
          this._onEnter.next(), this._onEnter.complete()
        }))
      }
      enter() {
        this._destroyed || (this._animationState = "visible", this._changeDetectorRef.markForCheck(), this._changeDetectorRef.detectChanges(), this._screenReaderAnnounce(), this._animationsDisabled ? Ot(() => {
          this._ngZone.run(() => queueMicrotask(() => this.onAnimationEnd(gs)))
        }, {
          injector: this._injector
        }) : (clearTimeout(this._enterFallback), this._enterFallback = setTimeout(() => {
          this._elementRef.nativeElement.classList.add("mat-snack-bar-fallback-visible"), this.onAnimationEnd(gs)
        }, 200)))
      }
      exit() {
        return this._destroyed ? g(void 0) : (this._ngZone.run(() => {
          this._animationState = "hidden", this._changeDetectorRef.markForCheck(), this._elementRef.nativeElement.setAttribute("mat-exit", ""), clearTimeout(this._announceTimeoutId), this._animationsDisabled ? Ot(() => {
            this._ngZone.run(() => queueMicrotask(() => this.onAnimationEnd(vs)))
          }, {
            injector: this._injector
          }) : (clearTimeout(this._exitFallback), this._exitFallback = setTimeout(() => this.onAnimationEnd(vs), 200))
        }), this._onExit)
      }
      ngOnDestroy() {
        this._destroyed = !0, this._clearFromModals(), this._completeExit()
      }
      _completeExit() {
        clearTimeout(this._exitFallback), queueMicrotask(() => {
          this._onExit.next(), this._onExit.complete()
        })
      }
      _afterPortalAttached() {
        let t = this._elementRef.nativeElement,
          e = this.snackBarConfig.panelClass;
        e && (Array.isArray(e) ? e.forEach(a => t.classList.add(a)) : t.classList.add(e)), this._exposeToModals();
        let r = this._label.nativeElement,
          o = "mdc-snackbar__label";
        r.classList.toggle(o, !r.querySelector(`.${o}`))
      }
      _exposeToModals() {
        let t = this._liveElementId,
          e = this._document.querySelectorAll('body > .cdk-overlay-container [aria-modal="true"]');
        for (let r = 0; r < e.length; r++) {
          let o = e[r],
            a = o.getAttribute("aria-owns");
          this._trackedModals.add(o), a ? a.indexOf(t) === -1 && o.setAttribute("aria-owns", a + " " + t) : o.setAttribute("aria-owns", t)
        }
      }
      _clearFromModals() {
        this._trackedModals.forEach(t => {
          let e = t.getAttribute("aria-owns");
          if (e) {
            let r = e.replace(this._liveElementId, "").trim();
            r.length > 0 ? t.setAttribute("aria-owns", r) : t.removeAttribute("aria-owns")
          }
        }), this._trackedModals.clear()
      }
      _assertNotAttached() {
        this._portalOutlet.hasAttached()
      }
      _screenReaderAnnounce() {
        this._announceTimeoutId || this._ngZone.runOutsideAngular(() => {
          this._announceTimeoutId = setTimeout(() => {
            if (this._destroyed) return;
            let t = this._elementRef.nativeElement,
              e = t.querySelector("[aria-hidden]"),
              r = t.querySelector("[aria-live]");
            if (e && r) {
              let o = null;
              this._platform.isBrowser && document.activeElement instanceof HTMLElement && e.contains(document.activeElement) && (o = document.activeElement), e.removeAttribute("aria-hidden"), r.appendChild(e), o?.focus(), this._onAnnounce.next(), this._onAnnounce.complete()
            }
          }, this._announceDelay)
        })
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["mat-snack-bar-container"]
        ],
        viewQuery: function(e, r) {
          if (e & 1 && (Rt(La, 7), Rt(rp, 7)), e & 2) {
            let o;
            et(o = it()) && (r._portalOutlet = o.first), et(o = it()) && (r._label = o.first)
          }
        },
        hostAttrs: [1, "mdc-snackbar", "mat-mdc-snack-bar-container"],
        hostVars: 6,
        hostBindings: function(e, r) {
          e & 1 && dt("animationend", function(a) {
            return r.onAnimationEnd(a.animationName)
          })("animationcancel", function(a) {
            return r.onAnimationEnd(a.animationName)
          }), e & 2 && H("mat-snack-bar-container-enter", r._animationState === "visible")("mat-snack-bar-container-exit", r._animationState === "hidden")("mat-snack-bar-container-animations-enabled", !r._animationsDisabled)
        },
        features: [L],
        decls: 6,
        vars: 3,
        consts: [
          ["label", ""],
          [1, "mdc-snackbar__surface", "mat-mdc-snackbar-surface"],
          [1, "mat-mdc-snack-bar-label"],
          ["aria-hidden", "true"],
          ["cdkPortalOutlet", ""]
        ],
        template: function(e, r) {
          e & 1 && (ct(0, "div", 1)(1, "div", 2, 0)(3, "div", 3), ei(4, op, 0, 0, "ng-template", 4), rt(), ne(5, "div"), rt()()), e & 2 && (q(5), tt("aria-live", r._live)("role", r._role)("id", r._liveElementId))
        },
        dependencies: [La],
        styles: [`@keyframes _mat-snack-bar-enter{from{transform:scale(0.8);opacity:0}to{transform:scale(1);opacity:1}}@keyframes _mat-snack-bar-exit{from{opacity:1}to{opacity:0}}.mat-mdc-snack-bar-container{display:flex;align-items:center;justify-content:center;box-sizing:border-box;-webkit-tap-highlight-color:rgba(0,0,0,0);margin:8px}.mat-mdc-snack-bar-handset .mat-mdc-snack-bar-container{width:100vw}.mat-snack-bar-container-animations-enabled{opacity:0}.mat-snack-bar-container-animations-enabled.mat-snack-bar-fallback-visible{opacity:1}.mat-snack-bar-container-animations-enabled.mat-snack-bar-container-enter{animation:_mat-snack-bar-enter 150ms cubic-bezier(0, 0, 0.2, 1) forwards}.mat-snack-bar-container-animations-enabled.mat-snack-bar-container-exit{animation:_mat-snack-bar-exit 75ms cubic-bezier(0.4, 0, 1, 1) forwards}.mat-mdc-snackbar-surface{box-shadow:0px 3px 5px -1px rgba(0, 0, 0, 0.2), 0px 6px 10px 0px rgba(0, 0, 0, 0.14), 0px 1px 18px 0px rgba(0, 0, 0, 0.12);display:flex;align-items:center;justify-content:flex-start;box-sizing:border-box;padding-left:0;padding-right:8px}[dir=rtl] .mat-mdc-snackbar-surface{padding-right:0;padding-left:8px}.mat-mdc-snack-bar-container .mat-mdc-snackbar-surface{min-width:344px;max-width:672px}.mat-mdc-snack-bar-handset .mat-mdc-snackbar-surface{width:100%;min-width:0}@media(forced-colors: active){.mat-mdc-snackbar-surface{outline:solid 1px}}.mat-mdc-snack-bar-container .mat-mdc-snackbar-surface{color:var(--mat-snack-bar-supporting-text-color, var(--mat-sys-inverse-on-surface));border-radius:var(--mat-snack-bar-container-shape, var(--mat-sys-corner-extra-small));background-color:var(--mat-snack-bar-container-color, var(--mat-sys-inverse-surface))}.mdc-snackbar__label{width:100%;flex-grow:1;box-sizing:border-box;margin:0;padding:14px 8px 14px 16px}[dir=rtl] .mdc-snackbar__label{padding-left:8px;padding-right:16px}.mat-mdc-snack-bar-container .mdc-snackbar__label{font-family:var(--mat-snack-bar-supporting-text-font, var(--mat-sys-body-medium-font));font-size:var(--mat-snack-bar-supporting-text-size, var(--mat-sys-body-medium-size));font-weight:var(--mat-snack-bar-supporting-text-weight, var(--mat-sys-body-medium-weight));line-height:var(--mat-snack-bar-supporting-text-line-height, var(--mat-sys-body-medium-line-height))}.mat-mdc-snack-bar-actions{display:flex;flex-shrink:0;align-items:center;box-sizing:border-box}.mat-mdc-snack-bar-handset,.mat-mdc-snack-bar-container,.mat-mdc-snack-bar-label{flex:1 1 auto}.mat-mdc-snack-bar-container .mat-mdc-button.mat-mdc-snack-bar-action:not(:disabled){--mat-button-text-state-layer-color: currentColor;--mat-button-text-ripple-color: currentColor}.mat-mdc-snack-bar-container .mat-mdc-button.mat-mdc-snack-bar-action:not(:disabled).mat-unthemed{color:var(--mat-snack-bar-button-color, var(--mat-sys-inverse-primary))}.mat-mdc-snack-bar-container .mat-mdc-button.mat-mdc-snack-bar-action:not(:disabled) .mat-ripple-element{opacity:.1}
`],
        encapsulation: 2
      })
    }
    return i
  })();
  hp = new v("mat-snack-bar-default-options", {
    providedIn: "root",
    factory: up
  }), _s = (() => {
    class i {
      _live = l(is);
      _injector = l(N);
      _breakpointObserver = l(xn);
      _parentSnackBar = l(i, {
        optional: !0,
        skipSelf: !0
      });
      _defaultConfig = l(hp);
      _animationsDisabled = Gt();
      _snackBarRefAtThisLevel = null;
      simpleSnackBarComponent = tu;
      snackBarContainerComponent = dp;
      handsetCssClass = "mat-mdc-snack-bar-handset";
      get _openedSnackBarRef() {
        let t = this._parentSnackBar;
        return t ? t._openedSnackBarRef : this._snackBarRefAtThisLevel
      }
      set _openedSnackBarRef(t) {
        this._parentSnackBar ? this._parentSnackBar._openedSnackBarRef = t : this._snackBarRefAtThisLevel = t
      }
      constructor() {}
      openFromComponent(t, e) {
        return this._attach(t, e)
      }
      openFromTemplate(t, e) {
        return this._attach(t, e)
      }
      open(t, e = "", r) {
        let o = h(h({}, this._defaultConfig), r);
        return o.data = {
          message: t,
          action: e
        }, o.announcementMessage === t && (o.announcementMessage = void 0), this.openFromComponent(this.simpleSnackBarComponent, o)
      }
      dismiss() {
        this._openedSnackBarRef && this._openedSnackBarRef.dismiss()
      }
      ngOnDestroy() {
        this._snackBarRefAtThisLevel && this._snackBarRefAtThisLevel.dismiss()
      }
      _attachSnackBarContainer(t, e) {
        let r = e && e.viewContainerRef && e.viewContainerRef.injector,
          o = N.create({
            parent: r || this._injector,
            providers: [{
              provide: Fi,
              useValue: e
            }]
          }),
          a = new Di(this.snackBarContainerComponent, e.viewContainerRef, o),
          s = t.attach(a);
        return s.instance.snackBarConfig = e, s.instance
      }
      _attach(t, e) {
        let r = h(h(h({}, new Fi), this._defaultConfig), e),
          o = this._createOverlay(r),
          a = this._attachSnackBarContainer(o, r),
          s = new On(a, o);
        if (t instanceof Oe) {
          let c = new Ce(t, null, {
            $implicit: r.data,
            snackBarRef: s
          });
          s.instance = a.attachTemplatePortal(c)
        } else {
          let c = this._createInjector(r, s),
            d = new Di(t, void 0, c),
            u = a.attachComponentPortal(d);
          s.instance = u.instance
        }
        return this._breakpointObserver.observe(ed.HandsetPortrait).pipe(Dt(o.detachments())).subscribe(c => {
          o.overlayElement.classList.toggle(this.handsetCssClass, c.matches)
        }), r.announcementMessage && a._onAnnounce.subscribe(() => {
          this._live.announce(r.announcementMessage, r.politeness)
        }), this._animateSnackBar(s, r), this._openedSnackBarRef = s, this._openedSnackBarRef
      }
      _animateSnackBar(t, e) {
        t.afterDismissed().subscribe(() => {
          this._openedSnackBarRef == t && (this._openedSnackBarRef = null), e.announcementMessage && this._live.clear()
        }), e.duration && e.duration > 0 && t.afterOpened().subscribe(() => t._dismissAfter(e.duration)), this._openedSnackBarRef ? (this._openedSnackBarRef.afterDismissed().subscribe(() => {
          t.containerInstance.enter()
        }), this._openedSnackBarRef.dismiss()) : t.containerInstance.enter()
      }
      _createOverlay(t) {
        let e = new We;
        e.direction = t.direction;
        let r = $r(this._injector),
          o = t.direction === "rtl",
          a = t.horizontalPosition === "left" || t.horizontalPosition === "start" && !o || t.horizontalPosition === "end" && o,
          s = !a && t.horizontalPosition !== "center";
        return a ? r.left("0") : s ? r.right("0") : r.centerHorizontally(), t.verticalPosition === "top" ? r.top("0") : r.bottom("0"), e.positionStrategy = r, e.disableAnimations = this._animationsDisabled, Cn(this._injector, e)
      }
      _createInjector(t, e) {
        let r = t && t.viewContainerRef && t.viewContainerRef.injector;
        return N.create({
          parent: r || this._injector,
          providers: [{
            provide: On,
            useValue: e
          }, {
            provide: Jd,
            useValue: t.data
          }]
        })
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Q0 = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        providers: [_s],
        imports: [qa, Fr, Xd, X, tu, X]
      })
    }
    return i
  })()
});

function gp() {
  let i = zo() ? zo().getUserAgent() : "";
  return /android (\d+)/.test(i.toLowerCase())
}

function ys(i) {
  return i == null || Cs(i) === 0
}

function Cs(i) {
  return i == null ? null : Array.isArray(i) || typeof i == "string" ? i.length : i instanceof Set ? i.size : null
}

function bp(i) {
  return n => {
    if (n.value == null || i == null) return null;
    let t = parseFloat(n.value);
    return !isNaN(t) && t < i ? {
      min: {
        min: i,
        actual: n.value
      }
    } : null
  }
}

function yp(i) {
  return n => {
    if (n.value == null || i == null) return null;
    let t = parseFloat(n.value);
    return !isNaN(t) && t > i ? {
      max: {
        max: i,
        actual: n.value
      }
    } : null
  }
}

function uu(i) {
  return ys(i.value) ? {
    required: !0
  } : null
}

function Cp(i) {
  return i.value === !0 ? null : {
    required: !0
  }
}

function xp(i) {
  return ys(i.value) || _p.test(i.value) ? null : {
    email: !0
  }
}

function hu(i) {
  return n => {
    let t = n.value?.length ?? Cs(n.value);
    return t === null || t === 0 ? null : t < i ? {
      minlength: {
        requiredLength: i,
        actualLength: t
      }
    } : null
  }
}

function mu(i) {
  return n => {
    let t = n.value?.length ?? Cs(n.value);
    return t !== null && t > i ? {
      maxlength: {
        requiredLength: i,
        actualLength: t
      }
    } : null
  }
}

function fu(i) {
  if (!i) return so;
  let n, t;
  return typeof i == "string" ? (t = "", i.charAt(0) !== "^" && (t += "^"), t += i, i.charAt(i.length - 1) !== "$" && (t += "$"), n = new RegExp(t)) : (t = i.toString(), n = i), e => {
    if (ys(e.value)) return null;
    let r = e.value;
    return n.test(r) ? null : {
      pattern: {
        requiredPattern: t,
        actualValue: r
      }
    }
  }
}

function so(i) {
  return null
}

function pu(i) {
  return i != null
}

function gu(i) {
  return Yn(i) ? pt(i) : i
}

function vu(i) {
  let n = {};
  return i.forEach(t => {
    n = t != null ? h(h({}, n), t) : n
  }), Object.keys(n).length === 0 ? null : n
}

function _u(i, n) {
  return n.map(t => t(i))
}

function wp(i) {
  return !i.validate
}

function bu(i) {
  return i.map(n => wp(n) ? n : t => n.validate(t))
}

function yu(i) {
  if (!i) return null;
  let n = i.filter(pu);
  return n.length == 0 ? null : function(t) {
    return vu(_u(t, n))
  }
}

function xs(i) {
  return i != null ? yu(bu(i)) : null
}

function Cu(i) {
  if (!i) return null;
  let n = i.filter(pu);
  return n.length == 0 ? null : function(t) {
    let e = _u(t, n).map(gu);
    return Ze(e).pipe(b(vu))
  }
}

function ws(i) {
  return i != null ? Cu(bu(i)) : null
}

function iu(i, n) {
  return i === null ? [n] : Array.isArray(i) ? [...i, n] : [i, n]
}

function xu(i) {
  return i._rawValidators
}

function wu(i) {
  return i._rawAsyncValidators
}

function bs(i) {
  return i ? Array.isArray(i) ? i : [i] : []
}

function lo(i, n) {
  return Array.isArray(i) ? i.includes(n) : i === n
}

function nu(i, n) {
  let t = bs(n);
  return bs(i).forEach(r => {
    lo(t, r) || t.push(r)
  }), t
}

function ru(i, n) {
  return bs(n).filter(t => !lo(i, t))
}

function Eu(i) {
  return (bo(i) ? i.validators : i) || null
}

function Sp(i) {
  return Array.isArray(i) ? xs(i) : i || null
}

function Su(i, n) {
  return (bo(n) ? n.asyncValidators : i) || null
}

function Dp(i) {
  return Array.isArray(i) ? ws(i) : i || null
}

function bo(i) {
  return i != null && !Array.isArray(i) && typeof i == "object"
}

function Rp(i, n, t) {
  let e = i.controls;
  if (!(n ? Object.keys(e) : e).length) throw new Q(1e3, "");
  if (!e[t]) throw new Q(1001, "")
}

function Ap(i, n, t) {
  i._forEachChild((e, r) => {
    if (t[r] === void 0) throw new Q(1002, "")
  })
}

function Du(i, n) {
  return [...n.path, i]
}

function Vn(i, n, t = yo) {
  Es(i, n), n.valueAccessor.writeValue(i.value), (i.disabled || t === "always") && n.valueAccessor.setDisabledState?.(i.disabled), Ip(i, n), kp(i, n), Op(i, n), Mp(i, n)
}

function go(i, n, t = !0) {
  let e = () => {};
  n.valueAccessor && (n.valueAccessor.registerOnChange(e), n.valueAccessor.registerOnTouched(e)), _o(i, n), i && (n._invokeOnDestroyCallbacks(), i._registerOnCollectionChange(() => {}))
}

function vo(i, n) {
  i.forEach(t => {
    t.registerOnValidatorChange && t.registerOnValidatorChange(n)
  })
}

function Mp(i, n) {
  if (n.valueAccessor.setDisabledState) {
    let t = e => {
      n.valueAccessor.setDisabledState(e)
    };
    i.registerOnDisabledChange(t), n._registerOnDestroy(() => {
      i._unregisterOnDisabledChange(t)
    })
  }
}

function Es(i, n) {
  let t = xu(i);
  n.validator !== null ? i.setValidators(iu(t, n.validator)) : typeof t == "function" && i.setValidators([t]);
  let e = wu(i);
  n.asyncValidator !== null ? i.setAsyncValidators(iu(e, n.asyncValidator)) : typeof e == "function" && i.setAsyncValidators([e]);
  let r = () => i.updateValueAndValidity();
  vo(n._rawValidators, r), vo(n._rawAsyncValidators, r)
}

function _o(i, n) {
  let t = !1;
  if (i !== null) {
    if (n.validator !== null) {
      let r = xu(i);
      if (Array.isArray(r) && r.length > 0) {
        let o = r.filter(a => a !== n.validator);
        o.length !== r.length && (t = !0, i.setValidators(o))
      }
    }
    if (n.asyncValidator !== null) {
      let r = wu(i);
      if (Array.isArray(r) && r.length > 0) {
        let o = r.filter(a => a !== n.asyncValidator);
        o.length !== r.length && (t = !0, i.setAsyncValidators(o))
      }
    }
  }
  let e = () => {};
  return vo(n._rawValidators, e), vo(n._rawAsyncValidators, e), t
}

function Ip(i, n) {
  n.valueAccessor.registerOnChange(t => {
    i._pendingValue = t, i._pendingChange = !0, i._pendingDirty = !0, i.updateOn === "change" && Ru(i, n)
  })
}

function Op(i, n) {
  n.valueAccessor.registerOnTouched(() => {
    i._pendingTouched = !0, i.updateOn === "blur" && i._pendingChange && Ru(i, n), i.updateOn !== "submit" && i.markAsTouched()
  })
}

function Ru(i, n) {
  i._pendingDirty && i.markAsDirty(), i.setValue(i._pendingValue, {
    emitModelToViewChange: !1
  }), n.viewToModelUpdate(i._pendingValue), i._pendingChange = !1
}

function kp(i, n) {
  let t = (e, r) => {
    n.valueAccessor.writeValue(e), r && n.viewToModelUpdate(e)
  };
  i.registerOnChange(t), n._registerOnDestroy(() => {
    i._unregisterOnChange(t)
  })
}

function Au(i, n) {
  i == null, Es(i, n)
}

function Tp(i, n) {
  return _o(i, n)
}

function Ss(i, n) {
  if (!i.hasOwnProperty("model")) return !1;
  let t = i.model;
  return t.isFirstChange() ? !0 : !Object.is(n, t.currentValue)
}

function Fp(i) {
  return Object.getPrototypeOf(i.constructor) === jn
}

function Mu(i, n) {
  i._syncPendingControls(), n.forEach(t => {
    let e = t.control;
    e.updateOn === "submit" && e._pendingChange && (t.viewToModelUpdate(e._pendingValue), e._pendingChange = !1)
  })
}

function Ds(i, n) {
  if (!n) return null;
  Array.isArray(n);
  let t, e, r;
  return n.forEach(o => {
    o.constructor === du ? t = o : Fp(o) ? e = o : r = o
  }), r || e || t || null
}

function Np(i, n) {
  let t = i.indexOf(n);
  t > -1 && i.splice(t, 1)
}

function ou(i, n) {
  let t = i.indexOf(n);
  t > -1 && i.splice(t, 1)
}

function au(i) {
  return typeof i == "object" && i !== null && Object.keys(i).length === 2 && "value" in i && "disabled" in i
}

function Iu(i, n) {
  return i == null ? `${n}` : (n && typeof n == "object" && (n = "Object"), `${i}: ${n}`.slice(0, 50))
}

function Yp(i) {
  return i.split(":")[0]
}

function lu(i, n) {
  return i == null ? `${n}` : (typeof n == "string" && (n = `'${n}'`), n && typeof n == "object" && (n = "Object"), `${i}: ${n}`.slice(0, 50))
}

function Zp(i) {
  return i.split(":")[0]
}

function Tu(i) {
  return typeof i == "number" ? i : parseInt(i, 10)
}
var cu, jn, Se, mp, fp, pp, vp, du, ue, Bn, _p, ao, co, de, qt, uo, Ep, vw, _w, bw, kn, oo, Ni, Tn, Ee, ho, Nn, Pn, Pi, mo, fo, po, Ln, yw, Li, yo, Pp, Fn, Rs, As, xw, Lp, Vp, su, jp, ww, Bp, zp, Ms, Up, Hp, $p, Is, Wp, Gp, qp, Ou, Ew, Kp, ku, Sw, Co, Xp, Qp, Jp, tg, eg, ig, ng, rg, Fu, Dw, Rw, Nu = _(() => {
  f();
  f();
  Pe();
  nt();
  ht();
  cu = (() => {
    class i {
      _renderer;
      _elementRef;
      onChange = t => {};
      onTouched = () => {};
      constructor(t, e) {
        this._renderer = t, this._elementRef = e
      }
      setProperty(t, e) {
        this._renderer.setProperty(this._elementRef.nativeElement, t, e)
      }
      registerOnTouched(t) {
        this.onTouched = t
      }
      registerOnChange(t) {
        this.onChange = t
      }
      setDisabledState(t) {
        this.setProperty("disabled", t)
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(lt), C(D))
      };
      static \u0275dir = p({
        type: i
      })
    }
    return i
  })(), jn = (() => {
    class i extends cu {
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        features: [L]
      })
    }
    return i
  })(), Se = new v(""), mp = {
    provide: Se,
    useExisting: gt(() => fp),
    multi: !0
  }, fp = (() => {
    class i extends jn {
      writeValue(t) {
        this.setProperty("checked", t)
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["input", "type", "checkbox", "formControlName", ""],
          ["input", "type", "checkbox", "formControl", ""],
          ["input", "type", "checkbox", "ngModel", ""]
        ],
        hostBindings: function(e, r) {
          e & 1 && dt("change", function(a) {
            return r.onChange(a.target.checked)
          })("blur", function() {
            return r.onTouched()
          })
        },
        standalone: !1,
        features: [z([mp]), L]
      })
    }
    return i
  })(), pp = {
    provide: Se,
    useExisting: gt(() => du),
    multi: !0
  };
  vp = new v(""), du = (() => {
    class i extends cu {
      _compositionMode;
      _composing = !1;
      constructor(t, e, r) {
        super(t, e), this._compositionMode = r, this._compositionMode == null && (this._compositionMode = !gp())
      }
      writeValue(t) {
        let e = t ?? "";
        this.setProperty("value", e)
      }
      _handleInput(t) {
        (!this._compositionMode || this._compositionMode && !this._composing) && this.onChange(t)
      }
      _compositionStart() {
        this._composing = !0
      }
      _compositionEnd(t) {
        this._composing = !1, this._compositionMode && this.onChange(t)
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(lt), C(D), C(vp, 8))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["input", "formControlName", "", 3, "type", "checkbox"],
          ["textarea", "formControlName", ""],
          ["input", "formControl", "", 3, "type", "checkbox"],
          ["textarea", "formControl", ""],
          ["input", "ngModel", "", 3, "type", "checkbox"],
          ["textarea", "ngModel", ""],
          ["", "ngDefaultControl", ""]
        ],
        hostBindings: function(e, r) {
          e & 1 && dt("input", function(a) {
            return r._handleInput(a.target.value)
          })("blur", function() {
            return r.onTouched()
          })("compositionstart", function() {
            return r._compositionStart()
          })("compositionend", function(a) {
            return r._compositionEnd(a.target.value)
          })
        },
        standalone: !1,
        features: [z([pp]), L]
      })
    }
    return i
  })();
  ue = new v(""), Bn = new v(""), _p = /^(?=.{1,254}$)(?=.{1,64}@)[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/, ao = class {
    static min(n) {
      return bp(n)
    }
    static max(n) {
      return yp(n)
    }
    static required(n) {
      return uu(n)
    }
    static requiredTrue(n) {
      return Cp(n)
    }
    static email(n) {
      return xp(n)
    }
    static minLength(n) {
      return hu(n)
    }
    static maxLength(n) {
      return mu(n)
    }
    static pattern(n) {
      return fu(n)
    }
    static nullValidator(n) {
      return so()
    }
    static compose(n) {
      return yu(n)
    }
    static composeAsync(n) {
      return Cu(n)
    }
  };
  co = class {
    get value() {
      return this.control ? this.control.value : null
    }
    get valid() {
      return this.control ? this.control.valid : null
    }
    get invalid() {
      return this.control ? this.control.invalid : null
    }
    get pending() {
      return this.control ? this.control.pending : null
    }
    get disabled() {
      return this.control ? this.control.disabled : null
    }
    get enabled() {
      return this.control ? this.control.enabled : null
    }
    get errors() {
      return this.control ? this.control.errors : null
    }
    get pristine() {
      return this.control ? this.control.pristine : null
    }
    get dirty() {
      return this.control ? this.control.dirty : null
    }
    get touched() {
      return this.control ? this.control.touched : null
    }
    get status() {
      return this.control ? this.control.status : null
    }
    get untouched() {
      return this.control ? this.control.untouched : null
    }
    get statusChanges() {
      return this.control ? this.control.statusChanges : null
    }
    get valueChanges() {
      return this.control ? this.control.valueChanges : null
    }
    get path() {
      return null
    }
    _composedValidatorFn;_composedAsyncValidatorFn;_rawValidators = [];_rawAsyncValidators = [];_setValidators(n) {
      this._rawValidators = n || [], this._composedValidatorFn = xs(this._rawValidators)
    }
    _setAsyncValidators(n) {
      this._rawAsyncValidators = n || [], this._composedAsyncValidatorFn = ws(this._rawAsyncValidators)
    }
    get validator() {
      return this._composedValidatorFn || null
    }
    get asyncValidator() {
      return this._composedAsyncValidatorFn || null
    }
    _onDestroyCallbacks = [];_registerOnDestroy(n) {
      this._onDestroyCallbacks.push(n)
    }
    _invokeOnDestroyCallbacks() {
      this._onDestroyCallbacks.forEach(n => n()), this._onDestroyCallbacks = []
    }
    reset(n = void 0) {
      this.control && this.control.reset(n)
    }
    hasError(n, t) {
      return this.control ? this.control.hasError(n, t) : !1
    }
    getError(n, t) {
      return this.control ? this.control.getError(n, t) : null
    }
  }, de = class extends co {
    name;
    get formDirective() {
      return null
    }
    get path() {
      return null
    }
  }, qt = class extends co {
    _parent = null;
    name = null;
    valueAccessor = null
  }, uo = class {
    _cd;
    constructor(n) {
      this._cd = n
    }
    get isTouched() {
      return this._cd?.control?._touched?.(), !!this._cd?.control?.touched
    }
    get isUntouched() {
      return !!this._cd?.control?.untouched
    }
    get isPristine() {
      return this._cd?.control?._pristine?.(), !!this._cd?.control?.pristine
    }
    get isDirty() {
      return !!this._cd?.control?.dirty
    }
    get isValid() {
      return this._cd?.control?._status?.(), !!this._cd?.control?.valid
    }
    get isInvalid() {
      return !!this._cd?.control?.invalid
    }
    get isPending() {
      return !!this._cd?.control?.pending
    }
    get isSubmitted() {
      return this._cd?._submitted?.(), !!this._cd?.submitted
    }
  }, Ep = {
    "[class.ng-untouched]": "isUntouched",
    "[class.ng-touched]": "isTouched",
    "[class.ng-pristine]": "isPristine",
    "[class.ng-dirty]": "isDirty",
    "[class.ng-valid]": "isValid",
    "[class.ng-invalid]": "isInvalid",
    "[class.ng-pending]": "isPending"
  }, vw = $(h({}, Ep), {
    "[class.ng-submitted]": "isSubmitted"
  }), _w = (() => {
    class i extends uo {
      constructor(t) {
        super(t)
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(qt, 2))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "formControlName", ""],
          ["", "ngModel", ""],
          ["", "formControl", ""]
        ],
        hostVars: 14,
        hostBindings: function(e, r) {
          e & 2 && H("ng-untouched", r.isUntouched)("ng-touched", r.isTouched)("ng-pristine", r.isPristine)("ng-dirty", r.isDirty)("ng-valid", r.isValid)("ng-invalid", r.isInvalid)("ng-pending", r.isPending)
        },
        standalone: !1,
        features: [L]
      })
    }
    return i
  })(), bw = (() => {
    class i extends uo {
      constructor(t) {
        super(t)
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(de, 10))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "formGroupName", ""],
          ["", "formArrayName", ""],
          ["", "ngModelGroup", ""],
          ["", "formGroup", ""],
          ["form", 3, "ngNoForm", ""],
          ["", "ngForm", ""]
        ],
        hostVars: 16,
        hostBindings: function(e, r) {
          e & 2 && H("ng-untouched", r.isUntouched)("ng-touched", r.isTouched)("ng-pristine", r.isPristine)("ng-dirty", r.isDirty)("ng-valid", r.isValid)("ng-invalid", r.isInvalid)("ng-pending", r.isPending)("ng-submitted", r.isSubmitted)
        },
        standalone: !1,
        features: [L]
      })
    }
    return i
  })(), kn = "VALID", oo = "INVALID", Ni = "PENDING", Tn = "DISABLED", Ee = class {}, ho = class extends Ee {
    value;
    source;
    constructor(n, t) {
      super(), this.value = n, this.source = t
    }
  }, Nn = class extends Ee {
    pristine;
    source;
    constructor(n, t) {
      super(), this.pristine = n, this.source = t
    }
  }, Pn = class extends Ee {
    touched;
    source;
    constructor(n, t) {
      super(), this.touched = n, this.source = t
    }
  }, Pi = class extends Ee {
    status;
    source;
    constructor(n, t) {
      super(), this.status = n, this.source = t
    }
  }, mo = class extends Ee {
    source;
    constructor(n) {
      super(), this.source = n
    }
  }, fo = class extends Ee {
    source;
    constructor(n) {
      super(), this.source = n
    }
  };
  po = class {
    _pendingDirty = !1;
    _hasOwnPendingAsyncValidator = null;
    _pendingTouched = !1;
    _onCollectionChange = () => {};
    _updateOn;
    _parent = null;
    _asyncValidationSubscription;
    _composedValidatorFn;
    _composedAsyncValidatorFn;
    _rawValidators;
    _rawAsyncValidators;
    value;
    constructor(n, t) {
      this._assignValidators(n), this._assignAsyncValidators(t)
    }
    get validator() {
      return this._composedValidatorFn
    }
    set validator(n) {
      this._rawValidators = this._composedValidatorFn = n
    }
    get asyncValidator() {
      return this._composedAsyncValidatorFn
    }
    set asyncValidator(n) {
      this._rawAsyncValidators = this._composedAsyncValidatorFn = n
    }
    get parent() {
      return this._parent
    }
    get status() {
      return ut(this.statusReactive)
    }
    set status(n) {
      ut(() => this.statusReactive.set(n))
    }
    _status = Zt(() => this.statusReactive());
    statusReactive = J(void 0);
    get valid() {
      return this.status === kn
    }
    get invalid() {
      return this.status === oo
    }
    get pending() {
      return this.status == Ni
    }
    get disabled() {
      return this.status === Tn
    }
    get enabled() {
      return this.status !== Tn
    }
    errors;
    get pristine() {
      return ut(this.pristineReactive)
    }
    set pristine(n) {
      ut(() => this.pristineReactive.set(n))
    }
    _pristine = Zt(() => this.pristineReactive());
    pristineReactive = J(!0);
    get dirty() {
      return !this.pristine
    }
    get touched() {
      return ut(this.touchedReactive)
    }
    set touched(n) {
      ut(() => this.touchedReactive.set(n))
    }
    _touched = Zt(() => this.touchedReactive());
    touchedReactive = J(!1);
    get untouched() {
      return !this.touched
    }
    _events = new y;
    events = this._events.asObservable();
    valueChanges;
    statusChanges;
    get updateOn() {
      return this._updateOn ? this._updateOn : this.parent ? this.parent.updateOn : "change"
    }
    setValidators(n) {
      this._assignValidators(n)
    }
    setAsyncValidators(n) {
      this._assignAsyncValidators(n)
    }
    addValidators(n) {
      this.setValidators(nu(n, this._rawValidators))
    }
    addAsyncValidators(n) {
      this.setAsyncValidators(nu(n, this._rawAsyncValidators))
    }
    removeValidators(n) {
      this.setValidators(ru(n, this._rawValidators))
    }
    removeAsyncValidators(n) {
      this.setAsyncValidators(ru(n, this._rawAsyncValidators))
    }
    hasValidator(n) {
      return lo(this._rawValidators, n)
    }
    hasAsyncValidator(n) {
      return lo(this._rawAsyncValidators, n)
    }
    clearValidators() {
      this.validator = null
    }
    clearAsyncValidators() {
      this.asyncValidator = null
    }
    markAsTouched(n = {}) {
      let t = this.touched === !1;
      this.touched = !0;
      let e = n.sourceControl ?? this;
      this._parent && !n.onlySelf && this._parent.markAsTouched($(h({}, n), {
        sourceControl: e
      })), t && n.emitEvent !== !1 && this._events.next(new Pn(!0, e))
    }
    markAllAsDirty(n = {}) {
      this.markAsDirty({
        onlySelf: !0,
        emitEvent: n.emitEvent,
        sourceControl: this
      }), this._forEachChild(t => t.markAllAsDirty(n))
    }
    markAllAsTouched(n = {}) {
      this.markAsTouched({
        onlySelf: !0,
        emitEvent: n.emitEvent,
        sourceControl: this
      }), this._forEachChild(t => t.markAllAsTouched(n))
    }
    markAsUntouched(n = {}) {
      let t = this.touched === !0;
      this.touched = !1, this._pendingTouched = !1;
      let e = n.sourceControl ?? this;
      this._forEachChild(r => {
        r.markAsUntouched({
          onlySelf: !0,
          emitEvent: n.emitEvent,
          sourceControl: e
        })
      }), this._parent && !n.onlySelf && this._parent._updateTouched(n, e), t && n.emitEvent !== !1 && this._events.next(new Pn(!1, e))
    }
    markAsDirty(n = {}) {
      let t = this.pristine === !0;
      this.pristine = !1;
      let e = n.sourceControl ?? this;
      this._parent && !n.onlySelf && this._parent.markAsDirty($(h({}, n), {
        sourceControl: e
      })), t && n.emitEvent !== !1 && this._events.next(new Nn(!1, e))
    }
    markAsPristine(n = {}) {
      let t = this.pristine === !1;
      this.pristine = !0, this._pendingDirty = !1;
      let e = n.sourceControl ?? this;
      this._forEachChild(r => {
        r.markAsPristine({
          onlySelf: !0,
          emitEvent: n.emitEvent
        })
      }), this._parent && !n.onlySelf && this._parent._updatePristine(n, e), t && n.emitEvent !== !1 && this._events.next(new Nn(!0, e))
    }
    markAsPending(n = {}) {
      this.status = Ni;
      let t = n.sourceControl ?? this;
      n.emitEvent !== !1 && (this._events.next(new Pi(this.status, t)), this.statusChanges.emit(this.status)), this._parent && !n.onlySelf && this._parent.markAsPending($(h({}, n), {
        sourceControl: t
      }))
    }
    disable(n = {}) {
      let t = this._parentMarkedDirty(n.onlySelf);
      this.status = Tn, this.errors = null, this._forEachChild(r => {
        r.disable($(h({}, n), {
          onlySelf: !0
        }))
      }), this._updateValue();
      let e = n.sourceControl ?? this;
      n.emitEvent !== !1 && (this._events.next(new ho(this.value, e)), this._events.next(new Pi(this.status, e)), this.valueChanges.emit(this.value), this.statusChanges.emit(this.status)), this._updateAncestors($(h({}, n), {
        skipPristineCheck: t
      }), this), this._onDisabledChange.forEach(r => r(!0))
    }
    enable(n = {}) {
      let t = this._parentMarkedDirty(n.onlySelf);
      this.status = kn, this._forEachChild(e => {
        e.enable($(h({}, n), {
          onlySelf: !0
        }))
      }), this.updateValueAndValidity({
        onlySelf: !0,
        emitEvent: n.emitEvent
      }), this._updateAncestors($(h({}, n), {
        skipPristineCheck: t
      }), this), this._onDisabledChange.forEach(e => e(!1))
    }
    _updateAncestors(n, t) {
      this._parent && !n.onlySelf && (this._parent.updateValueAndValidity(n), n.skipPristineCheck || this._parent._updatePristine({}, t), this._parent._updateTouched({}, t))
    }
    setParent(n) {
      this._parent = n
    }
    getRawValue() {
      return this.value
    }
    updateValueAndValidity(n = {}) {
      if (this._setInitialStatus(), this._updateValue(), this.enabled) {
        let e = this._cancelExistingSubscription();
        this.errors = this._runValidator(), this.status = this._calculateStatus(), (this.status === kn || this.status === Ni) && this._runAsyncValidator(e, n.emitEvent)
      }
      let t = n.sourceControl ?? this;
      n.emitEvent !== !1 && (this._events.next(new ho(this.value, t)), this._events.next(new Pi(this.status, t)), this.valueChanges.emit(this.value), this.statusChanges.emit(this.status)), this._parent && !n.onlySelf && this._parent.updateValueAndValidity($(h({}, n), {
        sourceControl: t
      }))
    }
    _updateTreeValidity(n = {
      emitEvent: !0
    }) {
      this._forEachChild(t => t._updateTreeValidity(n)), this.updateValueAndValidity({
        onlySelf: !0,
        emitEvent: n.emitEvent
      })
    }
    _setInitialStatus() {
      this.status = this._allControlsDisabled() ? Tn : kn
    }
    _runValidator() {
      return this.validator ? this.validator(this) : null
    }
    _runAsyncValidator(n, t) {
      if (this.asyncValidator) {
        this.status = Ni, this._hasOwnPendingAsyncValidator = {
          emitEvent: t !== !1,
          shouldHaveEmitted: n !== !1
        };
        let e = gu(this.asyncValidator(this));
        this._asyncValidationSubscription = e.subscribe(r => {
          this._hasOwnPendingAsyncValidator = null, this.setErrors(r, {
            emitEvent: t,
            shouldHaveEmitted: n
          })
        })
      }
    }
    _cancelExistingSubscription() {
      if (this._asyncValidationSubscription) {
        this._asyncValidationSubscription.unsubscribe();
        let n = (this._hasOwnPendingAsyncValidator?.emitEvent || this._hasOwnPendingAsyncValidator?.shouldHaveEmitted) ?? !1;
        return this._hasOwnPendingAsyncValidator = null, n
      }
      return !1
    }
    setErrors(n, t = {}) {
      this.errors = n, this._updateControlsErrors(t.emitEvent !== !1, this, t.shouldHaveEmitted)
    }
    get(n) {
      let t = n;
      return t == null || (Array.isArray(t) || (t = t.split(".")), t.length === 0) ? null : t.reduce((e, r) => e && e._find(r), this)
    }
    getError(n, t) {
      let e = t ? this.get(t) : this;
      return e && e.errors ? e.errors[n] : null
    }
    hasError(n, t) {
      return !!this.getError(n, t)
    }
    get root() {
      let n = this;
      for (; n._parent;) n = n._parent;
      return n
    }
    _updateControlsErrors(n, t, e) {
      this.status = this._calculateStatus(), n && this.statusChanges.emit(this.status), (n || e) && this._events.next(new Pi(this.status, t)), this._parent && this._parent._updateControlsErrors(n, t, e)
    }
    _initObservables() {
      this.valueChanges = new A, this.statusChanges = new A
    }
    _calculateStatus() {
      return this._allControlsDisabled() ? Tn : this.errors ? oo : this._hasOwnPendingAsyncValidator || this._anyControlsHaveStatus(Ni) ? Ni : this._anyControlsHaveStatus(oo) ? oo : kn
    }
    _anyControlsHaveStatus(n) {
      return this._anyControls(t => t.status === n)
    }
    _anyControlsDirty() {
      return this._anyControls(n => n.dirty)
    }
    _anyControlsTouched() {
      return this._anyControls(n => n.touched)
    }
    _updatePristine(n, t) {
      let e = !this._anyControlsDirty(),
        r = this.pristine !== e;
      this.pristine = e, this._parent && !n.onlySelf && this._parent._updatePristine(n, t), r && this._events.next(new Nn(this.pristine, t))
    }
    _updateTouched(n = {}, t) {
      this.touched = this._anyControlsTouched(), this._events.next(new Pn(this.touched, t)), this._parent && !n.onlySelf && this._parent._updateTouched(n, t)
    }
    _onDisabledChange = [];
    _registerOnCollectionChange(n) {
      this._onCollectionChange = n
    }
    _setUpdateStrategy(n) {
      bo(n) && n.updateOn != null && (this._updateOn = n.updateOn)
    }
    _parentMarkedDirty(n) {
      let t = this._parent && this._parent.dirty;
      return !n && !!t && !this._parent._anyControlsDirty()
    }
    _find(n) {
      return null
    }
    _assignValidators(n) {
      this._rawValidators = Array.isArray(n) ? n.slice() : n, this._composedValidatorFn = Sp(this._rawValidators)
    }
    _assignAsyncValidators(n) {
      this._rawAsyncValidators = Array.isArray(n) ? n.slice() : n, this._composedAsyncValidatorFn = Dp(this._rawAsyncValidators)
    }
  }, Ln = class extends po {
    constructor(n, t, e) {
      super(Eu(t), Su(e, t)), this.controls = n, this._initObservables(), this._setUpdateStrategy(t), this._setUpControls(), this.updateValueAndValidity({
        onlySelf: !0,
        emitEvent: !!this.asyncValidator
      })
    }
    controls;
    registerControl(n, t) {
      return this.controls[n] ? this.controls[n] : (this.controls[n] = t, t.setParent(this), t._registerOnCollectionChange(this._onCollectionChange), t)
    }
    addControl(n, t, e = {}) {
      this.registerControl(n, t), this.updateValueAndValidity({
        emitEvent: e.emitEvent
      }), this._onCollectionChange()
    }
    removeControl(n, t = {}) {
      this.controls[n] && this.controls[n]._registerOnCollectionChange(() => {}), delete this.controls[n], this.updateValueAndValidity({
        emitEvent: t.emitEvent
      }), this._onCollectionChange()
    }
    setControl(n, t, e = {}) {
      this.controls[n] && this.controls[n]._registerOnCollectionChange(() => {}), delete this.controls[n], t && this.registerControl(n, t), this.updateValueAndValidity({
        emitEvent: e.emitEvent
      }), this._onCollectionChange()
    }
    contains(n) {
      return this.controls.hasOwnProperty(n) && this.controls[n].enabled
    }
    setValue(n, t = {}) {
      Ap(this, !0, n), Object.keys(n).forEach(e => {
        Rp(this, !0, e), this.controls[e].setValue(n[e], {
          onlySelf: !0,
          emitEvent: t.emitEvent
        })
      }), this.updateValueAndValidity(t)
    }
    patchValue(n, t = {}) {
      n != null && (Object.keys(n).forEach(e => {
        let r = this.controls[e];
        r && r.patchValue(n[e], {
          onlySelf: !0,
          emitEvent: t.emitEvent
        })
      }), this.updateValueAndValidity(t))
    }
    reset(n = {}, t = {}) {
      this._forEachChild((e, r) => {
        e.reset(n ? n[r] : null, {
          onlySelf: !0,
          emitEvent: t.emitEvent
        })
      }), this._updatePristine(t, this), this._updateTouched(t, this), this.updateValueAndValidity(t), t?.emitEvent !== !1 && this._events.next(new fo(this))
    }
    getRawValue() {
      return this._reduceChildren({}, (n, t, e) => (n[e] = t.getRawValue(), n))
    }
    _syncPendingControls() {
      let n = this._reduceChildren(!1, (t, e) => e._syncPendingControls() ? !0 : t);
      return n && this.updateValueAndValidity({
        onlySelf: !0
      }), n
    }
    _forEachChild(n) {
      Object.keys(this.controls).forEach(t => {
        let e = this.controls[t];
        e && n(e, t)
      })
    }
    _setUpControls() {
      this._forEachChild(n => {
        n.setParent(this), n._registerOnCollectionChange(this._onCollectionChange)
      })
    }
    _updateValue() {
      this.value = this._reduceValue()
    }
    _anyControls(n) {
      for (let [t, e] of Object.entries(this.controls))
        if (this.contains(t) && n(e)) return !0;
      return !1
    }
    _reduceValue() {
      let n = {};
      return this._reduceChildren(n, (t, e, r) => ((e.enabled || this.disabled) && (t[r] = e.value), t))
    }
    _reduceChildren(n, t) {
      let e = n;
      return this._forEachChild((r, o) => {
        e = t(e, r, o)
      }), e
    }
    _allControlsDisabled() {
      for (let n of Object.keys(this.controls))
        if (this.controls[n].enabled) return !1;
      return Object.keys(this.controls).length > 0 || this.disabled
    }
    _find(n) {
      return this.controls.hasOwnProperty(n) ? this.controls[n] : null
    }
  }, yw = Ln, Li = new v("", {
    providedIn: "root",
    factory: () => yo
  }), yo = "always";
  Pp = {
    provide: de,
    useExisting: gt(() => Rs)
  }, Fn = Promise.resolve(), Rs = (() => {
    class i extends de {
      callSetDisabledState;
      get submitted() {
        return ut(this.submittedReactive)
      }
      _submitted = Zt(() => this.submittedReactive());
      submittedReactive = J(!1);
      _directives = new Set;
      form;
      ngSubmit = new A;
      options;
      constructor(t, e, r) {
        super(), this.callSetDisabledState = r, this.form = new Ln({}, xs(t), ws(e))
      }
      ngAfterViewInit() {
        this._setUpdateStrategy()
      }
      get formDirective() {
        return this
      }
      get control() {
        return this.form
      }
      get path() {
        return []
      }
      get controls() {
        return this.form.controls
      }
      addControl(t) {
        Fn.then(() => {
          let e = this._findContainer(t.path);
          t.control = e.registerControl(t.name, t.control), Vn(t.control, t, this.callSetDisabledState), t.control.updateValueAndValidity({
            emitEvent: !1
          }), this._directives.add(t)
        })
      }
      getControl(t) {
        return this.form.get(t.path)
      }
      removeControl(t) {
        Fn.then(() => {
          let e = this._findContainer(t.path);
          e && e.removeControl(t.name), this._directives.delete(t)
        })
      }
      addFormGroup(t) {
        Fn.then(() => {
          let e = this._findContainer(t.path),
            r = new Ln({});
          Au(r, t), e.registerControl(t.name, r), r.updateValueAndValidity({
            emitEvent: !1
          })
        })
      }
      removeFormGroup(t) {
        Fn.then(() => {
          let e = this._findContainer(t.path);
          e && e.removeControl(t.name)
        })
      }
      getFormGroup(t) {
        return this.form.get(t.path)
      }
      updateModel(t, e) {
        Fn.then(() => {
          this.form.get(t.path).setValue(e)
        })
      }
      setValue(t) {
        this.control.setValue(t)
      }
      onSubmit(t) {
        return this.submittedReactive.set(!0), Mu(this.form, this._directives), this.ngSubmit.emit(t), this.form._events.next(new mo(this.control)), t?.target?.method === "dialog"
      }
      onReset() {
        this.resetForm()
      }
      resetForm(t = void 0) {
        this.form.reset(t), this.submittedReactive.set(!1)
      }
      _setUpdateStrategy() {
        this.options && this.options.updateOn != null && (this.form._updateOn = this.options.updateOn)
      }
      _findContainer(t) {
        return t.pop(), t.length ? this.form.get(t) : this.form
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(ue, 10), C(Bn, 10), C(Li, 8))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["form", 3, "ngNoForm", "", 3, "formGroup", ""],
          ["ng-form"],
          ["", "ngForm", ""]
        ],
        hostBindings: function(e, r) {
          e & 1 && dt("submit", function(a) {
            return r.onSubmit(a)
          })("reset", function() {
            return r.onReset()
          })
        },
        inputs: {
          options: [0, "ngFormOptions", "options"]
        },
        outputs: {
          ngSubmit: "ngSubmit"
        },
        exportAs: ["ngForm"],
        standalone: !1,
        features: [z([Pp]), L]
      })
    }
    return i
  })();
  As = class extends po {
    defaultValue = null;
    _onChange = [];
    _pendingValue;
    _pendingChange = !1;
    constructor(n = null, t, e) {
      super(Eu(t), Su(e, t)), this._applyFormState(n), this._setUpdateStrategy(t), this._initObservables(), this.updateValueAndValidity({
        onlySelf: !0,
        emitEvent: !!this.asyncValidator
      }), bo(t) && (t.nonNullable || t.initialValueIsDefault) && (au(n) ? this.defaultValue = n.value : this.defaultValue = n)
    }
    setValue(n, t = {}) {
      this.value = this._pendingValue = n, this._onChange.length && t.emitModelToViewChange !== !1 && this._onChange.forEach(e => e(this.value, t.emitViewToModelChange !== !1)), this.updateValueAndValidity(t)
    }
    patchValue(n, t = {}) {
      this.setValue(n, t)
    }
    reset(n = this.defaultValue, t = {}) {
      this._applyFormState(n), this.markAsPristine(t), this.markAsUntouched(t), this.setValue(this.value, t), this._pendingChange = !1, t?.emitEvent !== !1 && this._events.next(new fo(this))
    }
    _updateValue() {}
    _anyControls(n) {
      return !1
    }
    _allControlsDisabled() {
      return this.disabled
    }
    registerOnChange(n) {
      this._onChange.push(n)
    }
    _unregisterOnChange(n) {
      ou(this._onChange, n)
    }
    registerOnDisabledChange(n) {
      this._onDisabledChange.push(n)
    }
    _unregisterOnDisabledChange(n) {
      ou(this._onDisabledChange, n)
    }
    _forEachChild(n) {}
    _syncPendingControls() {
      return this.updateOn === "submit" && (this._pendingDirty && this.markAsDirty(), this._pendingTouched && this.markAsTouched(), this._pendingChange) ? (this.setValue(this._pendingValue, {
        onlySelf: !0,
        emitModelToViewChange: !1
      }), !0) : !1
    }
    _applyFormState(n) {
      au(n) ? (this.value = this._pendingValue = n.value, n.disabled ? this.disable({
        onlySelf: !0,
        emitEvent: !1
      }) : this.enable({
        onlySelf: !0,
        emitEvent: !1
      })) : this.value = this._pendingValue = n
    }
  }, xw = As, Lp = i => i instanceof As, Vp = {
    provide: qt,
    useExisting: gt(() => jp)
  }, su = Promise.resolve(), jp = (() => {
    class i extends qt {
      _changeDetectorRef;
      callSetDisabledState;
      control = new As;
      static ngAcceptInputType_isDisabled;
      _registered = !1;
      viewModel;
      name = "";
      isDisabled;
      model;
      options;
      update = new A;
      constructor(t, e, r, o, a, s) {
        super(), this._changeDetectorRef = a, this.callSetDisabledState = s, this._parent = t, this._setValidators(e), this._setAsyncValidators(r), this.valueAccessor = Ds(this, o)
      }
      ngOnChanges(t) {
        if (this._checkForErrors(), !this._registered || "name" in t) {
          if (this._registered && (this._checkName(), this.formDirective)) {
            let e = t.name.previousValue;
            this.formDirective.removeControl({
              name: e,
              path: this._getPath(e)
            })
          }
          this._setUpControl()
        }
        "isDisabled" in t && this._updateDisabled(t), Ss(t, this.viewModel) && (this._updateValue(this.model), this.viewModel = this.model)
      }
      ngOnDestroy() {
        this.formDirective && this.formDirective.removeControl(this)
      }
      get path() {
        return this._getPath(this.name)
      }
      get formDirective() {
        return this._parent ? this._parent.formDirective : null
      }
      viewToModelUpdate(t) {
        this.viewModel = t, this.update.emit(t)
      }
      _setUpControl() {
        this._setUpdateStrategy(), this._isStandalone() ? this._setUpStandalone() : this.formDirective.addControl(this), this._registered = !0
      }
      _setUpdateStrategy() {
        this.options && this.options.updateOn != null && (this.control._updateOn = this.options.updateOn)
      }
      _isStandalone() {
        return !this._parent || !!(this.options && this.options.standalone)
      }
      _setUpStandalone() {
        Vn(this.control, this, this.callSetDisabledState), this.control.updateValueAndValidity({
          emitEvent: !1
        })
      }
      _checkForErrors() {
        this._checkName()
      }
      _checkName() {
        this.options && this.options.name && (this.name = this.options.name), !this._isStandalone() && this.name
      }
      _updateValue(t) {
        su.then(() => {
          this.control.setValue(t, {
            emitViewToModelChange: !1
          }), this._changeDetectorRef?.markForCheck()
        })
      }
      _updateDisabled(t) {
        let e = t.isDisabled.currentValue,
          r = e !== 0 && F(e);
        su.then(() => {
          r && !this.control.disabled ? this.control.disable() : !r && this.control.disabled && this.control.enable(), this._changeDetectorRef?.markForCheck()
        })
      }
      _getPath(t) {
        return this._parent ? Du(t, this._parent) : [t]
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(de, 9), C(ue, 10), C(Bn, 10), C(Se, 10), C(At, 8), C(Li, 8))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "ngModel", "", 3, "formControlName", "", 3, "formControl", ""]
        ],
        inputs: {
          name: "name",
          isDisabled: [0, "disabled", "isDisabled"],
          model: [0, "ngModel", "model"],
          options: [0, "ngModelOptions", "options"]
        },
        outputs: {
          update: "ngModelChange"
        },
        exportAs: ["ngModel"],
        standalone: !1,
        features: [z([Vp]), L, mt]
      })
    }
    return i
  })(), ww = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["form", 3, "ngNoForm", "", 3, "ngNativeValidate", ""]
        ],
        hostAttrs: ["novalidate", ""],
        standalone: !1
      })
    }
    return i
  })(), Bp = {
    provide: Se,
    useExisting: gt(() => zp),
    multi: !0
  }, zp = (() => {
    class i extends jn {
      writeValue(t) {
        let e = t ?? "";
        this.setProperty("value", e)
      }
      registerOnChange(t) {
        this.onChange = e => {
          t(e == "" ? null : parseFloat(e))
        }
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["input", "type", "number", "formControlName", ""],
          ["input", "type", "number", "formControl", ""],
          ["input", "type", "number", "ngModel", ""]
        ],
        hostBindings: function(e, r) {
          e & 1 && dt("input", function(a) {
            return r.onChange(a.target.value)
          })("blur", function() {
            return r.onTouched()
          })
        },
        standalone: !1,
        features: [z([Bp]), L]
      })
    }
    return i
  })(), Ms = new v(""), Up = {
    provide: qt,
    useExisting: gt(() => Hp)
  }, Hp = (() => {
    class i extends qt {
      _ngModelWarningConfig;
      callSetDisabledState;
      viewModel;
      form;
      set isDisabled(t) {}
      model;
      update = new A;
      static _ngModelWarningSentOnce = !1;
      _ngModelWarningSent = !1;
      constructor(t, e, r, o, a) {
        super(), this._ngModelWarningConfig = o, this.callSetDisabledState = a, this._setValidators(t), this._setAsyncValidators(e), this.valueAccessor = Ds(this, r)
      }
      ngOnChanges(t) {
        if (this._isControlChanged(t)) {
          let e = t.form.previousValue;
          e && go(e, this, !1), Vn(this.form, this, this.callSetDisabledState), this.form.updateValueAndValidity({
            emitEvent: !1
          })
        }
        Ss(t, this.viewModel) && (this.form.setValue(this.model), this.viewModel = this.model)
      }
      ngOnDestroy() {
        this.form && go(this.form, this, !1)
      }
      get path() {
        return []
      }
      get control() {
        return this.form
      }
      viewToModelUpdate(t) {
        this.viewModel = t, this.update.emit(t)
      }
      _isControlChanged(t) {
        return t.hasOwnProperty("form")
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(ue, 10), C(Bn, 10), C(Se, 10), C(Ms, 8), C(Li, 8))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "formControl", ""]
        ],
        inputs: {
          form: [0, "formControl", "form"],
          isDisabled: [0, "disabled", "isDisabled"],
          model: [0, "ngModel", "model"]
        },
        outputs: {
          update: "ngModelChange"
        },
        exportAs: ["ngForm"],
        standalone: !1,
        features: [z([Up]), L, mt]
      })
    }
    return i
  })(), $p = {
    provide: de,
    useExisting: gt(() => Is)
  }, Is = (() => {
    class i extends de {
      callSetDisabledState;
      get submitted() {
        return ut(this._submittedReactive)
      }
      set submitted(t) {
        this._submittedReactive.set(t)
      }
      _submitted = Zt(() => this._submittedReactive());
      _submittedReactive = J(!1);
      _oldForm;
      _onCollectionChange = () => this._updateDomValue();
      directives = [];
      form = null;
      ngSubmit = new A;
      constructor(t, e, r) {
        super(), this.callSetDisabledState = r, this._setValidators(t), this._setAsyncValidators(e)
      }
      ngOnChanges(t) {
        t.hasOwnProperty("form") && (this._updateValidators(), this._updateDomValue(), this._updateRegistrations(), this._oldForm = this.form)
      }
      ngOnDestroy() {
        this.form && (_o(this.form, this), this.form._onCollectionChange === this._onCollectionChange && this.form._registerOnCollectionChange(() => {}))
      }
      get formDirective() {
        return this
      }
      get control() {
        return this.form
      }
      get path() {
        return []
      }
      addControl(t) {
        let e = this.form.get(t.path);
        return Vn(e, t, this.callSetDisabledState), e.updateValueAndValidity({
          emitEvent: !1
        }), this.directives.push(t), e
      }
      getControl(t) {
        return this.form.get(t.path)
      }
      removeControl(t) {
        go(t.control || null, t, !1), Np(this.directives, t)
      }
      addFormGroup(t) {
        this._setUpFormContainer(t)
      }
      removeFormGroup(t) {
        this._cleanUpFormContainer(t)
      }
      getFormGroup(t) {
        return this.form.get(t.path)
      }
      addFormArray(t) {
        this._setUpFormContainer(t)
      }
      removeFormArray(t) {
        this._cleanUpFormContainer(t)
      }
      getFormArray(t) {
        return this.form.get(t.path)
      }
      updateModel(t, e) {
        this.form.get(t.path).setValue(e)
      }
      onSubmit(t) {
        return this._submittedReactive.set(!0), Mu(this.form, this.directives), this.ngSubmit.emit(t), this.form._events.next(new mo(this.control)), t?.target?.method === "dialog"
      }
      onReset() {
        this.resetForm()
      }
      resetForm(t = void 0, e = {}) {
        this.form.reset(t, e), this._submittedReactive.set(!1)
      }
      _updateDomValue() {
        this.directives.forEach(t => {
          let e = t.control,
            r = this.form.get(t.path);
          e !== r && (go(e || null, t), Lp(r) && (Vn(r, t, this.callSetDisabledState), t.control = r))
        }), this.form._updateTreeValidity({
          emitEvent: !1
        })
      }
      _setUpFormContainer(t) {
        let e = this.form.get(t.path);
        Au(e, t), e.updateValueAndValidity({
          emitEvent: !1
        })
      }
      _cleanUpFormContainer(t) {
        if (this.form) {
          let e = this.form.get(t.path);
          e && Tp(e, t) && e.updateValueAndValidity({
            emitEvent: !1
          })
        }
      }
      _updateRegistrations() {
        this.form._registerOnCollectionChange(this._onCollectionChange), this._oldForm && this._oldForm._registerOnCollectionChange(() => {})
      }
      _updateValidators() {
        Es(this.form, this), this._oldForm && _o(this._oldForm, this)
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(ue, 10), C(Bn, 10), C(Li, 8))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "formGroup", ""]
        ],
        hostBindings: function(e, r) {
          e & 1 && dt("submit", function(a) {
            return r.onSubmit(a)
          })("reset", function() {
            return r.onReset()
          })
        },
        inputs: {
          form: [0, "formGroup", "form"]
        },
        outputs: {
          ngSubmit: "ngSubmit"
        },
        exportAs: ["ngForm"],
        standalone: !1,
        features: [z([$p]), L, mt]
      })
    }
    return i
  })(), Wp = {
    provide: qt,
    useExisting: gt(() => Gp)
  }, Gp = (() => {
    class i extends qt {
      _ngModelWarningConfig;
      _added = !1;
      viewModel;
      control;
      name = null;
      set isDisabled(t) {}
      model;
      update = new A;
      static _ngModelWarningSentOnce = !1;
      _ngModelWarningSent = !1;
      constructor(t, e, r, o, a) {
        super(), this._ngModelWarningConfig = a, this._parent = t, this._setValidators(e), this._setAsyncValidators(r), this.valueAccessor = Ds(this, o)
      }
      ngOnChanges(t) {
        this._added || this._setUpControl(), Ss(t, this.viewModel) && (this.viewModel = this.model, this.formDirective.updateModel(this, this.model))
      }
      ngOnDestroy() {
        this.formDirective && this.formDirective.removeControl(this)
      }
      viewToModelUpdate(t) {
        this.viewModel = t, this.update.emit(t)
      }
      get path() {
        return Du(this.name == null ? this.name : this.name.toString(), this._parent)
      }
      get formDirective() {
        return this._parent ? this._parent.formDirective : null
      }
      _setUpControl() {
        this.control = this.formDirective.addControl(this), this._added = !0
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(de, 13), C(ue, 10), C(Bn, 10), C(Se, 10), C(Ms, 8))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "formControlName", ""]
        ],
        inputs: {
          name: [0, "formControlName", "name"],
          isDisabled: [0, "disabled", "isDisabled"],
          model: [0, "ngModel", "model"]
        },
        outputs: {
          update: "ngModelChange"
        },
        standalone: !1,
        features: [z([Wp]), L, mt]
      })
    }
    return i
  })(), qp = {
    provide: Se,
    useExisting: gt(() => Ou),
    multi: !0
  };
  Ou = (() => {
    class i extends jn {
      value;
      _optionMap = new Map;
      _idCounter = 0;
      set compareWith(t) {
        this._compareWith = t
      }
      _compareWith = Object.is;
      appRefInjector = l(ie).injector;
      destroyRef = l(Bi);
      cdr = l(At);
      _queuedWrite = !1;
      _writeValueAfterRender() {
        this._queuedWrite || this.appRefInjector.destroyed || (this._queuedWrite = !0, Ot({
          write: () => {
            this.destroyRef.destroyed || (this._queuedWrite = !1, this.writeValue(this.value))
          }
        }, {
          injector: this.appRefInjector
        }))
      }
      writeValue(t) {
        this.cdr.markForCheck(), this.value = t;
        let e = this._getOptionId(t),
          r = Iu(e, t);
        this.setProperty("value", r)
      }
      registerOnChange(t) {
        this.onChange = e => {
          this.value = this._getOptionValue(e), t(this.value)
        }
      }
      _registerOption() {
        return (this._idCounter++).toString()
      }
      _getOptionId(t) {
        for (let e of this._optionMap.keys())
          if (this._compareWith(this._optionMap.get(e), t)) return e;
        return null
      }
      _getOptionValue(t) {
        let e = Yp(t);
        return this._optionMap.has(e) ? this._optionMap.get(e) : t
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["select", "formControlName", "", 3, "multiple", ""],
          ["select", "formControl", "", 3, "multiple", ""],
          ["select", "ngModel", "", 3, "multiple", ""]
        ],
        hostBindings: function(e, r) {
          e & 1 && dt("change", function(a) {
            return r.onChange(a.target.value)
          })("blur", function() {
            return r.onTouched()
          })
        },
        inputs: {
          compareWith: "compareWith"
        },
        standalone: !1,
        features: [z([qp]), L]
      })
    }
    return i
  })(), Ew = (() => {
    class i {
      _element;
      _renderer;
      _select;
      id;
      constructor(t, e, r) {
        this._element = t, this._renderer = e, this._select = r, this._select && (this.id = this._select._registerOption())
      }
      set ngValue(t) {
        this._select != null && (this._select._optionMap.set(this.id, t), this._setElementValue(Iu(this.id, t)), this._select._writeValueAfterRender())
      }
      set value(t) {
        this._setElementValue(t), this._select && this._select._writeValueAfterRender()
      }
      _setElementValue(t) {
        this._renderer.setProperty(this._element.nativeElement, "value", t)
      }
      ngOnDestroy() {
        this._select && (this._select._optionMap.delete(this.id), this._select._writeValueAfterRender())
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(D), C(lt), C(Ou, 9))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["option"]
        ],
        inputs: {
          ngValue: "ngValue",
          value: "value"
        },
        standalone: !1
      })
    }
    return i
  })(), Kp = {
    provide: Se,
    useExisting: gt(() => ku),
    multi: !0
  };
  ku = (() => {
    class i extends jn {
      value;
      _optionMap = new Map;
      _idCounter = 0;
      set compareWith(t) {
        this._compareWith = t
      }
      _compareWith = Object.is;
      writeValue(t) {
        this.value = t;
        let e;
        if (Array.isArray(t)) {
          let r = t.map(o => this._getOptionId(o));
          e = (o, a) => {
            o._setSelected(r.indexOf(a.toString()) > -1)
          }
        } else e = (r, o) => {
          r._setSelected(!1)
        };
        this._optionMap.forEach(e)
      }
      registerOnChange(t) {
        this.onChange = e => {
          let r = [],
            o = e.selectedOptions;
          if (o !== void 0) {
            let a = o;
            for (let s = 0; s < a.length; s++) {
              let c = a[s],
                d = this._getOptionValue(c.value);
              r.push(d)
            }
          } else {
            let a = e.options;
            for (let s = 0; s < a.length; s++) {
              let c = a[s];
              if (c.selected) {
                let d = this._getOptionValue(c.value);
                r.push(d)
              }
            }
          }
          this.value = r, t(r)
        }
      }
      _registerOption(t) {
        let e = (this._idCounter++).toString();
        return this._optionMap.set(e, t), e
      }
      _getOptionId(t) {
        for (let e of this._optionMap.keys())
          if (this._compareWith(this._optionMap.get(e)._value, t)) return e;
        return null
      }
      _getOptionValue(t) {
        let e = Zp(t);
        return this._optionMap.has(e) ? this._optionMap.get(e)._value : t
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["select", "multiple", "", "formControlName", ""],
          ["select", "multiple", "", "formControl", ""],
          ["select", "multiple", "", "ngModel", ""]
        ],
        hostBindings: function(e, r) {
          e & 1 && dt("change", function(a) {
            return r.onChange(a.target)
          })("blur", function() {
            return r.onTouched()
          })
        },
        inputs: {
          compareWith: "compareWith"
        },
        standalone: !1,
        features: [z([Kp]), L]
      })
    }
    return i
  })(), Sw = (() => {
    class i {
      _element;
      _renderer;
      _select;
      id;
      _value;
      constructor(t, e, r) {
        this._element = t, this._renderer = e, this._select = r, this._select && (this.id = this._select._registerOption(this))
      }
      set ngValue(t) {
        this._select != null && (this._value = t, this._setElementValue(lu(this.id, t)), this._select.writeValue(this._select.value))
      }
      set value(t) {
        this._select ? (this._value = t, this._setElementValue(lu(this.id, t)), this._select.writeValue(this._select.value)) : this._setElementValue(t)
      }
      _setElementValue(t) {
        this._renderer.setProperty(this._element.nativeElement, "value", t)
      }
      _setSelected(t) {
        this._renderer.setProperty(this._element.nativeElement, "selected", t)
      }
      ngOnDestroy() {
        this._select && (this._select._optionMap.delete(this.id), this._select.writeValue(this._select.value))
      }
      static \u0275fac = function(e) {
        return new(e || i)(C(D), C(lt), C(ku, 9))
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["option"]
        ],
        inputs: {
          ngValue: "ngValue",
          value: "value"
        },
        standalone: !1
      })
    }
    return i
  })();
  Co = (() => {
    class i {
      _validator = so;
      _onChange;
      _enabled;
      ngOnChanges(t) {
        if (this.inputName in t) {
          let e = this.normalizeInput(t[this.inputName].currentValue);
          this._enabled = this.enabled(e), this._validator = this._enabled ? this.createValidator(e) : so, this._onChange && this._onChange()
        }
      }
      validate(t) {
        return this._validator(t)
      }
      registerOnValidatorChange(t) {
        this._onChange = t
      }
      enabled(t) {
        return t != null
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        features: [mt]
      })
    }
    return i
  })(), Xp = {
    provide: ue,
    useExisting: gt(() => Qp),
    multi: !0
  }, Qp = (() => {
    class i extends Co {
      required;
      inputName = "required";
      normalizeInput = F;
      createValidator = t => uu;
      enabled(t) {
        return t
      }
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "required", "", "formControlName", "", 3, "type", "checkbox"],
          ["", "required", "", "formControl", "", 3, "type", "checkbox"],
          ["", "required", "", "ngModel", "", 3, "type", "checkbox"]
        ],
        hostVars: 1,
        hostBindings: function(e, r) {
          e & 2 && tt("required", r._enabled ? "" : null)
        },
        inputs: {
          required: "required"
        },
        standalone: !1,
        features: [z([Xp]), L]
      })
    }
    return i
  })(), Jp = {
    provide: ue,
    useExisting: gt(() => tg),
    multi: !0
  }, tg = (() => {
    class i extends Co {
      minlength;
      inputName = "minlength";
      normalizeInput = t => Tu(t);
      createValidator = t => hu(t);
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "minlength", "", "formControlName", ""],
          ["", "minlength", "", "formControl", ""],
          ["", "minlength", "", "ngModel", ""]
        ],
        hostVars: 1,
        hostBindings: function(e, r) {
          e & 2 && tt("minlength", r._enabled ? r.minlength : null)
        },
        inputs: {
          minlength: "minlength"
        },
        standalone: !1,
        features: [z([Jp]), L]
      })
    }
    return i
  })(), eg = {
    provide: ue,
    useExisting: gt(() => ig),
    multi: !0
  }, ig = (() => {
    class i extends Co {
      maxlength;
      inputName = "maxlength";
      normalizeInput = t => Tu(t);
      createValidator = t => mu(t);
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "maxlength", "", "formControlName", ""],
          ["", "maxlength", "", "formControl", ""],
          ["", "maxlength", "", "ngModel", ""]
        ],
        hostVars: 1,
        hostBindings: function(e, r) {
          e & 2 && tt("maxlength", r._enabled ? r.maxlength : null)
        },
        inputs: {
          maxlength: "maxlength"
        },
        standalone: !1,
        features: [z([eg]), L]
      })
    }
    return i
  })(), ng = {
    provide: ue,
    useExisting: gt(() => rg),
    multi: !0
  }, rg = (() => {
    class i extends Co {
      pattern;
      inputName = "pattern";
      normalizeInput = t => t;
      createValidator = t => fu(t);
      static \u0275fac = (() => {
        let t;
        return function(r) {
          return (t || (t = Z(i)))(r || i)
        }
      })();
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "pattern", "", "formControlName", ""],
          ["", "pattern", "", "formControl", ""],
          ["", "pattern", "", "ngModel", ""]
        ],
        hostVars: 1,
        hostBindings: function(e, r) {
          e & 2 && tt("pattern", r._enabled ? r.pattern : null)
        },
        inputs: {
          pattern: "pattern"
        },
        standalone: !1,
        features: [z([ng]), L]
      })
    }
    return i
  })(), Fu = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })(), Dw = (() => {
    class i {
      static withConfig(t) {
        return {
          ngModule: i,
          providers: [{
            provide: Li,
            useValue: t.callSetDisabledState ?? yo
          }]
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [Fu]
      })
    }
    return i
  })(), Rw = (() => {
    class i {
      static withConfig(t) {
        return {
          ngModule: i,
          providers: [{
            provide: Ms,
            useValue: t.warnOnNgModelWithFormControl ?? "always"
          }, {
            provide: Li,
            useValue: t.callSetDisabledState ?? yo
          }]
        }
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [Fu]
      })
    }
    return i
  })()
});
var Os, Pu, Lu = _(() => {
  f();
  f();
  nt();
  ht();
  Os = class {
    _box;
    _destroyed = new y;
    _resizeSubject = new y;
    _resizeObserver;
    _elementObservables = new Map;
    constructor(n) {
      this._box = n, typeof ResizeObserver < "u" && (this._resizeObserver = new ResizeObserver(t => this._resizeSubject.next(t)))
    }
    observe(n) {
      return this._elementObservables.has(n) || this._elementObservables.set(n, new Yt(t => {
        let e = this._resizeSubject.subscribe(t);
        return this._resizeObserver?.observe(n, {
          box: this._box
        }), () => {
          this._resizeObserver?.unobserve(n), e.unsubscribe(), this._elementObservables.delete(n)
        }
      }).pipe(K(t => t.some(e => e.target === n)), Je({
        bufferSize: 1,
        refCount: !0
      }), Dt(this._destroyed))), this._elementObservables.get(n)
    }
    destroy() {
      this._destroyed.next(), this._destroyed.complete(), this._resizeSubject.complete(), this._elementObservables.clear()
    }
  }, Pu = (() => {
    class i {
      _cleanupErrorListener;
      _observers = new Map;
      _ngZone = l(E);
      constructor() {
        typeof ResizeObserver < "u"
      }
      ngOnDestroy() {
        for (let [, t] of this._observers) t.destroy();
        this._observers.clear(), this._cleanupErrorListener?.()
      }
      observe(t, e) {
        let r = e?.box || "content-box";
        return this._observers.has(r) || this._observers.set(r, new Os(r)), this._observers.get(r).observe(t)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});

function ug(i, n) {
  i & 1 && ne(0, "span", 21)
}

function hg(i, n) {
  if (i & 1 && (ct(0, "label", 20), U(1, 1), vt(2, ug, 1, 0, "span", 21), rt()), i & 2) {
    let t = Ht(2);
    ii("floating", t._shouldLabelFloat())("monitorResize", t._hasOutline())("id", t._labelId), tt("for", t._control.disableAutomaticLabeling ? null : t._control.id), q(2), _t(!t.hideRequiredMarker && t._control.required ? 2 : -1)
  }
}

function mg(i, n) {
  if (i & 1 && vt(0, hg, 3, 5, "label", 20), i & 2) {
    let t = Ht();
    _t(t._hasFloatingLabel() ? 0 : -1)
  }
}

function fg(i, n) {
  i & 1 && ne(0, "div", 7)
}

function pg(i, n) {}

function gg(i, n) {
  if (i & 1 && ei(0, pg, 0, 0, "ng-template", 13), i & 2) {
    Ht(2);
    let t = jo(1);
    ii("ngTemplateOutlet", t)
  }
}

function vg(i, n) {
  if (i & 1 && (ct(0, "div", 9), vt(1, gg, 1, 1, null, 13), rt()), i & 2) {
    let t = Ht();
    ii("matFormFieldNotchedOutlineOpen", t._shouldLabelFloat()), q(), _t(t._forceDisplayInfixLabel() ? -1 : 1)
  }
}

function _g(i, n) {
  i & 1 && (ct(0, "div", 10, 2), U(2, 2), rt())
}

function bg(i, n) {
  i & 1 && (ct(0, "div", 11, 3), U(2, 3), rt())
}

function yg(i, n) {}

function Cg(i, n) {
  if (i & 1 && ei(0, yg, 0, 0, "ng-template", 13), i & 2) {
    Ht();
    let t = jo(1);
    ii("ngTemplateOutlet", t)
  }
}

function xg(i, n) {
  i & 1 && (ct(0, "div", 14, 4), U(2, 4), rt())
}

function wg(i, n) {
  i & 1 && (ct(0, "div", 15, 5), U(2, 5), rt())
}

function Eg(i, n) {
  i & 1 && ne(0, "div", 16)
}

function Sg(i, n) {
  i & 1 && (ct(0, "div", 18), U(1, 6), rt())
}

function Dg(i, n) {
  if (i & 1 && (ct(0, "mat-hint", 22), Wi(1), rt()), i & 2) {
    let t = Ht(2);
    ii("id", t._hintLabelId), q(), ll(t.hintLabel)
  }
}

function Rg(i, n) {
  if (i & 1 && (ct(0, "div", 19), vt(1, Dg, 2, 2, "mat-hint", 22), U(2, 7), ne(3, "div", 23), U(4, 8), rt()), i & 2) {
    let t = Ht();
    q(), _t(t.hintLabel ? 1 : -1)
  }
}

function Og(i) {
  let n = i;
  if (n.offsetParent !== null) return n.scrollWidth;
  let t = n.cloneNode(!0);
  t.style.setProperty("position", "absolute"), t.style.setProperty("transform", "translate(-9999px, -9999px)"), document.documentElement.appendChild(t);
  let e = t.scrollWidth;
  return t.remove(), e
}
var og, ag, sg, Vu, ju, Bu, zu, lg, cg, dg, ks, Fs, Ag, Ts, Ns, Mg, Ps, Ig, Yu, Uu, Hu, xo, $u, Wu, wo, Eo, Ku, Gu, kg, qu, Tg, Ls, So = _(() => {
  qe();
  vn();
  no();
  Oi();
  Pe();
  f();
  f();
  nt();
  ht();
  Lu();
  Ti();
  og = ["notch"], ag = ["matFormFieldNotchedOutline", ""], sg = ["*"], Vu = ["iconPrefixContainer"], ju = ["textPrefixContainer"], Bu = ["iconSuffixContainer"], zu = ["textSuffixContainer"], lg = ["textField"], cg = ["*", [
      ["mat-label"]
    ],
    [
      ["", "matPrefix", ""],
      ["", "matIconPrefix", ""]
    ],
    [
      ["", "matTextPrefix", ""]
    ],
    [
      ["", "matTextSuffix", ""]
    ],
    [
      ["", "matSuffix", ""],
      ["", "matIconSuffix", ""]
    ],
    [
      ["mat-error"],
      ["", "matError", ""]
    ],
    [
      ["mat-hint", 3, "align", "end"]
    ],
    [
      ["mat-hint", "align", "end"]
    ]
  ], dg = ["*", "mat-label", "[matPrefix], [matIconPrefix]", "[matTextPrefix]", "[matTextSuffix]", "[matSuffix], [matIconSuffix]", "mat-error, [matError]", "mat-hint:not([align='end'])", "mat-hint[align='end']"];
  ks = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["mat-label"]
        ]
      })
    }
    return i
  })(), Fs = new v("MatError"), Ag = (() => {
    class i {
      id = l(Wt).getId("mat-mdc-error-");
      constructor() {}
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["mat-error"],
          ["", "matError", ""]
        ],
        hostAttrs: [1, "mat-mdc-form-field-error", "mat-mdc-form-field-bottom-align"],
        hostVars: 1,
        hostBindings: function(e, r) {
          e & 2 && Hi("id", r.id)
        },
        inputs: {
          id: "id"
        },
        features: [z([{
          provide: Fs,
          useExisting: i
        }])]
      })
    }
    return i
  })(), Ts = (() => {
    class i {
      align = "start";
      id = l(Wt).getId("mat-mdc-hint-");
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["mat-hint"]
        ],
        hostAttrs: [1, "mat-mdc-form-field-hint", "mat-mdc-form-field-bottom-align"],
        hostVars: 4,
        hostBindings: function(e, r) {
          e & 2 && (Hi("id", r.id), tt("align", null), H("mat-mdc-form-field-hint-end", r.align === "end"))
        },
        inputs: {
          align: "align",
          id: "id"
        }
      })
    }
    return i
  })(), Ns = new v("MatPrefix"), Mg = (() => {
    class i {
      set _isTextSelector(t) {
        this._isText = !0
      }
      _isText = !1;
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "matPrefix", ""],
          ["", "matIconPrefix", ""],
          ["", "matTextPrefix", ""]
        ],
        inputs: {
          _isTextSelector: [0, "matTextPrefix", "_isTextSelector"]
        },
        features: [z([{
          provide: Ns,
          useExisting: i
        }])]
      })
    }
    return i
  })(), Ps = new v("MatSuffix"), Ig = (() => {
    class i {
      set _isTextSelector(t) {
        this._isText = !0
      }
      _isText = !1;
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["", "matSuffix", ""],
          ["", "matIconSuffix", ""],
          ["", "matTextSuffix", ""]
        ],
        inputs: {
          _isTextSelector: [0, "matTextSuffix", "_isTextSelector"]
        },
        features: [z([{
          provide: Ps,
          useExisting: i
        }])]
      })
    }
    return i
  })(), Yu = new v("FloatingLabelParent"), Uu = (() => {
    class i {
      _elementRef = l(D);
      get floating() {
        return this._floating
      }
      set floating(t) {
        this._floating = t, this.monitorResize && this._handleResize()
      }
      _floating = !1;
      get monitorResize() {
        return this._monitorResize
      }
      set monitorResize(t) {
        this._monitorResize = t, this._monitorResize ? this._subscribeToResize() : this._resizeSubscription.unsubscribe()
      }
      _monitorResize = !1;
      _resizeObserver = l(Pu);
      _ngZone = l(E);
      _parent = l(Yu);
      _resizeSubscription = new ft;
      constructor() {}
      ngOnDestroy() {
        this._resizeSubscription.unsubscribe()
      }
      getWidth() {
        return Og(this._elementRef.nativeElement)
      }
      get element() {
        return this._elementRef.nativeElement
      }
      _handleResize() {
        setTimeout(() => this._parent._handleLabelResized())
      }
      _subscribeToResize() {
        this._resizeSubscription.unsubscribe(), this._ngZone.runOutsideAngular(() => {
          this._resizeSubscription = this._resizeObserver.observe(this._elementRef.nativeElement, {
            box: "border-box"
          }).subscribe(() => this._handleResize())
        })
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["label", "matFormFieldFloatingLabel", ""]
        ],
        hostAttrs: [1, "mdc-floating-label", "mat-mdc-floating-label"],
        hostVars: 2,
        hostBindings: function(e, r) {
          e & 2 && H("mdc-floating-label--float-above", r.floating)
        },
        inputs: {
          floating: "floating",
          monitorResize: "monitorResize"
        }
      })
    }
    return i
  })();
  Hu = "mdc-line-ripple--active", xo = "mdc-line-ripple--deactivating", $u = (() => {
    class i {
      _elementRef = l(D);
      _cleanupTransitionEnd;
      constructor() {
        let t = l(E),
          e = l(lt);
        t.runOutsideAngular(() => {
          this._cleanupTransitionEnd = e.listen(this._elementRef.nativeElement, "transitionend", this._handleTransitionEnd)
        })
      }
      activate() {
        let t = this._elementRef.nativeElement.classList;
        t.remove(xo), t.add(Hu)
      }
      deactivate() {
        this._elementRef.nativeElement.classList.add(xo)
      }
      _handleTransitionEnd = t => {
        let e = this._elementRef.nativeElement.classList,
          r = e.contains(xo);
        t.propertyName === "opacity" && r && e.remove(Hu, xo)
      };
      ngOnDestroy() {
        this._cleanupTransitionEnd()
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["div", "matFormFieldLineRipple", ""]
        ],
        hostAttrs: [1, "mdc-line-ripple"]
      })
    }
    return i
  })(), Wu = (() => {
    class i {
      _elementRef = l(D);
      _ngZone = l(E);
      open = !1;
      _notch;
      ngAfterViewInit() {
        let t = this._elementRef.nativeElement,
          e = t.querySelector(".mdc-floating-label");
        e ? (t.classList.add("mdc-notched-outline--upgraded"), typeof requestAnimationFrame == "function" && (e.style.transitionDuration = "0s", this._ngZone.runOutsideAngular(() => {
          requestAnimationFrame(() => e.style.transitionDuration = "")
        }))) : t.classList.add("mdc-notched-outline--no-label")
      }
      _setNotchWidth(t) {
        let e = this._notch.nativeElement;
        !this.open || !t ? e.style.width = "" : e.style.width = `calc(${t}px * var(--mat-mdc-form-field-floating-label-scale, 0.75) + 9px)`
      }
      _setMaxWidth(t) {
        this._notch.nativeElement.style.setProperty("--mat-form-field-notch-max-width", `calc(100% - ${t}px)`)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["div", "matFormFieldNotchedOutline", ""]
        ],
        viewQuery: function(e, r) {
          if (e & 1 && Rt(og, 5), e & 2) {
            let o;
            et(o = it()) && (r._notch = o.first)
          }
        },
        hostAttrs: [1, "mdc-notched-outline"],
        hostVars: 2,
        hostBindings: function(e, r) {
          e & 2 && H("mdc-notched-outline--notched", r.open)
        },
        inputs: {
          open: [0, "matFormFieldNotchedOutlineOpen", "open"]
        },
        attrs: ag,
        ngContentSelectors: sg,
        decls: 5,
        vars: 0,
        consts: [
          ["notch", ""],
          [1, "mat-mdc-notch-piece", "mdc-notched-outline__leading"],
          [1, "mat-mdc-notch-piece", "mdc-notched-outline__notch"],
          [1, "mat-mdc-notch-piece", "mdc-notched-outline__trailing"]
        ],
        template: function(e, r) {
          e & 1 && (Tt(), Kt(0, "div", 1), ke(1, "div", 2, 0), U(3), Te(), Kt(4, "div", 3))
        },
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), wo = (() => {
    class i {
      value;
      stateChanges;
      id;
      placeholder;
      ngControl;
      focused;
      empty;
      shouldLabelFloat;
      required;
      disabled;
      errorState;
      controlType;
      autofilled;
      userAriaDescribedBy;
      disableAutomaticLabeling;
      describedByIds;
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i
      })
    }
    return i
  })(), Eo = new v("MatFormField"), Ku = new v("MAT_FORM_FIELD_DEFAULT_OPTIONS"), Gu = "fill", kg = "auto", qu = "fixed", Tg = "translateY(-50%)", Ls = (() => {
    class i {
      _elementRef = l(D);
      _changeDetectorRef = l(At);
      _platform = l(T);
      _idGenerator = l(Wt);
      _ngZone = l(E);
      _defaults = l(Ku, {
        optional: !0
      });
      _currentDirection;
      _textField;
      _iconPrefixContainer;
      _textPrefixContainer;
      _iconSuffixContainer;
      _textSuffixContainer;
      _floatingLabel;
      _notchedOutline;
      _lineRipple;
      _iconPrefixContainerSignal = Gi("iconPrefixContainer");
      _textPrefixContainerSignal = Gi("textPrefixContainer");
      _iconSuffixContainerSignal = Gi("iconSuffixContainer");
      _textSuffixContainerSignal = Gi("textSuffixContainer");
      _prefixSuffixContainers = Zt(() => [this._iconPrefixContainerSignal(), this._textPrefixContainerSignal(), this._iconSuffixContainerSignal(), this._textSuffixContainerSignal()].map(t => t?.nativeElement).filter(t => t !== void 0));
      _formFieldControl;
      _prefixChildren;
      _suffixChildren;
      _errorChildren;
      _hintChildren;
      _labelChild = hl(ks);
      get hideRequiredMarker() {
        return this._hideRequiredMarker
      }
      set hideRequiredMarker(t) {
        this._hideRequiredMarker = ki(t)
      }
      _hideRequiredMarker = !1;
      color = "primary";
      get floatLabel() {
        return this._floatLabel || this._defaults?.floatLabel || kg
      }
      set floatLabel(t) {
        t !== this._floatLabel && (this._floatLabel = t, this._changeDetectorRef.markForCheck())
      }
      _floatLabel;
      get appearance() {
        return this._appearanceSignal()
      }
      set appearance(t) {
        let e = t || this._defaults?.appearance || Gu;
        this._appearanceSignal.set(e)
      }
      _appearanceSignal = J(Gu);
      get subscriptSizing() {
        return this._subscriptSizing || this._defaults?.subscriptSizing || qu
      }
      set subscriptSizing(t) {
        this._subscriptSizing = t || this._defaults?.subscriptSizing || qu
      }
      _subscriptSizing = null;
      get hintLabel() {
        return this._hintLabel
      }
      set hintLabel(t) {
        this._hintLabel = t, this._processHints()
      }
      _hintLabel = "";
      _hasIconPrefix = !1;
      _hasTextPrefix = !1;
      _hasIconSuffix = !1;
      _hasTextSuffix = !1;
      _labelId = this._idGenerator.getId("mat-mdc-form-field-label-");
      _hintLabelId = this._idGenerator.getId("mat-mdc-hint-");
      _describedByIds;
      get _control() {
        return this._explicitFormFieldControl || this._formFieldControl
      }
      set _control(t) {
        this._explicitFormFieldControl = t
      }
      _destroyed = new y;
      _isFocused = null;
      _explicitFormFieldControl;
      _previousControl = null;
      _previousControlValidatorFn = null;
      _stateChanges;
      _valueChanges;
      _describedByChanges;
      _outlineLabelOffsetResizeObserver = null;
      _animationsDisabled = Gt();
      constructor() {
        let t = this._defaults,
          e = l(le);
        t && (t.appearance && (this.appearance = t.appearance), this._hideRequiredMarker = !!t?.hideRequiredMarker, t.color && (this.color = t.color)), Ne(() => this._currentDirection = e.valueSignal()), this._syncOutlineLabelOffset()
      }
      ngAfterViewInit() {
        this._updateFocusState(), this._animationsDisabled || this._ngZone.runOutsideAngular(() => {
          setTimeout(() => {
            this._elementRef.nativeElement.classList.add("mat-form-field-animations-enabled")
          }, 300)
        }), this._changeDetectorRef.detectChanges()
      }
      ngAfterContentInit() {
        this._assertFormFieldControl(), this._initializeSubscript(), this._initializePrefixAndSuffix()
      }
      ngAfterContentChecked() {
        this._assertFormFieldControl(), this._control !== this._previousControl && (this._initializeControl(this._previousControl), this._control.ngControl && this._control.ngControl.control && (this._previousControlValidatorFn = this._control.ngControl.control.validator), this._previousControl = this._control), this._control.ngControl && this._control.ngControl.control && this._control.ngControl.control.validator !== this._previousControlValidatorFn && this._changeDetectorRef.markForCheck()
      }
      ngOnDestroy() {
        this._outlineLabelOffsetResizeObserver?.disconnect(), this._stateChanges?.unsubscribe(), this._valueChanges?.unsubscribe(), this._describedByChanges?.unsubscribe(), this._destroyed.next(), this._destroyed.complete()
      }
      getLabelId = Zt(() => this._hasFloatingLabel() ? this._labelId : null);
      getConnectedOverlayOrigin() {
        return this._textField || this._elementRef
      }
      _animateAndLockLabel() {
        this._hasFloatingLabel() && (this.floatLabel = "always")
      }
      _initializeControl(t) {
        let e = this._control,
          r = "mat-mdc-form-field-type-";
        t && this._elementRef.nativeElement.classList.remove(r + t.controlType), e.controlType && this._elementRef.nativeElement.classList.add(r + e.controlType), this._stateChanges?.unsubscribe(), this._stateChanges = e.stateChanges.subscribe(() => {
          this._updateFocusState(), this._changeDetectorRef.markForCheck()
        }), this._describedByChanges?.unsubscribe(), this._describedByChanges = e.stateChanges.pipe(Ie([void 0, void 0]), b(() => [e.errorState, e.userAriaDescribedBy]), Fo(), K(([
          [o, a],
          [s, c]
        ]) => o !== s || a !== c)).subscribe(() => this._syncDescribedByIds()), this._valueChanges?.unsubscribe(), e.ngControl && e.ngControl.valueChanges && (this._valueChanges = e.ngControl.valueChanges.pipe(Dt(this._destroyed)).subscribe(() => this._changeDetectorRef.markForCheck()))
      }
      _checkPrefixAndSuffixTypes() {
        this._hasIconPrefix = !!this._prefixChildren.find(t => !t._isText), this._hasTextPrefix = !!this._prefixChildren.find(t => t._isText), this._hasIconSuffix = !!this._suffixChildren.find(t => !t._isText), this._hasTextSuffix = !!this._suffixChildren.find(t => t._isText)
      }
      _initializePrefixAndSuffix() {
        this._checkPrefixAndSuffixTypes(), Us(this._prefixChildren.changes, this._suffixChildren.changes).subscribe(() => {
          this._checkPrefixAndSuffixTypes(), this._changeDetectorRef.markForCheck()
        })
      }
      _initializeSubscript() {
        this._hintChildren.changes.subscribe(() => {
          this._processHints(), this._changeDetectorRef.markForCheck()
        }), this._errorChildren.changes.subscribe(() => {
          this._syncDescribedByIds(), this._changeDetectorRef.markForCheck()
        }), this._validateHints(), this._syncDescribedByIds()
      }
      _assertFormFieldControl() {
        this._control
      }
      _updateFocusState() {
        let t = this._control.focused;
        t && !this._isFocused ? (this._isFocused = !0, this._lineRipple?.activate()) : !t && (this._isFocused || this._isFocused === null) && (this._isFocused = !1, this._lineRipple?.deactivate()), this._elementRef.nativeElement.classList.toggle("mat-focused", t), this._textField?.nativeElement.classList.toggle("mdc-text-field--focused", t)
      }
      _syncOutlineLabelOffset() {
        fl({
          earlyRead: () => {
            if (this._appearanceSignal() !== "outline") return this._outlineLabelOffsetResizeObserver?.disconnect(), null;
            if (globalThis.ResizeObserver) {
              this._outlineLabelOffsetResizeObserver ||= new globalThis.ResizeObserver(() => {
                this._writeOutlinedLabelStyles(this._getOutlinedLabelOffset())
              });
              for (let t of this._prefixSuffixContainers()) this._outlineLabelOffsetResizeObserver.observe(t, {
                box: "border-box"
              })
            }
            return this._getOutlinedLabelOffset()
          },
          write: t => this._writeOutlinedLabelStyles(t())
        })
      }
      _shouldAlwaysFloat() {
        return this.floatLabel === "always"
      }
      _hasOutline() {
        return this.appearance === "outline"
      }
      _forceDisplayInfixLabel() {
        return !this._platform.isBrowser && this._prefixChildren.length && !this._shouldLabelFloat()
      }
      _hasFloatingLabel = Zt(() => !!this._labelChild());
      _shouldLabelFloat() {
        return this._hasFloatingLabel() ? this._control.shouldLabelFloat || this._shouldAlwaysFloat() : !1
      }
      _shouldForward(t) {
        let e = this._control ? this._control.ngControl : null;
        return e && e[t]
      }
      _getSubscriptMessageType() {
        return this._errorChildren && this._errorChildren.length > 0 && this._control.errorState ? "error" : "hint"
      }
      _handleLabelResized() {
        this._refreshOutlineNotchWidth()
      }
      _refreshOutlineNotchWidth() {
        !this._hasOutline() || !this._floatingLabel || !this._shouldLabelFloat() ? this._notchedOutline?._setNotchWidth(0) : this._notchedOutline?._setNotchWidth(this._floatingLabel.getWidth())
      }
      _processHints() {
        this._validateHints(), this._syncDescribedByIds()
      }
      _validateHints() {
        this._hintChildren
      }
      _syncDescribedByIds() {
        if (this._control) {
          let t = [];
          if (this._control.userAriaDescribedBy && typeof this._control.userAriaDescribedBy == "string" && t.push(...this._control.userAriaDescribedBy.split(" ")), this._getSubscriptMessageType() === "hint") {
            let o = this._hintChildren ? this._hintChildren.find(s => s.align === "start") : null,
              a = this._hintChildren ? this._hintChildren.find(s => s.align === "end") : null;
            o ? t.push(o.id) : this._hintLabel && t.push(this._hintLabelId), a && t.push(a.id)
          } else this._errorChildren && t.push(...this._errorChildren.map(o => o.id));
          let e = this._control.describedByIds,
            r;
          if (e) {
            let o = this._describedByIds || t;
            r = t.concat(e.filter(a => a && !o.includes(a)))
          } else r = t;
          this._control.setDescribedByIds(r), this._describedByIds = t
        }
      }
      _getOutlinedLabelOffset() {
        if (!this._hasOutline() || !this._floatingLabel) return null;
        if (!this._iconPrefixContainer && !this._textPrefixContainer) return ["", null];
        if (!this._isAttachedToDom()) return null;
        let t = this._iconPrefixContainer?.nativeElement,
          e = this._textPrefixContainer?.nativeElement,
          r = this._iconSuffixContainer?.nativeElement,
          o = this._textSuffixContainer?.nativeElement,
          a = t?.getBoundingClientRect().width ?? 0,
          s = e?.getBoundingClientRect().width ?? 0,
          c = r?.getBoundingClientRect().width ?? 0,
          d = o?.getBoundingClientRect().width ?? 0,
          u = this._currentDirection === "rtl" ? "-1" : "1",
          x = `${a+s}px`,
          B = `calc(${u} * (${x} + var(--mat-mdc-form-field-label-offset-x, 0px)))`,
          I = `var(--mat-mdc-form-field-label-transform, ${Tg} translateX(${B}))`,
          V = a + s + c + d;
        return [I, V]
      }
      _writeOutlinedLabelStyles(t) {
        if (t !== null) {
          let [e, r] = t;
          this._floatingLabel && (this._floatingLabel.element.style.transform = e), r !== null && this._notchedOutline?._setMaxWidth(r)
        }
      }
      _isAttachedToDom() {
        let t = this._elementRef.nativeElement;
        if (t.getRootNode) {
          let e = t.getRootNode();
          return e && e !== t
        }
        return document.documentElement.contains(t)
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["mat-form-field"]
        ],
        contentQueries: function(e, r, o) {
          if (e & 1 && (sl(o, r._labelChild, ks, 5), Fe(o, wo, 5), Fe(o, Ns, 5), Fe(o, Ps, 5), Fe(o, Fs, 5), Fe(o, Ts, 5)), e & 2) {
            Vo();
            let a;
            et(a = it()) && (r._formFieldControl = a.first), et(a = it()) && (r._prefixChildren = a), et(a = it()) && (r._suffixChildren = a), et(a = it()) && (r._errorChildren = a), et(a = it()) && (r._hintChildren = a)
          }
        },
        viewQuery: function(e, r) {
          if (e & 1 && ($i(r._iconPrefixContainerSignal, Vu, 5), $i(r._textPrefixContainerSignal, ju, 5), $i(r._iconSuffixContainerSignal, Bu, 5), $i(r._textSuffixContainerSignal, zu, 5), Rt(lg, 5), Rt(Vu, 5), Rt(ju, 5), Rt(Bu, 5), Rt(zu, 5), Rt(Uu, 5), Rt(Wu, 5), Rt($u, 5)), e & 2) {
            Vo(4);
            let o;
            et(o = it()) && (r._textField = o.first), et(o = it()) && (r._iconPrefixContainer = o.first), et(o = it()) && (r._textPrefixContainer = o.first), et(o = it()) && (r._iconSuffixContainer = o.first), et(o = it()) && (r._textSuffixContainer = o.first), et(o = it()) && (r._floatingLabel = o.first), et(o = it()) && (r._notchedOutline = o.first), et(o = it()) && (r._lineRipple = o.first)
          }
        },
        hostAttrs: [1, "mat-mdc-form-field"],
        hostVars: 38,
        hostBindings: function(e, r) {
          e & 2 && H("mat-mdc-form-field-label-always-float", r._shouldAlwaysFloat())("mat-mdc-form-field-has-icon-prefix", r._hasIconPrefix)("mat-mdc-form-field-has-icon-suffix", r._hasIconSuffix)("mat-form-field-invalid", r._control.errorState)("mat-form-field-disabled", r._control.disabled)("mat-form-field-autofilled", r._control.autofilled)("mat-form-field-appearance-fill", r.appearance == "fill")("mat-form-field-appearance-outline", r.appearance == "outline")("mat-form-field-hide-placeholder", r._hasFloatingLabel() && !r._shouldLabelFloat())("mat-primary", r.color !== "accent" && r.color !== "warn")("mat-accent", r.color === "accent")("mat-warn", r.color === "warn")("ng-untouched", r._shouldForward("untouched"))("ng-touched", r._shouldForward("touched"))("ng-pristine", r._shouldForward("pristine"))("ng-dirty", r._shouldForward("dirty"))("ng-valid", r._shouldForward("valid"))("ng-invalid", r._shouldForward("invalid"))("ng-pending", r._shouldForward("pending"))
        },
        inputs: {
          hideRequiredMarker: "hideRequiredMarker",
          color: "color",
          floatLabel: "floatLabel",
          appearance: "appearance",
          subscriptSizing: "subscriptSizing",
          hintLabel: "hintLabel"
        },
        exportAs: ["matFormField"],
        features: [z([{
          provide: Eo,
          useExisting: i
        }, {
          provide: Yu,
          useExisting: i
        }])],
        ngContentSelectors: dg,
        decls: 18,
        vars: 21,
        consts: [
          ["labelTemplate", ""],
          ["textField", ""],
          ["iconPrefixContainer", ""],
          ["textPrefixContainer", ""],
          ["textSuffixContainer", ""],
          ["iconSuffixContainer", ""],
          [1, "mat-mdc-text-field-wrapper", "mdc-text-field", 3, "click"],
          [1, "mat-mdc-form-field-focus-overlay"],
          [1, "mat-mdc-form-field-flex"],
          ["matFormFieldNotchedOutline", "", 3, "matFormFieldNotchedOutlineOpen"],
          [1, "mat-mdc-form-field-icon-prefix"],
          [1, "mat-mdc-form-field-text-prefix"],
          [1, "mat-mdc-form-field-infix"],
          [3, "ngTemplateOutlet"],
          [1, "mat-mdc-form-field-text-suffix"],
          [1, "mat-mdc-form-field-icon-suffix"],
          ["matFormFieldLineRipple", ""],
          ["aria-atomic", "true", "aria-live", "polite", 1, "mat-mdc-form-field-subscript-wrapper", "mat-mdc-form-field-bottom-align"],
          [1, "mat-mdc-form-field-error-wrapper"],
          [1, "mat-mdc-form-field-hint-wrapper"],
          ["matFormFieldFloatingLabel", "", 3, "floating", "monitorResize", "id"],
          ["aria-hidden", "true", 1, "mat-mdc-form-field-required-marker", "mdc-floating-label--required"],
          [3, "id"],
          [1, "mat-mdc-form-field-hint-spacer"]
        ],
        template: function(e, r) {
          if (e & 1) {
            let o = Kn();
            Tt(cg), ei(0, mg, 1, 1, "ng-template", null, 0, cl), ct(2, "div", 6, 1), dt("click", function(s) {
              return Un(o), Hn(r._control.onContainerClick(s))
            }), vt(4, fg, 1, 0, "div", 7), ct(5, "div", 8), vt(6, vg, 2, 2, "div", 9), vt(7, _g, 3, 0, "div", 10), vt(8, bg, 3, 0, "div", 11), ct(9, "div", 12), vt(10, Cg, 1, 1, null, 13), U(11), rt(), vt(12, xg, 3, 0, "div", 14), vt(13, wg, 3, 0, "div", 15), rt(), vt(14, Eg, 1, 0, "div", 16), rt(), ct(15, "div", 17), vt(16, Sg, 2, 0, "div", 18)(17, Rg, 5, 1, "div", 19), rt()
          }
          if (e & 2) {
            let o;
            q(2), H("mdc-text-field--filled", !r._hasOutline())("mdc-text-field--outlined", r._hasOutline())("mdc-text-field--no-label", !r._hasFloatingLabel())("mdc-text-field--disabled", r._control.disabled)("mdc-text-field--invalid", r._control.errorState), q(2), _t(!r._hasOutline() && !r._control.disabled ? 4 : -1), q(2), _t(r._hasOutline() ? 6 : -1), q(), _t(r._hasIconPrefix ? 7 : -1), q(), _t(r._hasTextPrefix ? 8 : -1), q(2), _t(!r._hasOutline() || r._forceDisplayInfixLabel() ? 10 : -1), q(2), _t(r._hasTextSuffix ? 12 : -1), q(), _t(r._hasIconSuffix ? 13 : -1), q(), _t(r._hasOutline() ? -1 : 14), q(), H("mat-mdc-form-field-subscript-dynamic-size", r.subscriptSizing === "dynamic");
            let a = r._getSubscriptMessageType();
            q(), _t((o = a) === "error" ? 16 : o === "hint" ? 17 : -1)
          }
        },
        dependencies: [Uu, Wu, bl, $u, Ts],
        styles: [`.mdc-text-field{display:inline-flex;align-items:baseline;padding:0 16px;position:relative;box-sizing:border-box;overflow:hidden;will-change:opacity,transform,color;border-top-left-radius:4px;border-top-right-radius:4px;border-bottom-right-radius:0;border-bottom-left-radius:0}.mdc-text-field__input{width:100%;min-width:0;border:none;border-radius:0;background:none;padding:0;-moz-appearance:none;-webkit-appearance:none;height:28px}.mdc-text-field__input::-webkit-calendar-picker-indicator,.mdc-text-field__input::-webkit-search-cancel-button{display:none}.mdc-text-field__input::-ms-clear{display:none}.mdc-text-field__input:focus{outline:none}.mdc-text-field__input:invalid{box-shadow:none}.mdc-text-field__input::placeholder{opacity:0}.mdc-text-field__input::-moz-placeholder{opacity:0}.mdc-text-field__input::-webkit-input-placeholder{opacity:0}.mdc-text-field__input:-ms-input-placeholder{opacity:0}.mdc-text-field--no-label .mdc-text-field__input::placeholder,.mdc-text-field--focused .mdc-text-field__input::placeholder{opacity:1}.mdc-text-field--no-label .mdc-text-field__input::-moz-placeholder,.mdc-text-field--focused .mdc-text-field__input::-moz-placeholder{opacity:1}.mdc-text-field--no-label .mdc-text-field__input::-webkit-input-placeholder,.mdc-text-field--focused .mdc-text-field__input::-webkit-input-placeholder{opacity:1}.mdc-text-field--no-label .mdc-text-field__input:-ms-input-placeholder,.mdc-text-field--focused .mdc-text-field__input:-ms-input-placeholder{opacity:1}.mdc-text-field--disabled:not(.mdc-text-field--no-label) .mdc-text-field__input.mat-mdc-input-disabled-interactive::placeholder{opacity:0}.mdc-text-field--disabled:not(.mdc-text-field--no-label) .mdc-text-field__input.mat-mdc-input-disabled-interactive::-moz-placeholder{opacity:0}.mdc-text-field--disabled:not(.mdc-text-field--no-label) .mdc-text-field__input.mat-mdc-input-disabled-interactive::-webkit-input-placeholder{opacity:0}.mdc-text-field--disabled:not(.mdc-text-field--no-label) .mdc-text-field__input.mat-mdc-input-disabled-interactive:-ms-input-placeholder{opacity:0}.mdc-text-field--outlined .mdc-text-field__input,.mdc-text-field--filled.mdc-text-field--no-label .mdc-text-field__input{height:100%}.mdc-text-field--outlined .mdc-text-field__input{display:flex;border:none !important;background-color:rgba(0,0,0,0)}.mdc-text-field--disabled .mdc-text-field__input{pointer-events:auto}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-text-field__input{color:var(--mat-form-field-filled-input-text-color, var(--mat-sys-on-surface));caret-color:var(--mat-form-field-filled-caret-color, var(--mat-sys-primary))}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-text-field__input::placeholder{color:var(--mat-form-field-filled-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-text-field__input::-moz-placeholder{color:var(--mat-form-field-filled-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-text-field__input::-webkit-input-placeholder{color:var(--mat-form-field-filled-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-text-field__input:-ms-input-placeholder{color:var(--mat-form-field-filled-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--outlined:not(.mdc-text-field--disabled) .mdc-text-field__input{color:var(--mat-form-field-outlined-input-text-color, var(--mat-sys-on-surface));caret-color:var(--mat-form-field-outlined-caret-color, var(--mat-sys-primary))}.mdc-text-field--outlined:not(.mdc-text-field--disabled) .mdc-text-field__input::placeholder{color:var(--mat-form-field-outlined-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--outlined:not(.mdc-text-field--disabled) .mdc-text-field__input::-moz-placeholder{color:var(--mat-form-field-outlined-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--outlined:not(.mdc-text-field--disabled) .mdc-text-field__input::-webkit-input-placeholder{color:var(--mat-form-field-outlined-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--outlined:not(.mdc-text-field--disabled) .mdc-text-field__input:-ms-input-placeholder{color:var(--mat-form-field-outlined-input-text-placeholder-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--filled.mdc-text-field--invalid:not(.mdc-text-field--disabled) .mdc-text-field__input{caret-color:var(--mat-form-field-filled-error-caret-color, var(--mat-sys-error))}.mdc-text-field--outlined.mdc-text-field--invalid:not(.mdc-text-field--disabled) .mdc-text-field__input{caret-color:var(--mat-form-field-outlined-error-caret-color, var(--mat-sys-error))}.mdc-text-field--filled.mdc-text-field--disabled .mdc-text-field__input{color:var(--mat-form-field-filled-disabled-input-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mdc-text-field--outlined.mdc-text-field--disabled .mdc-text-field__input{color:var(--mat-form-field-outlined-disabled-input-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}@media(forced-colors: active){.mdc-text-field--disabled .mdc-text-field__input{background-color:Window}}.mdc-text-field--filled{height:56px;border-bottom-right-radius:0;border-bottom-left-radius:0;border-top-left-radius:var(--mat-form-field-filled-container-shape, var(--mat-sys-corner-extra-small));border-top-right-radius:var(--mat-form-field-filled-container-shape, var(--mat-sys-corner-extra-small))}.mdc-text-field--filled:not(.mdc-text-field--disabled){background-color:var(--mat-form-field-filled-container-color, var(--mat-sys-surface-variant))}.mdc-text-field--filled.mdc-text-field--disabled{background-color:var(--mat-form-field-filled-disabled-container-color, color-mix(in srgb, var(--mat-sys-on-surface) 4%, transparent))}.mdc-text-field--outlined{height:56px;overflow:visible;padding-right:max(16px,var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small)));padding-left:max(16px,var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small)) + 4px)}[dir=rtl] .mdc-text-field--outlined{padding-right:max(16px,var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small)) + 4px);padding-left:max(16px,var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small)))}.mdc-floating-label{position:absolute;left:0;transform-origin:left top;line-height:1.15rem;text-align:left;text-overflow:ellipsis;white-space:nowrap;cursor:text;overflow:hidden;will-change:transform}[dir=rtl] .mdc-floating-label{right:0;left:auto;transform-origin:right top;text-align:right}.mdc-text-field .mdc-floating-label{top:50%;transform:translateY(-50%);pointer-events:none}.mdc-notched-outline .mdc-floating-label{display:inline-block;position:relative;max-width:100%}.mdc-text-field--outlined .mdc-floating-label{left:4px;right:auto}[dir=rtl] .mdc-text-field--outlined .mdc-floating-label{left:auto;right:4px}.mdc-text-field--filled .mdc-floating-label{left:16px;right:auto}[dir=rtl] .mdc-text-field--filled .mdc-floating-label{left:auto;right:16px}.mdc-text-field--disabled .mdc-floating-label{cursor:default}@media(forced-colors: active){.mdc-text-field--disabled .mdc-floating-label{z-index:1}}.mdc-text-field--filled.mdc-text-field--no-label .mdc-floating-label{display:none}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-floating-label{color:var(--mat-form-field-filled-label-text-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--filled:not(.mdc-text-field--disabled).mdc-text-field--focused .mdc-floating-label{color:var(--mat-form-field-filled-focus-label-text-color, var(--mat-sys-primary))}.mdc-text-field--filled:not(.mdc-text-field--disabled):not(.mdc-text-field--focused):hover .mdc-floating-label{color:var(--mat-form-field-filled-hover-label-text-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--filled.mdc-text-field--disabled .mdc-floating-label{color:var(--mat-form-field-filled-disabled-label-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mdc-text-field--filled:not(.mdc-text-field--disabled).mdc-text-field--invalid .mdc-floating-label{color:var(--mat-form-field-filled-error-label-text-color, var(--mat-sys-error))}.mdc-text-field--filled:not(.mdc-text-field--disabled).mdc-text-field--invalid.mdc-text-field--focused .mdc-floating-label{color:var(--mat-form-field-filled-error-focus-label-text-color, var(--mat-sys-error))}.mdc-text-field--filled:not(.mdc-text-field--disabled).mdc-text-field--invalid:not(.mdc-text-field--disabled):hover .mdc-floating-label{color:var(--mat-form-field-filled-error-hover-label-text-color, var(--mat-sys-on-error-container))}.mdc-text-field--filled .mdc-floating-label{font-family:var(--mat-form-field-filled-label-text-font, var(--mat-sys-body-large-font));font-size:var(--mat-form-field-filled-label-text-size, var(--mat-sys-body-large-size));font-weight:var(--mat-form-field-filled-label-text-weight, var(--mat-sys-body-large-weight));letter-spacing:var(--mat-form-field-filled-label-text-tracking, var(--mat-sys-body-large-tracking))}.mdc-text-field--outlined:not(.mdc-text-field--disabled) .mdc-floating-label{color:var(--mat-form-field-outlined-label-text-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--focused .mdc-floating-label{color:var(--mat-form-field-outlined-focus-label-text-color, var(--mat-sys-primary))}.mdc-text-field--outlined:not(.mdc-text-field--disabled):not(.mdc-text-field--focused):hover .mdc-floating-label{color:var(--mat-form-field-outlined-hover-label-text-color, var(--mat-sys-on-surface))}.mdc-text-field--outlined.mdc-text-field--disabled .mdc-floating-label{color:var(--mat-form-field-outlined-disabled-label-text-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--invalid .mdc-floating-label{color:var(--mat-form-field-outlined-error-label-text-color, var(--mat-sys-error))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--invalid.mdc-text-field--focused .mdc-floating-label{color:var(--mat-form-field-outlined-error-focus-label-text-color, var(--mat-sys-error))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--invalid:not(.mdc-text-field--disabled):hover .mdc-floating-label{color:var(--mat-form-field-outlined-error-hover-label-text-color, var(--mat-sys-on-error-container))}.mdc-text-field--outlined .mdc-floating-label{font-family:var(--mat-form-field-outlined-label-text-font, var(--mat-sys-body-large-font));font-size:var(--mat-form-field-outlined-label-text-size, var(--mat-sys-body-large-size));font-weight:var(--mat-form-field-outlined-label-text-weight, var(--mat-sys-body-large-weight));letter-spacing:var(--mat-form-field-outlined-label-text-tracking, var(--mat-sys-body-large-tracking))}.mdc-floating-label--float-above{cursor:auto;transform:translateY(-106%) scale(0.75)}.mdc-text-field--filled .mdc-floating-label--float-above{transform:translateY(-106%) scale(0.75)}.mdc-text-field--outlined .mdc-floating-label--float-above{transform:translateY(-37.25px) scale(1);font-size:.75rem}.mdc-notched-outline .mdc-floating-label--float-above{text-overflow:clip}.mdc-notched-outline--upgraded .mdc-floating-label--float-above{max-width:133.3333333333%}.mdc-text-field--outlined.mdc-notched-outline--upgraded .mdc-floating-label--float-above,.mdc-text-field--outlined .mdc-notched-outline--upgraded .mdc-floating-label--float-above{transform:translateY(-34.75px) scale(0.75)}.mdc-text-field--outlined.mdc-notched-outline--upgraded .mdc-floating-label--float-above,.mdc-text-field--outlined .mdc-notched-outline--upgraded .mdc-floating-label--float-above{font-size:1rem}.mdc-floating-label--required:not(.mdc-floating-label--hide-required-marker)::after{margin-left:1px;margin-right:0;content:"*"}[dir=rtl] .mdc-floating-label--required:not(.mdc-floating-label--hide-required-marker)::after{margin-left:0;margin-right:1px}.mdc-notched-outline{display:flex;position:absolute;top:0;right:0;left:0;box-sizing:border-box;width:100%;max-width:100%;height:100%;text-align:left;pointer-events:none}[dir=rtl] .mdc-notched-outline{text-align:right}.mdc-text-field--outlined .mdc-notched-outline{z-index:1}.mat-mdc-notch-piece{box-sizing:border-box;height:100%;pointer-events:none;border-top:1px solid;border-bottom:1px solid}.mdc-text-field--focused .mat-mdc-notch-piece{border-width:2px}.mdc-text-field--outlined:not(.mdc-text-field--disabled) .mat-mdc-notch-piece{border-color:var(--mat-form-field-outlined-outline-color, var(--mat-sys-outline));border-width:var(--mat-form-field-outlined-outline-width, 1px)}.mdc-text-field--outlined:not(.mdc-text-field--disabled):not(.mdc-text-field--focused):hover .mat-mdc-notch-piece{border-color:var(--mat-form-field-outlined-hover-outline-color, var(--mat-sys-on-surface))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--focused .mat-mdc-notch-piece{border-color:var(--mat-form-field-outlined-focus-outline-color, var(--mat-sys-primary))}.mdc-text-field--outlined.mdc-text-field--disabled .mat-mdc-notch-piece{border-color:var(--mat-form-field-outlined-disabled-outline-color, color-mix(in srgb, var(--mat-sys-on-surface) 12%, transparent))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--invalid .mat-mdc-notch-piece{border-color:var(--mat-form-field-outlined-error-outline-color, var(--mat-sys-error))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--invalid:not(.mdc-text-field--focused):hover .mdc-notched-outline .mat-mdc-notch-piece{border-color:var(--mat-form-field-outlined-error-hover-outline-color, var(--mat-sys-on-error-container))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--invalid.mdc-text-field--focused .mat-mdc-notch-piece{border-color:var(--mat-form-field-outlined-error-focus-outline-color, var(--mat-sys-error))}.mdc-text-field--outlined:not(.mdc-text-field--disabled).mdc-text-field--focused .mdc-notched-outline .mat-mdc-notch-piece{border-width:var(--mat-form-field-outlined-focus-outline-width, 2px)}.mdc-notched-outline__leading{border-left:1px solid;border-right:none;border-top-right-radius:0;border-bottom-right-radius:0;border-top-left-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small));border-bottom-left-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small))}.mdc-text-field--outlined .mdc-notched-outline .mdc-notched-outline__leading{width:max(12px,var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small)))}[dir=rtl] .mdc-notched-outline__leading{border-left:none;border-right:1px solid;border-bottom-left-radius:0;border-top-left-radius:0;border-top-right-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small));border-bottom-right-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small))}.mdc-notched-outline__trailing{flex-grow:1;border-left:none;border-right:1px solid;border-top-left-radius:0;border-bottom-left-radius:0;border-top-right-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small));border-bottom-right-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small))}[dir=rtl] .mdc-notched-outline__trailing{border-left:1px solid;border-right:none;border-top-right-radius:0;border-bottom-right-radius:0;border-top-left-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small));border-bottom-left-radius:var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small))}.mdc-notched-outline__notch{flex:0 0 auto;width:auto}.mdc-text-field--outlined .mdc-notched-outline .mdc-notched-outline__notch{max-width:min(var(--mat-form-field-notch-max-width, 100%),calc(100% - max(12px, var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small))) * 2))}.mdc-text-field--outlined .mdc-notched-outline--notched .mdc-notched-outline__notch{max-width:min(100%,calc(100% - max(12px, var(--mat-form-field-outlined-container-shape, var(--mat-sys-corner-extra-small))) * 2))}.mdc-text-field--outlined .mdc-notched-outline--notched .mdc-notched-outline__notch{padding-top:1px}.mdc-text-field--focused.mdc-text-field--outlined .mdc-notched-outline--notched .mdc-notched-outline__notch{padding-top:2px}.mdc-notched-outline--notched .mdc-notched-outline__notch{padding-left:0;padding-right:8px;border-top:none}[dir=rtl] .mdc-notched-outline--notched .mdc-notched-outline__notch{padding-left:8px;padding-right:0}.mdc-notched-outline--no-label .mdc-notched-outline__notch{display:none}.mdc-line-ripple::before,.mdc-line-ripple::after{position:absolute;bottom:0;left:0;width:100%;border-bottom-style:solid;content:""}.mdc-line-ripple::before{z-index:1;border-bottom-width:var(--mat-form-field-filled-active-indicator-height, 1px)}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-line-ripple::before{border-bottom-color:var(--mat-form-field-filled-active-indicator-color, var(--mat-sys-on-surface-variant))}.mdc-text-field--filled:not(.mdc-text-field--disabled):not(.mdc-text-field--focused):hover .mdc-line-ripple::before{border-bottom-color:var(--mat-form-field-filled-hover-active-indicator-color, var(--mat-sys-on-surface))}.mdc-text-field--filled.mdc-text-field--disabled .mdc-line-ripple::before{border-bottom-color:var(--mat-form-field-filled-disabled-active-indicator-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mdc-text-field--filled:not(.mdc-text-field--disabled).mdc-text-field--invalid .mdc-line-ripple::before{border-bottom-color:var(--mat-form-field-filled-error-active-indicator-color, var(--mat-sys-error))}.mdc-text-field--filled:not(.mdc-text-field--disabled).mdc-text-field--invalid:not(.mdc-text-field--focused):hover .mdc-line-ripple::before{border-bottom-color:var(--mat-form-field-filled-error-hover-active-indicator-color, var(--mat-sys-on-error-container))}.mdc-line-ripple::after{transform:scaleX(0);opacity:0;z-index:2}.mdc-text-field--filled .mdc-line-ripple::after{border-bottom-width:var(--mat-form-field-filled-focus-active-indicator-height, 2px)}.mdc-text-field--filled:not(.mdc-text-field--disabled) .mdc-line-ripple::after{border-bottom-color:var(--mat-form-field-filled-focus-active-indicator-color, var(--mat-sys-primary))}.mdc-text-field--filled.mdc-text-field--invalid:not(.mdc-text-field--disabled) .mdc-line-ripple::after{border-bottom-color:var(--mat-form-field-filled-error-focus-active-indicator-color, var(--mat-sys-error))}.mdc-line-ripple--active::after{transform:scaleX(1);opacity:1}.mdc-line-ripple--deactivating::after{opacity:0}.mdc-text-field--disabled{pointer-events:none}.mat-mdc-form-field-textarea-control{vertical-align:middle;resize:vertical;box-sizing:border-box;height:auto;margin:0;padding:0;border:none;overflow:auto}.mat-mdc-form-field-input-control.mat-mdc-form-field-input-control{-moz-osx-font-smoothing:grayscale;-webkit-font-smoothing:antialiased;font:inherit;letter-spacing:inherit;text-decoration:inherit;text-transform:inherit;border:none}.mat-mdc-form-field .mat-mdc-floating-label.mdc-floating-label{-moz-osx-font-smoothing:grayscale;-webkit-font-smoothing:antialiased;line-height:normal;pointer-events:all;will-change:auto}.mat-mdc-form-field:not(.mat-form-field-disabled) .mat-mdc-floating-label.mdc-floating-label{cursor:inherit}.mdc-text-field--no-label:not(.mdc-text-field--textarea) .mat-mdc-form-field-input-control.mdc-text-field__input,.mat-mdc-text-field-wrapper .mat-mdc-form-field-input-control{height:auto}.mat-mdc-text-field-wrapper .mat-mdc-form-field-input-control.mdc-text-field__input[type=color]{height:23px}.mat-mdc-text-field-wrapper{height:auto;flex:auto;will-change:auto}.mat-mdc-form-field-has-icon-prefix .mat-mdc-text-field-wrapper{padding-left:0;--mat-mdc-form-field-label-offset-x: -16px}.mat-mdc-form-field-has-icon-suffix .mat-mdc-text-field-wrapper{padding-right:0}[dir=rtl] .mat-mdc-text-field-wrapper{padding-left:16px;padding-right:16px}[dir=rtl] .mat-mdc-form-field-has-icon-suffix .mat-mdc-text-field-wrapper{padding-left:0}[dir=rtl] .mat-mdc-form-field-has-icon-prefix .mat-mdc-text-field-wrapper{padding-right:0}.mat-form-field-disabled .mdc-text-field__input::placeholder{color:var(--mat-form-field-disabled-input-text-placeholder-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-form-field-disabled .mdc-text-field__input::-moz-placeholder{color:var(--mat-form-field-disabled-input-text-placeholder-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-form-field-disabled .mdc-text-field__input::-webkit-input-placeholder{color:var(--mat-form-field-disabled-input-text-placeholder-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-form-field-disabled .mdc-text-field__input:-ms-input-placeholder{color:var(--mat-form-field-disabled-input-text-placeholder-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-mdc-form-field-label-always-float .mdc-text-field__input::placeholder{transition-delay:40ms;transition-duration:110ms;opacity:1}.mat-mdc-text-field-wrapper .mat-mdc-form-field-infix .mat-mdc-floating-label{left:auto;right:auto}.mat-mdc-text-field-wrapper.mdc-text-field--outlined .mdc-text-field__input{display:inline-block}.mat-mdc-form-field .mat-mdc-text-field-wrapper.mdc-text-field .mdc-notched-outline__notch{padding-top:0}.mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field .mdc-notched-outline__notch{border-left:1px solid rgba(0,0,0,0)}[dir=rtl] .mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field.mat-mdc-form-field .mdc-notched-outline__notch{border-left:none;border-right:1px solid rgba(0,0,0,0)}.mat-mdc-form-field-infix{min-height:var(--mat-form-field-container-height, 56px);padding-top:var(--mat-form-field-filled-with-label-container-padding-top, 24px);padding-bottom:var(--mat-form-field-filled-with-label-container-padding-bottom, 8px)}.mdc-text-field--outlined .mat-mdc-form-field-infix,.mdc-text-field--no-label .mat-mdc-form-field-infix{padding-top:var(--mat-form-field-container-vertical-padding, 16px);padding-bottom:var(--mat-form-field-container-vertical-padding, 16px)}.mat-mdc-text-field-wrapper .mat-mdc-form-field-flex .mat-mdc-floating-label{top:calc(var(--mat-form-field-container-height, 56px)/2)}.mdc-text-field--filled .mat-mdc-floating-label{display:var(--mat-form-field-filled-label-display, block)}.mat-mdc-text-field-wrapper.mdc-text-field--outlined .mdc-notched-outline--upgraded .mdc-floating-label--float-above{--mat-mdc-form-field-label-transform: translateY(calc(calc(6.75px + var(--mat-form-field-container-height, 56px) / 2) * -1)) scale(var(--mat-mdc-form-field-floating-label-scale, 0.75));transform:var(--mat-mdc-form-field-label-transform)}@keyframes _mat-form-field-subscript-animation{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:translateY(0)}}.mat-mdc-form-field-subscript-wrapper{box-sizing:border-box;width:100%;position:relative}.mat-mdc-form-field-hint-wrapper,.mat-mdc-form-field-error-wrapper{position:absolute;top:0;left:0;right:0;padding:0 16px;opacity:1;transform:translateY(0);animation:_mat-form-field-subscript-animation 0ms cubic-bezier(0.55, 0, 0.55, 0.2)}.mat-mdc-form-field-subscript-dynamic-size .mat-mdc-form-field-hint-wrapper,.mat-mdc-form-field-subscript-dynamic-size .mat-mdc-form-field-error-wrapper{position:static}.mat-mdc-form-field-bottom-align::before{content:"";display:inline-block;height:16px}.mat-mdc-form-field-bottom-align.mat-mdc-form-field-subscript-dynamic-size::before{content:unset}.mat-mdc-form-field-hint-end{order:1}.mat-mdc-form-field-hint-wrapper{display:flex}.mat-mdc-form-field-hint-spacer{flex:1 0 1em}.mat-mdc-form-field-error{display:block;color:var(--mat-form-field-error-text-color, var(--mat-sys-error))}.mat-mdc-form-field-subscript-wrapper,.mat-mdc-form-field-bottom-align::before{-moz-osx-font-smoothing:grayscale;-webkit-font-smoothing:antialiased;font-family:var(--mat-form-field-subscript-text-font, var(--mat-sys-body-small-font));line-height:var(--mat-form-field-subscript-text-line-height, var(--mat-sys-body-small-line-height));font-size:var(--mat-form-field-subscript-text-size, var(--mat-sys-body-small-size));letter-spacing:var(--mat-form-field-subscript-text-tracking, var(--mat-sys-body-small-tracking));font-weight:var(--mat-form-field-subscript-text-weight, var(--mat-sys-body-small-weight))}.mat-mdc-form-field-focus-overlay{top:0;left:0;right:0;bottom:0;position:absolute;opacity:0;pointer-events:none;background-color:var(--mat-form-field-state-layer-color, var(--mat-sys-on-surface))}.mat-mdc-text-field-wrapper:hover .mat-mdc-form-field-focus-overlay{opacity:var(--mat-form-field-hover-state-layer-opacity, var(--mat-sys-hover-state-layer-opacity))}.mat-mdc-form-field.mat-focused .mat-mdc-form-field-focus-overlay{opacity:var(--mat-form-field-focus-state-layer-opacity, 0)}select.mat-mdc-form-field-input-control{-moz-appearance:none;-webkit-appearance:none;background-color:rgba(0,0,0,0);display:inline-flex;box-sizing:border-box}select.mat-mdc-form-field-input-control:not(:disabled){cursor:pointer}select.mat-mdc-form-field-input-control:not(.mat-mdc-native-select-inline) option{color:var(--mat-form-field-select-option-text-color, var(--mat-sys-neutral10))}select.mat-mdc-form-field-input-control:not(.mat-mdc-native-select-inline) option:disabled{color:var(--mat-form-field-select-disabled-option-text-color, color-mix(in srgb, var(--mat-sys-neutral10) 38%, transparent))}.mat-mdc-form-field-type-mat-native-select .mat-mdc-form-field-infix::after{content:"";width:0;height:0;border-left:5px solid rgba(0,0,0,0);border-right:5px solid rgba(0,0,0,0);border-top:5px solid;position:absolute;right:0;top:50%;margin-top:-2.5px;pointer-events:none;color:var(--mat-form-field-enabled-select-arrow-color, var(--mat-sys-on-surface-variant))}[dir=rtl] .mat-mdc-form-field-type-mat-native-select .mat-mdc-form-field-infix::after{right:auto;left:0}.mat-mdc-form-field-type-mat-native-select.mat-focused .mat-mdc-form-field-infix::after{color:var(--mat-form-field-focus-select-arrow-color, var(--mat-sys-primary))}.mat-mdc-form-field-type-mat-native-select.mat-form-field-disabled .mat-mdc-form-field-infix::after{color:var(--mat-form-field-disabled-select-arrow-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-mdc-form-field-type-mat-native-select .mat-mdc-form-field-input-control{padding-right:15px}[dir=rtl] .mat-mdc-form-field-type-mat-native-select .mat-mdc-form-field-input-control{padding-right:0;padding-left:15px}@media(forced-colors: active){.mat-form-field-appearance-fill .mat-mdc-text-field-wrapper{outline:solid 1px}}@media(forced-colors: active){.mat-form-field-appearance-fill.mat-form-field-disabled .mat-mdc-text-field-wrapper{outline-color:GrayText}}@media(forced-colors: active){.mat-form-field-appearance-fill.mat-focused .mat-mdc-text-field-wrapper{outline:dashed 3px}}@media(forced-colors: active){.mat-mdc-form-field.mat-focused .mdc-notched-outline{border:dashed 3px}}.mat-mdc-form-field-input-control[type=date],.mat-mdc-form-field-input-control[type=datetime],.mat-mdc-form-field-input-control[type=datetime-local],.mat-mdc-form-field-input-control[type=month],.mat-mdc-form-field-input-control[type=week],.mat-mdc-form-field-input-control[type=time]{line-height:1}.mat-mdc-form-field-input-control::-webkit-datetime-edit{line-height:1;padding:0;margin-bottom:-2px}.mat-mdc-form-field{--mat-mdc-form-field-floating-label-scale: 0.75;display:inline-flex;flex-direction:column;min-width:0;text-align:left;-moz-osx-font-smoothing:grayscale;-webkit-font-smoothing:antialiased;font-family:var(--mat-form-field-container-text-font, var(--mat-sys-body-large-font));line-height:var(--mat-form-field-container-text-line-height, var(--mat-sys-body-large-line-height));font-size:var(--mat-form-field-container-text-size, var(--mat-sys-body-large-size));letter-spacing:var(--mat-form-field-container-text-tracking, var(--mat-sys-body-large-tracking));font-weight:var(--mat-form-field-container-text-weight, var(--mat-sys-body-large-weight))}.mat-mdc-form-field .mdc-text-field--outlined .mdc-floating-label--float-above{font-size:calc(var(--mat-form-field-outlined-label-text-populated-size)*var(--mat-mdc-form-field-floating-label-scale))}.mat-mdc-form-field .mdc-text-field--outlined .mdc-notched-outline--upgraded .mdc-floating-label--float-above{font-size:var(--mat-form-field-outlined-label-text-populated-size)}[dir=rtl] .mat-mdc-form-field{text-align:right}.mat-mdc-form-field-flex{display:inline-flex;align-items:baseline;box-sizing:border-box;width:100%}.mat-mdc-text-field-wrapper{width:100%;z-index:0}.mat-mdc-form-field-icon-prefix,.mat-mdc-form-field-icon-suffix{align-self:center;line-height:0;pointer-events:auto;position:relative;z-index:1}.mat-mdc-form-field-icon-prefix>.mat-icon,.mat-mdc-form-field-icon-suffix>.mat-icon{padding:0 12px;box-sizing:content-box}.mat-mdc-form-field-icon-prefix{color:var(--mat-form-field-leading-icon-color, var(--mat-sys-on-surface-variant))}.mat-form-field-disabled .mat-mdc-form-field-icon-prefix{color:var(--mat-form-field-disabled-leading-icon-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-mdc-form-field-icon-suffix{color:var(--mat-form-field-trailing-icon-color, var(--mat-sys-on-surface-variant))}.mat-form-field-disabled .mat-mdc-form-field-icon-suffix{color:var(--mat-form-field-disabled-trailing-icon-color, color-mix(in srgb, var(--mat-sys-on-surface) 38%, transparent))}.mat-form-field-invalid .mat-mdc-form-field-icon-suffix{color:var(--mat-form-field-error-trailing-icon-color, var(--mat-sys-error))}.mat-form-field-invalid:not(.mat-focused):not(.mat-form-field-disabled) .mat-mdc-text-field-wrapper:hover .mat-mdc-form-field-icon-suffix{color:var(--mat-form-field-error-hover-trailing-icon-color, var(--mat-sys-on-error-container))}.mat-form-field-invalid.mat-focused .mat-mdc-text-field-wrapper .mat-mdc-form-field-icon-suffix{color:var(--mat-form-field-error-focus-trailing-icon-color, var(--mat-sys-error))}.mat-mdc-form-field-icon-prefix,[dir=rtl] .mat-mdc-form-field-icon-suffix{padding:0 4px 0 0}.mat-mdc-form-field-icon-suffix,[dir=rtl] .mat-mdc-form-field-icon-prefix{padding:0 0 0 4px}.mat-mdc-form-field-subscript-wrapper .mat-icon,.mat-mdc-form-field label .mat-icon{width:1em;height:1em;font-size:inherit}.mat-mdc-form-field-infix{flex:auto;min-width:0;width:180px;position:relative;box-sizing:border-box}.mat-mdc-form-field-infix:has(textarea[cols]){width:auto}.mat-mdc-form-field .mdc-notched-outline__notch{margin-left:-1px;-webkit-clip-path:inset(-9em -999em -9em 1px);clip-path:inset(-9em -999em -9em 1px)}[dir=rtl] .mat-mdc-form-field .mdc-notched-outline__notch{margin-left:0;margin-right:-1px;-webkit-clip-path:inset(-9em 1px -9em -999em);clip-path:inset(-9em 1px -9em -999em)}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-floating-label{transition:transform 150ms cubic-bezier(0.4, 0, 0.2, 1),color 150ms cubic-bezier(0.4, 0, 0.2, 1)}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-text-field__input{transition:opacity 150ms cubic-bezier(0.4, 0, 0.2, 1)}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-text-field__input::placeholder{transition:opacity 67ms cubic-bezier(0.4, 0, 0.2, 1)}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-text-field__input::-moz-placeholder{transition:opacity 67ms cubic-bezier(0.4, 0, 0.2, 1)}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-text-field__input::-webkit-input-placeholder{transition:opacity 67ms cubic-bezier(0.4, 0, 0.2, 1)}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-text-field__input:-ms-input-placeholder{transition:opacity 67ms cubic-bezier(0.4, 0, 0.2, 1)}.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--no-label .mdc-text-field__input::placeholder,.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--focused .mdc-text-field__input::placeholder{transition-delay:40ms;transition-duration:110ms}.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--no-label .mdc-text-field__input::-moz-placeholder,.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--focused .mdc-text-field__input::-moz-placeholder{transition-delay:40ms;transition-duration:110ms}.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--no-label .mdc-text-field__input::-webkit-input-placeholder,.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--focused .mdc-text-field__input::-webkit-input-placeholder{transition-delay:40ms;transition-duration:110ms}.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--no-label .mdc-text-field__input:-ms-input-placeholder,.mat-mdc-form-field.mat-form-field-animations-enabled.mdc-text-field--focused .mdc-text-field__input:-ms-input-placeholder{transition-delay:40ms;transition-duration:110ms}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-text-field--filled:not(.mdc-ripple-upgraded):focus .mdc-text-field__ripple::before{transition-duration:75ms}.mat-mdc-form-field.mat-form-field-animations-enabled .mdc-line-ripple::after{transition:transform 180ms cubic-bezier(0.4, 0, 0.2, 1),opacity 180ms cubic-bezier(0.4, 0, 0.2, 1)}.mat-mdc-form-field.mat-form-field-animations-enabled .mat-mdc-form-field-hint-wrapper,.mat-mdc-form-field.mat-form-field-animations-enabled .mat-mdc-form-field-error-wrapper{animation-duration:300ms}.mdc-notched-outline .mdc-floating-label{max-width:calc(100% + 1px)}.mdc-notched-outline--upgraded .mdc-floating-label--float-above{max-width:calc(133.3333333333% + 1px)}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })()
});
var Do, Vs = _(() => {
  ts();
  f();
  So();
  we();
  Do = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [X, Xr, Ls, X]
      })
    }
    return i
  })()
});
var Fg = _(() => {
  So();
  Vs()
});
var Ng, Pg, Zu, Xu, Qu = _(() => {
  f();
  f();
  nt();
  se();
  xi();
  Ei();
  Ng = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275cmp = P({
        type: i,
        selectors: [
          ["ng-component"]
        ],
        hostAttrs: ["cdk-text-field-style-loader", ""],
        decls: 0,
        vars: 0,
        template: function(e, r) {},
        styles: [`textarea.cdk-textarea-autosize{resize:none}textarea.cdk-textarea-autosize-measuring{padding:2px 0 !important;box-sizing:content-box !important;height:auto !important;overflow:hidden !important}textarea.cdk-textarea-autosize-measuring-firefox{padding:2px 0 !important;box-sizing:content-box !important;height:0 !important}@keyframes cdk-text-field-autofill-start{/*!*/}@keyframes cdk-text-field-autofill-end{/*!*/}.cdk-text-field-autofill-monitored:-webkit-autofill{animation:cdk-text-field-autofill-start 0s 1ms}.cdk-text-field-autofill-monitored:not(:-webkit-autofill){animation:cdk-text-field-autofill-end 0s 1ms}
`],
        encapsulation: 2,
        changeDetection: 0
      })
    }
    return i
  })(), Pg = {
    passive: !0
  }, Zu = (() => {
    class i {
      _platform = l(T);
      _ngZone = l(E);
      _renderer = l(kt).createRenderer(null, null);
      _styleLoader = l(Mt);
      _monitoredElements = new Map;
      constructor() {}
      monitor(t) {
        if (!this._platform.isBrowser) return Ut;
        this._styleLoader.load(Ng);
        let e = wt(t),
          r = this._monitoredElements.get(e);
        if (r) return r.subject;
        let o = new y,
          a = "cdk-text-field-autofilled",
          s = d => {
            d.animationName === "cdk-text-field-autofill-start" && !e.classList.contains(a) ? (e.classList.add(a), this._ngZone.run(() => o.next({
              target: d.target,
              isAutofilled: !0
            }))) : d.animationName === "cdk-text-field-autofill-end" && e.classList.contains(a) && (e.classList.remove(a), this._ngZone.run(() => o.next({
              target: d.target,
              isAutofilled: !1
            })))
          },
          c = this._ngZone.runOutsideAngular(() => (e.classList.add("cdk-text-field-autofill-monitored"), this._renderer.listen(e, "animationstart", s, Pg)));
        return this._monitoredElements.set(e, {
          subject: o,
          unlisten: c
        }), o
      }
      stopMonitoring(t) {
        let e = wt(t),
          r = this._monitoredElements.get(e);
        r && (r.unlisten(), r.subject.complete(), e.classList.remove("cdk-text-field-autofill-monitored"), e.classList.remove("cdk-text-field-autofilled"), this._monitoredElements.delete(e))
      }
      ngOnDestroy() {
        this._monitoredElements.forEach((t, e) => this.stopMonitoring(e))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })(), Xu = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({})
    }
    return i
  })()
});
var Ju, th = _(() => {
  f();
  Ju = new v("MAT_INPUT_VALUE_ACCESSOR")
});
var eh, ih = _(() => {
  f();
  eh = (() => {
    class i {
      isErrorState(t, e) {
        return !!(t && t.invalid && (t.touched || e && e.submitted))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});
var Ro, nh = _(() => {
  Ro = class {
    _defaultMatcher;
    ngControl;
    _parentFormGroup;
    _parentForm;
    _stateChanges;
    errorState = !1;
    matcher;
    constructor(n, t, e, r, o) {
      this._defaultMatcher = n, this.ngControl = t, this._parentFormGroup = e, this._parentForm = r, this._stateChanges = o
    }
    updateErrorState() {
      let n = this.errorState,
        t = this._parentFormGroup || this._parentForm,
        e = this.matcher || this._defaultMatcher,
        r = this.ngControl ? this.ngControl.control : null,
        o = e?.isErrorState(r, t) ?? !1;
      o !== n && (this.errorState = o, this._stateChanges.next())
    }
  }
});
var Lg, Vg, ZE, XE, jg = _(() => {
  no();
  Oi();
  Qu();
  f();
  f();
  qe();
  Nu();
  nt();
  th();
  So();
  ih();
  nh();
  Vs();
  we();
  Lg = ["button", "checkbox", "file", "hidden", "image", "radio", "range", "reset", "submit"], Vg = new v("MAT_INPUT_CONFIG"), ZE = (() => {
    class i {
      _elementRef = l(D);
      _platform = l(T);
      ngControl = l(qt, {
        optional: !0,
        self: !0
      });
      _autofillMonitor = l(Zu);
      _ngZone = l(E);
      _formField = l(Eo, {
        optional: !0
      });
      _renderer = l(lt);
      _uid = l(Wt).getId("mat-input-");
      _previousNativeValue;
      _inputValueAccessor;
      _signalBasedValueAccessor;
      _previousPlaceholder;
      _errorStateTracker;
      _config = l(Vg, {
        optional: !0
      });
      _cleanupIosKeyup;
      _cleanupWebkitWheel;
      _isServer;
      _isNativeSelect;
      _isTextarea;
      _isInFormField;
      focused = !1;
      stateChanges = new y;
      controlType = "mat-input";
      autofilled = !1;
      get disabled() {
        return this._disabled
      }
      set disabled(t) {
        this._disabled = ki(t), this.focused && (this.focused = !1, this.stateChanges.next())
      }
      _disabled = !1;
      get id() {
        return this._id
      }
      set id(t) {
        this._id = t || this._uid
      }
      _id;
      placeholder;
      name;
      get required() {
        return this._required ?? this.ngControl?.control?.hasValidator(ao.required) ?? !1
      }
      set required(t) {
        this._required = ki(t)
      }
      _required;
      get type() {
        return this._type
      }
      set type(t) {
        this._type = t || "text", this._validateType(), !this._isTextarea && cs().has(this._type) && (this._elementRef.nativeElement.type = this._type)
      }
      _type = "text";
      get errorStateMatcher() {
        return this._errorStateTracker.matcher
      }
      set errorStateMatcher(t) {
        this._errorStateTracker.matcher = t
      }
      userAriaDescribedBy;
      get value() {
        return this._signalBasedValueAccessor ? this._signalBasedValueAccessor.value() : this._inputValueAccessor.value
      }
      set value(t) {
        t !== this.value && (this._signalBasedValueAccessor ? this._signalBasedValueAccessor.value.set(t) : this._inputValueAccessor.value = t, this.stateChanges.next())
      }
      get readonly() {
        return this._readonly
      }
      set readonly(t) {
        this._readonly = ki(t)
      }
      _readonly = !1;
      disabledInteractive;
      get errorState() {
        return this._errorStateTracker.errorState
      }
      set errorState(t) {
        this._errorStateTracker.errorState = t
      }
      _neverEmptyInputTypes = ["date", "datetime", "datetime-local", "month", "time", "week"].filter(t => cs().has(t));
      constructor() {
        let t = l(Rs, {
            optional: !0
          }),
          e = l(Is, {
            optional: !0
          }),
          r = l(eh),
          o = l(Ju, {
            optional: !0,
            self: !0
          }),
          a = this._elementRef.nativeElement,
          s = a.nodeName.toLowerCase();
        o ? Ui(o.value) ? this._signalBasedValueAccessor = o : this._inputValueAccessor = o : this._inputValueAccessor = a, this._previousNativeValue = this.value, this.id = this.id, this._platform.IOS && this._ngZone.runOutsideAngular(() => {
          this._cleanupIosKeyup = this._renderer.listen(a, "keyup", this._iOSKeyupListener)
        }), this._errorStateTracker = new Ro(r, this.ngControl, e, t, this.stateChanges), this._isServer = !this._platform.isBrowser, this._isNativeSelect = s === "select", this._isTextarea = s === "textarea", this._isInFormField = !!this._formField, this.disabledInteractive = this._config?.disabledInteractive || !1, this._isNativeSelect && (this.controlType = a.multiple ? "mat-native-select-multiple" : "mat-native-select"), this._signalBasedValueAccessor && Ne(() => {
          this._signalBasedValueAccessor.value(), this.stateChanges.next()
        })
      }
      ngAfterViewInit() {
        this._platform.isBrowser && this._autofillMonitor.monitor(this._elementRef.nativeElement).subscribe(t => {
          this.autofilled = t.isAutofilled, this.stateChanges.next()
        })
      }
      ngOnChanges() {
        this.stateChanges.next()
      }
      ngOnDestroy() {
        this.stateChanges.complete(), this._platform.isBrowser && this._autofillMonitor.stopMonitoring(this._elementRef.nativeElement), this._cleanupIosKeyup?.(), this._cleanupWebkitWheel?.()
      }
      ngDoCheck() {
        this.ngControl && (this.updateErrorState(), this.ngControl.disabled !== null && this.ngControl.disabled !== this.disabled && (this.disabled = this.ngControl.disabled, this.stateChanges.next())), this._dirtyCheckNativeValue(), this._dirtyCheckPlaceholder()
      }
      focus(t) {
        this._elementRef.nativeElement.focus(t)
      }
      updateErrorState() {
        this._errorStateTracker.updateErrorState()
      }
      _focusChanged(t) {
        if (t !== this.focused) {
          if (!this._isNativeSelect && t && this.disabled && this.disabledInteractive) {
            let e = this._elementRef.nativeElement;
            e.type === "number" ? (e.type = "text", e.setSelectionRange(0, 0), e.type = "number") : e.setSelectionRange(0, 0)
          }
          this.focused = t, this.stateChanges.next()
        }
      }
      _onInput() {}
      _dirtyCheckNativeValue() {
        let t = this._elementRef.nativeElement.value;
        this._previousNativeValue !== t && (this._previousNativeValue = t, this.stateChanges.next())
      }
      _dirtyCheckPlaceholder() {
        let t = this._getPlaceholder();
        if (t !== this._previousPlaceholder) {
          let e = this._elementRef.nativeElement;
          this._previousPlaceholder = t, t ? e.setAttribute("placeholder", t) : e.removeAttribute("placeholder")
        }
      }
      _getPlaceholder() {
        return this.placeholder || null
      }
      _validateType() {
        Lg.indexOf(this._type) > -1
      }
      _isNeverEmpty() {
        return this._neverEmptyInputTypes.indexOf(this._type) > -1
      }
      _isBadInput() {
        let t = this._elementRef.nativeElement.validity;
        return t && t.badInput
      }
      get empty() {
        return !this._isNeverEmpty() && !this._elementRef.nativeElement.value && !this._isBadInput() && !this.autofilled
      }
      get shouldLabelFloat() {
        if (this._isNativeSelect) {
          let t = this._elementRef.nativeElement,
            e = t.options[0];
          return this.focused || t.multiple || !this.empty || !!(t.selectedIndex > -1 && e && e.label)
        } else return this.focused && !this.disabled || !this.empty
      }
      get describedByIds() {
        return this._elementRef.nativeElement.getAttribute("aria-describedby")?.split(" ") || []
      }
      setDescribedByIds(t) {
        let e = this._elementRef.nativeElement;
        t.length ? e.setAttribute("aria-describedby", t.join(" ")) : e.removeAttribute("aria-describedby")
      }
      onContainerClick() {
        this.focused || this.focus()
      }
      _isInlineSelect() {
        let t = this._elementRef.nativeElement;
        return this._isNativeSelect && (t.multiple || t.size > 1)
      }
      _iOSKeyupListener = t => {
        let e = t.target;
        !e.value && e.selectionStart === 0 && e.selectionEnd === 0 && (e.setSelectionRange(1, 1), e.setSelectionRange(0, 0))
      };
      _getReadonlyAttribute() {
        return this._isNativeSelect ? null : this.readonly || this.disabled && this.disabledInteractive ? "true" : null
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275dir = p({
        type: i,
        selectors: [
          ["input", "matInput", ""],
          ["textarea", "matInput", ""],
          ["select", "matNativeControl", ""],
          ["input", "matNativeControl", ""],
          ["textarea", "matNativeControl", ""]
        ],
        hostAttrs: [1, "mat-mdc-input-element"],
        hostVars: 21,
        hostBindings: function(e, r) {
          e & 1 && dt("focus", function() {
            return r._focusChanged(!0)
          })("blur", function() {
            return r._focusChanged(!1)
          })("input", function() {
            return r._onInput()
          }), e & 2 && (Hi("id", r.id)("disabled", r.disabled && !r.disabledInteractive)("required", r.required), tt("name", r.name || null)("readonly", r._getReadonlyAttribute())("aria-disabled", r.disabled && r.disabledInteractive ? "true" : null)("aria-invalid", r.empty && r.required ? null : r.errorState)("aria-required", r.required)("id", r.id), H("mat-input-server", r._isServer)("mat-mdc-form-field-textarea-control", r._isInFormField && r._isTextarea)("mat-mdc-form-field-input-control", r._isInFormField)("mat-mdc-input-disabled-interactive", r.disabledInteractive)("mdc-text-field__input", r._isInFormField)("mat-mdc-native-select-inline", r._isInlineSelect()))
        },
        inputs: {
          disabled: "disabled",
          id: "id",
          placeholder: "placeholder",
          name: "name",
          required: "required",
          type: "type",
          errorStateMatcher: "errorStateMatcher",
          userAriaDescribedBy: [0, "aria-describedby", "userAriaDescribedBy"],
          value: "value",
          readonly: "readonly",
          disabledInteractive: [2, "disabledInteractive", "disabledInteractive", F]
        },
        exportAs: ["matInput"],
        features: [z([{
          provide: wo,
          useExisting: i
        }]), mt]
      })
    }
    return i
  })(), XE = (() => {
    class i {
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275mod = R({
        type: i
      });
      static \u0275inj = S({
        imports: [X, Do, Do, Xu, X]
      })
    }
    return i
  })()
});
var rS, Bg = _(() => {
  f();
  Uo();
  ht();
  Ho();
  f();
  rS = (() => {
    class i {
      http = l(ni);
      hostServer = Jn.hostServer;
      host = this.hostServer + "/rest/web3";
      nftUnlocked() {
        return this.http.get(this.host + "/nftUnlocked").pipe(b(t => t), at(t => {
          throw t
        }))
      }
      nftMintListen() {
        return this.http.get(this.host + "/nftMintListen").pipe(b(t => t), at(t => {
          throw t
        }))
      }
      checkNftMinted() {
        return this.http.get(this.hostServer + "/api/Challenges/?key=nftMintChallenge").pipe(b(t => t), at(t => {
          throw t
        }))
      }
      submitKey(t) {
        let e = this.host + "/submitKey",
          r = {
            privateKey: t
          };
        return this.http.post(e, r).pipe(b(o => o), at(o => {
          throw o
        }))
      }
      verifyNFTWallet(t) {
        let e = this.host + "/walletNFTVerify",
          r = {
            walletAddress: t
          };
        return this.http.post(e, r).pipe(b(o => o), at(o => {
          throw o
        }))
      }
      walletAddressSend(t) {
        let e = this.host + "/walletExploitAddress",
          r = {
            walletAddress: t
          };
        return this.http.post(e, r).pipe(b(o => o), at(o => {
          throw o
        }))
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});
var dS, zg = _(() => {
  f();
  eu();
  Il();
  f();
  dS = (() => {
    class i {
      translateService = l(si);
      snackBar = l(_s);
      open(t, e) {
        this.translateService.get(t).subscribe({
          next: r => {
            this.snackBar.open(r, "X", {
              duration: 5e3,
              panelClass: [e, "mat-body"]
            })
          },
          error: () => {
            this.snackBar.open(t, "X", {
              duration: 5e3,
              panelClass: [e, "mat-body"]
            })
          }
        })
      }
      static \u0275fac = function(e) {
        return new(e || i)
      };
      static \u0275prov = m({
        token: i,
        factory: i.\u0275fac,
        providedIn: "root"
      })
    }
    return i
  })()
});
export {
  Jn as a, Ho as b, ri as c, si as d, Qg as e, Jg as f, tv as g, Il as h, re as i, fa as j, ae as k, bc as l, Pm as m, Um as n, r_ as o, Hm as p, Di as q, Ce as r, Ri as s, ub as t, La as u, Fr as v, Va as w, En as x, Sn as y, Aa as z, fn as A, T as B, se as C, Ai as D, pn as E, Tc as F, Kr as G, hf as H, fd as I, Mt as J, Zr as K, An as L, iC as M, Xr as N, ts as O, yd as P, xd as Q, Ef as R, is as S, Df as T, ns as U, Nr as V, za as W, Y as X, le as Y, Ir as Z, Bt as _, He as $, M_ as aa, vn as ba, Fc as ca, k_ as da, qm as ea, Ym as fa, N_ as ga, Km as ha, _n as ia, Qm as ja, Si as ka, Ta as la, Fa as ma, Na as na, Wt as oa, Ba as pa, Uc as qa, Hr as ra, We as sa, Wa as ta, Br as ua, Ga as va, zr as wa, $r as xa, Cn as ya, $a as za, rf as Aa, qa as Ba, Ya as Ca, Qc as Da, ki as Ea, Dx as Fa, no as Ga, fy as Ha, Za as Ia, Vf as Ja, Gt as Ka, Ti as La, os as Ma, as as Na, Af as Oa, Mf as Pa, KC as Qa, qe as Ra, X as Sa, we as Ta, _x as Ua, bx as Va, Pf as Wa, Oi as Xa, zt as Ya, In as Za, hs as _a, $x as $a, jd as ab, Wd as bb, Gd as cb, qf as db, Yd as eb, Bd as fb, zd as gb, Zd as hb, Xd as ib, Qd as jb, D0 as kb, R0 as lb, A0 as mb, M0 as nb, I0 as ob, O0 as pb, k0 as qb, ip as rb, _s as sb, Q0 as tb, eu as ub, dS as vb, zg as wb, Se as xb, fp as yb, du as zb, ue as Ab, ao as Bb, qt as Cb, _w as Db, bw as Eb, yw as Fb, Rs as Gb, xw as Hb, jp as Ib, ww as Jb, zp as Kb, Hp as Lb, Is as Mb, Gp as Nb, Ou as Ob, Ew as Pb, Sw as Qb, Qp as Rb, tg as Sb, ig as Tb, rg as Ub, Dw as Vb, Rw as Wb, Nu as Xb, Pu as Yb, Lu as Zb, ks as _b, Ag as $b, Ts as ac, Mg as bc, Ig as cc, wo as dc, Eo as ec, Ls as fc, So as gc, Do as hc, Vs as ic, Fg as jc, Ju as kc, th as lc, eh as mc, ih as nc, Ro as oc, nh as pc, ZE as qc, XE as rc, jg as sc, rS as tc, Bg as uc
};