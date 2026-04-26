import {
  a as V,
  b as G,
  e as h
} from "./chunk-TWZW5B45.js";

function Uo() {
  return wa
}

function Ge(e) {
  let t = wa;
  return wa = e, t
}

function Nn(e) {
  return e === Ef || e?.name === "ɵNotFound"
}
var wa, Ef, Ca = h(() => {
  Ef = Symbol("NotFound")
});

function M(e) {
  let t = oe;
  return oe = e, t
}

function qo() {
  return oe
}

function $t(e) {
  if ($o) throw new Error("");
  if (oe === null) return;
  oe.consumerOnSignalRead(e);
  let t = oe.producersTail;
  if (t !== void 0 && t.producer === e) return;
  let n, r = oe.recomputing;
  if (r && (n = t !== void 0 ? t.nextProducer : oe.producers, n !== void 0 && n.producer === e)) {
    oe.producersTail = n, n.lastReadVersion = e.version;
    return
  }
  let o = e.consumersTail;
  if (o !== void 0 && o.consumer === oe && (!r || mD(o, oe))) return;
  let i = An(oe),
    s = {
      producer: e,
      consumer: oe,
      nextProducer: n,
      prevConsumer: o,
      lastReadVersion: e.version,
      nextConsumer: void 0
    };
  oe.producersTail = s, t !== void 0 ? t.nextProducer = s : oe.producers = s, i && bf(e, s)
}

function If() {
  ba++
}

function Zo(e) {
  if (!(An(e) && !e.dirty) && !(!e.dirty && e.lastCleanEpoch === ba)) {
    if (!e.producerMustRecompute(e) && !Gt(e)) {
      Wo(e);
      return
    }
    e.producerRecomputeValue(e), Wo(e)
  }
}

function Ta(e) {
  if (e.consumers === void 0) return;
  let t = $o;
  $o = !0;
  try {
    for (let n = e.consumers; n !== void 0; n = n.nextConsumer) {
      let r = n.consumer;
      r.dirty || gD(r)
    }
  } finally {
    $o = t
  }
}

function _a() {
  return oe?.consumerAllowSignalWrites !== !1
}

function gD(e) {
  e.dirty = !0, Ta(e), e.consumerMarkedDirty?.(e)
}

function Wo(e) {
  e.dirty = !1, e.lastCleanEpoch = ba
}

function Ct(e) {
  return e && wf(e), M(e)
}

function wf(e) {
  e.producersTail = void 0, e.recomputing = !0
}

function zt(e, t) {
  M(t), e && Cf(e)
}

function Cf(e) {
  e.recomputing = !1;
  let t = e.producersTail,
    n = t !== void 0 ? t.nextProducer : e.producers;
  if (n !== void 0) {
    if (An(e))
      do n = Ma(n); while (n !== void 0);
    t !== void 0 ? t.nextProducer = void 0 : e.producers = void 0
  }
}

function Gt(e) {
  for (let t = e.producers; t !== void 0; t = t.nextProducer) {
    let n = t.producer,
      r = t.lastReadVersion;
    if (r !== n.version || (Zo(n), r !== n.version)) return !0
  }
  return !1
}

function bt(e) {
  if (An(e)) {
    let t = e.producers;
    for (; t !== void 0;) t = Ma(t)
  }
  e.producers = void 0, e.producersTail = void 0, e.consumers = void 0, e.consumersTail = void 0
}

function bf(e, t) {
  let n = e.consumersTail,
    r = An(e);
  if (n !== void 0 ? (t.nextConsumer = n.nextConsumer, n.nextConsumer = t) : (t.nextConsumer = void 0, e.consumers = t), t.prevConsumer = n, e.consumersTail = t, !r)
    for (let o = e.producers; o !== void 0; o = o.nextProducer) bf(o.producer, o)
}

function Ma(e) {
  let t = e.producer,
    n = e.nextProducer,
    r = e.nextConsumer,
    o = e.prevConsumer;
  if (e.nextConsumer = void 0, e.prevConsumer = void 0, r !== void 0 ? r.prevConsumer = o : t.consumersTail = o, o !== void 0) o.nextConsumer = r;
  else if (t.consumers = r, !An(t)) {
    let i = t.producers;
    for (; i !== void 0;) i = Ma(i)
  }
  return n
}

function An(e) {
  return e.consumerIsAlwaysLive || e.consumers !== void 0
}

function Yo(e) {
  hD?.(e)
}

function mD(e, t) {
  let n = t.producersTail;
  if (n !== void 0) {
    let r = t.producers;
    do {
      if (r === e) return !0;
      if (r === n) break;
      r = r.nextProducer
    } while (r !== void 0)
  }
  return !1
}

function Qo(e, t) {
  return Object.is(e, t)
}

function Mr(e, t) {
  let n = Object.create(yD);
  n.computation = e, t !== void 0 && (n.equal = t);
  let r = () => {
    if (Zo(n), $t(n), n.value === _r) throw n.error;
    return n.value
  };
  return r[X] = n, Yo(n), r
}

function vD() {
  throw new Error
}

function _f(e) {
  Tf(e)
}

function Sa(e) {
  Tf = e
}

function Na(e, t) {
  let n = Object.create(Sr);
  n.value = e, t !== void 0 && (n.equal = t);
  let r = () => Mf(n);
  return r[X] = n, Yo(n), [r, s => xn(n, s), s => Aa(n, s)]
}

function Mf(e) {
  return $t(e), e.value
}

function xn(e, t) {
  _a() || _f(e), e.equal(e.value, t) || (e.value = t, ED(e))
}

function Aa(e, t) {
  _a() || _f(e), xn(e, t(e.value))
}

function ED(e) {
  e.version++, If(), Ta(e), DD?.(e)
}
var oe, $o, ba, hD, X, Ut, zo, Go, _r, yD, Tf, DD, Sr, Wt = h(() => {
  oe = null, $o = !1, ba = 1, hD = null, X = Symbol("SIGNAL");
  Ut = {
    version: 0,
    lastCleanEpoch: 0,
    dirty: !1,
    producers: void 0,
    producersTail: void 0,
    consumers: void 0,
    consumersTail: void 0,
    recomputing: !1,
    consumerAllowSignalWrites: !1,
    consumerIsAlwaysLive: !1,
    kind: "unknown",
    producerMustRecompute: () => !1,
    producerRecomputeValue: () => {},
    consumerMarkedDirty: () => {},
    consumerOnSignalRead: () => {}
  };
  zo = Symbol("UNSET"), Go = Symbol("COMPUTING"), _r = Symbol("ERRORED"), yD = G(V({}, Ut), {
    value: zo,
    dirty: !0,
    error: null,
    equal: Qo,
    kind: "computed",
    producerMustRecompute(e) {
      return e.value === zo || e.value === Go
    },
    producerRecomputeValue(e) {
      if (e.value === Go) throw new Error("");
      let t = e.value;
      e.value = Go;
      let n = Ct(e),
        r, o = !1;
      try {
        r = e.computation(), M(null), o = t !== zo && t !== _r && r !== _r && e.equal(t, r)
      } catch (i) {
        r = _r, e.error = i
      } finally {
        zt(e, n)
      }
      if (o) {
        e.value = t;
        return
      }
      e.value = r, e.version++
    }
  });
  Tf = vD;
  DD = null;
  Sr = G(V({}, Ut), {
    equal: Qo,
    value: void 0,
    kind: "signal"
  })
});

function b(e) {
  return typeof e == "function"
}
var K = h(() => {});

function Rn(e) {
  let n = e(r => {
    Error.call(r), r.stack = new Error().stack
  });
  return n.prototype = Object.create(Error.prototype), n.prototype.constructor = n, n
}
var Ko = h(() => {});
var Jo, Sf = h(() => {
  Ko();
  Jo = Rn(e => function(n) {
    e(this), this.message = n ? `${n.length} errors occurred during unsubscription:
${n.map((r,o)=>`${o+1}) ${r.toString()}`).join(`
  `)}` : "", this.name = "UnsubscriptionError", this.errors = n
  })
});

function qt(e, t) {
  if (e) {
    let n = e.indexOf(t);
    0 <= n && e.splice(n, 1)
  }
}
var Xo = h(() => {});

function ei(e) {
  return e instanceof W || e && "closed" in e && b(e.remove) && b(e.add) && b(e.unsubscribe)
}

function Nf(e) {
  b(e) ? e() : e.unsubscribe()
}
var W, xa, Tt = h(() => {
  K();
  Sf();
  Xo();
  W = class e {
    constructor(t) {
      this.initialTeardown = t, this.closed = !1, this._parentage = null, this._finalizers = null
    }
    unsubscribe() {
      let t;
      if (!this.closed) {
        this.closed = !0;
        let {
          _parentage: n
        } = this;
        if (n)
          if (this._parentage = null, Array.isArray(n))
            for (let i of n) i.remove(this);
          else n.remove(this);
        let {
          initialTeardown: r
        } = this;
        if (b(r)) try {
          r()
        } catch (i) {
          t = i instanceof Jo ? i.errors : [i]
        }
        let {
          _finalizers: o
        } = this;
        if (o) {
          this._finalizers = null;
          for (let i of o) try {
            Nf(i)
          } catch (s) {
            t = t ?? [], s instanceof Jo ? t = [...t, ...s.errors] : t.push(s)
          }
        }
        if (t) throw new Jo(t)
      }
    }
    add(t) {
      var n;
      if (t && t !== this)
        if (this.closed) Nf(t);
        else {
          if (t instanceof e) {
            if (t.closed || t._hasParent(this)) return;
            t._addParent(this)
          }(this._finalizers = (n = this._finalizers) !== null && n !== void 0 ? n : []).push(t)
        }
    }
    _hasParent(t) {
      let {
        _parentage: n
      } = this;
      return n === t || Array.isArray(n) && n.includes(t)
    }
    _addParent(t) {
      let {
        _parentage: n
      } = this;
      this._parentage = Array.isArray(n) ? (n.push(t), n) : n ? [n, t] : t
    }
    _removeParent(t) {
      let {
        _parentage: n
      } = this;
      n === t ? this._parentage = null : Array.isArray(n) && qt(n, t)
    }
    remove(t) {
      let {
        _finalizers: n
      } = this;
      n && qt(n, t), t instanceof e && t._removeParent(this)
    }
  };
  W.EMPTY = (() => {
    let e = new W;
    return e.closed = !0, e
  })();
  xa = W.EMPTY
});
var Re, Nr = h(() => {
  Re = {
    onUnhandledError: null,
    onStoppedNotification: null,
    Promise: void 0,
    useDeprecatedSynchronousErrorHandling: !1,
    useDeprecatedNextContext: !1
  }
});
var On, Ra = h(() => {
  On = {
    setTimeout(e, t, ...n) {
      let {
        delegate: r
      } = On;
      return r?.setTimeout ? r.setTimeout(e, t, ...n) : setTimeout(e, t, ...n)
    },
    clearTimeout(e) {
      let {
        delegate: t
      } = On;
      return (t?.clearTimeout || clearTimeout)(e)
    },
    delegate: void 0
  }
});

function ti(e) {
  On.setTimeout(() => {
    let {
      onUnhandledError: t
    } = Re;
    if (t) t(e);
    else throw e
  })
}
var Oa = h(() => {
  Nr();
  Ra()
});

function Zt() {}
var ni = h(() => {});

function xf(e) {
  return Fa("E", void 0, e)
}

function Rf(e) {
  return Fa("N", e, void 0)
}

function Fa(e, t, n) {
  return {
    kind: e,
    value: t,
    error: n
  }
}
var Af, Of = h(() => {
  Af = Fa("C", void 0, void 0)
});

function Fn(e) {
  if (Re.useDeprecatedSynchronousErrorHandling) {
    let t = !Yt;
    if (t && (Yt = {
        errorThrown: !1,
        error: null
      }), e(), t) {
      let {
        errorThrown: n,
        error: r
      } = Yt;
      if (Yt = null, n) throw r
    }
  } else e()
}

function Ff(e) {
  Re.useDeprecatedSynchronousErrorHandling && Yt && (Yt.errorThrown = !0, Yt.error = e)
}
var Yt, ri = h(() => {
  Nr();
  Yt = null
});

function ka(e, t) {
  return ID.call(e, t)
}

function oi(e) {
  Re.useDeprecatedSynchronousErrorHandling ? Ff(e) : ti(e)
}

function wD(e) {
  throw e
}

function Pa(e, t) {
  let {
    onStoppedNotification: n
  } = Re;
  n && On.setTimeout(() => n(e, t))
}
var Qt, ID, La, Oe, CD, Ar = h(() => {
  K();
  Tt();
  Nr();
  Oa();
  ni();
  Of();
  Ra();
  ri();
  Qt = class extends W {
    constructor(t) {
      super(), this.isStopped = !1, t ? (this.destination = t, ei(t) && t.add(this)) : this.destination = CD
    }
    static create(t, n, r) {
      return new Oe(t, n, r)
    }
    next(t) {
      this.isStopped ? Pa(Rf(t), this) : this._next(t)
    }
    error(t) {
      this.isStopped ? Pa(xf(t), this) : (this.isStopped = !0, this._error(t))
    }
    complete() {
      this.isStopped ? Pa(Af, this) : (this.isStopped = !0, this._complete())
    }
    unsubscribe() {
      this.closed || (this.isStopped = !0, super.unsubscribe(), this.destination = null)
    }
    _next(t) {
      this.destination.next(t)
    }
    _error(t) {
      try {
        this.destination.error(t)
      } finally {
        this.unsubscribe()
      }
    }
    _complete() {
      try {
        this.destination.complete()
      } finally {
        this.unsubscribe()
      }
    }
  }, ID = Function.prototype.bind;
  La = class {
    constructor(t) {
      this.partialObserver = t
    }
    next(t) {
      let {
        partialObserver: n
      } = this;
      if (n.next) try {
        n.next(t)
      } catch (r) {
        oi(r)
      }
    }
    error(t) {
      let {
        partialObserver: n
      } = this;
      if (n.error) try {
        n.error(t)
      } catch (r) {
        oi(r)
      } else oi(t)
    }
    complete() {
      let {
        partialObserver: t
      } = this;
      if (t.complete) try {
        t.complete()
      } catch (n) {
        oi(n)
      }
    }
  }, Oe = class extends Qt {
    constructor(t, n, r) {
      super();
      let o;
      if (b(t) || !t) o = {
        next: t ?? void 0,
        error: n ?? void 0,
        complete: r ?? void 0
      };
      else {
        let i;
        this && Re.useDeprecatedNextContext ? (i = Object.create(t), i.unsubscribe = () => this.unsubscribe(), o = {
          next: t.next && ka(t.next, i),
          error: t.error && ka(t.error, i),
          complete: t.complete && ka(t.complete, i)
        }) : o = t
      }
      this.destination = new La(o)
    }
  };
  CD = {
    closed: !0,
    next: Zt,
    error: wD,
    complete: Zt
  }
});
var kn, ii = h(() => {
  kn = typeof Symbol == "function" && Symbol.observable || "@@observable"
});

function ue(e) {
  return e
}
var _t = h(() => {});

function bD(...e) {
  return ja(e)
}

function ja(e) {
  return e.length === 0 ? ue : e.length === 1 ? e[0] : function(n) {
    return e.reduce((r, o) => o(r), n)
  }
}
var Ba = h(() => {
  _t()
});

function kf(e) {
  var t;
  return (t = e ?? Re.Promise) !== null && t !== void 0 ? t : Promise
}

function TD(e) {
  return e && b(e.next) && b(e.error) && b(e.complete)
}

function _D(e) {
  return e && e instanceof Qt || TD(e) && ei(e)
}
var R, ie = h(() => {
  Ar();
  Tt();
  ii();
  Ba();
  Nr();
  K();
  ri();
  R = (() => {
    class e {
      constructor(n) {
        n && (this._subscribe = n)
      }
      lift(n) {
        let r = new e;
        return r.source = this, r.operator = n, r
      }
      subscribe(n, r, o) {
        let i = _D(n) ? n : new Oe(n, r, o);
        return Fn(() => {
          let {
            operator: s,
            source: a
          } = this;
          i.add(s ? s.call(i, a) : a ? this._subscribe(i) : this._trySubscribe(i))
        }), i
      }
      _trySubscribe(n) {
        try {
          return this._subscribe(n)
        } catch (r) {
          n.error(r)
        }
      }
      forEach(n, r) {
        return r = kf(r), new r((o, i) => {
          let s = new Oe({
            next: a => {
              try {
                n(a)
              } catch (c) {
                i(c), s.unsubscribe()
              }
            },
            error: i,
            complete: o
          });
          this.subscribe(s)
        })
      }
      _subscribe(n) {
        var r;
        return (r = this.source) === null || r === void 0 ? void 0 : r.subscribe(n)
      } [kn]() {
        return this
      }
      pipe(...n) {
        return ja(n)(this)
      }
      toPromise(n) {
        return n = kf(n), new n((r, o) => {
          let i;
          this.subscribe(s => i = s, s => o(s), () => r(i))
        })
      }
    }
    return e.create = t => new e(t), e
  })()
});

function Va(e) {
  return b(e?.lift)
}

function _(e) {
  return t => {
    if (Va(t)) return t.lift(function(n) {
      try {
        return e(n, this)
      } catch (r) {
        this.error(r)
      }
    });
    throw new TypeError("Unable to lift unknown Observable type")
  }
}
var j = h(() => {
  K()
});

function S(e, t, n, r, o) {
  return new Ha(e, t, n, r, o)
}
var Ha, $ = h(() => {
  Ar();
  Ha = class extends Qt {
    constructor(t, n, r, o, i, s) {
      super(t), this.onFinalize = i, this.shouldUnsubscribe = s, this._next = n ? function(a) {
        try {
          n(a)
        } catch (c) {
          t.error(c)
        }
      } : super._next, this._error = o ? function(a) {
        try {
          o(a)
        } catch (c) {
          t.error(c)
        } finally {
          this.unsubscribe()
        }
      } : super._error, this._complete = r ? function() {
        try {
          r()
        } catch (a) {
          t.error(a)
        } finally {
          this.unsubscribe()
        }
      } : super._complete
    }
    unsubscribe() {
      var t;
      if (!this.shouldUnsubscribe || this.shouldUnsubscribe()) {
        let {
          closed: n
        } = this;
        super.unsubscribe(), !n && ((t = this.onFinalize) === null || t === void 0 || t.call(this))
      }
    }
  }
});

function Ua() {
  return _((e, t) => {
    let n = null;
    e._refCount++;
    let r = S(t, void 0, void 0, void 0, () => {
      if (!e || e._refCount <= 0 || 0 < --e._refCount) {
        n = null;
        return
      }
      let o = e._connection,
        i = n;
      n = null, o && (!i || o === i) && o.unsubscribe(), t.unsubscribe()
    });
    e.subscribe(r), r.closed || (n = e.connect())
  })
}
var $a = h(() => {
  j();
  $()
});
var za, Pf = h(() => {
  ie();
  Tt();
  $a();
  $();
  j();
  za = class extends R {
    constructor(t, n) {
      super(), this.source = t, this.subjectFactory = n, this._subject = null, this._refCount = 0, this._connection = null, Va(t) && (this.lift = t.lift)
    }
    _subscribe(t) {
      return this.getSubject().subscribe(t)
    }
    getSubject() {
      let t = this._subject;
      return (!t || t.isStopped) && (this._subject = this.subjectFactory()), this._subject
    }
    _teardown() {
      this._refCount = 0;
      let {
        _connection: t
      } = this;
      this._subject = this._connection = null, t?.unsubscribe()
    }
    connect() {
      let t = this._connection;
      if (!t) {
        t = this._connection = new W;
        let n = this.getSubject();
        t.add(this.source.subscribe(S(n, void 0, () => {
          this._teardown(), n.complete()
        }, r => {
          this._teardown(), n.error(r)
        }, () => this._teardown()))), t.closed && (this._connection = null, t = W.EMPTY)
      }
      return t
    }
    refCount() {
      return Ua()(this)
    }
  }
});
var Pn, Lf = h(() => {
  Tt();
  Pn = {
    schedule(e) {
      let t = requestAnimationFrame,
        n = cancelAnimationFrame,
        {
          delegate: r
        } = Pn;
      r && (t = r.requestAnimationFrame, n = r.cancelAnimationFrame);
      let o = t(i => {
        n = void 0, e(i)
      });
      return new W(() => n?.(o))
    },
    requestAnimationFrame(...e) {
      let {
        delegate: t
      } = Pn;
      return (t?.requestAnimationFrame || requestAnimationFrame)(...e)
    },
    cancelAnimationFrame(...e) {
      let {
        delegate: t
      } = Pn;
      return (t?.cancelAnimationFrame || cancelAnimationFrame)(...e)
    },
    delegate: void 0
  }
});
var jf, Bf = h(() => {
  Ko();
  jf = Rn(e => function() {
    e(this), this.name = "ObjectUnsubscribedError", this.message = "object unsubscribed"
  })
});
var ge, si, xr = h(() => {
  ie();
  Tt();
  Bf();
  Xo();
  ri();
  ge = (() => {
    class e extends R {
      constructor() {
        super(), this.closed = !1, this.currentObservers = null, this.observers = [], this.isStopped = !1, this.hasError = !1, this.thrownError = null
      }
      lift(n) {
        let r = new si(this, this);
        return r.operator = n, r
      }
      _throwIfClosed() {
        if (this.closed) throw new jf
      }
      next(n) {
        Fn(() => {
          if (this._throwIfClosed(), !this.isStopped) {
            this.currentObservers || (this.currentObservers = Array.from(this.observers));
            for (let r of this.currentObservers) r.next(n)
          }
        })
      }
      error(n) {
        Fn(() => {
          if (this._throwIfClosed(), !this.isStopped) {
            this.hasError = this.isStopped = !0, this.thrownError = n;
            let {
              observers: r
            } = this;
            for (; r.length;) r.shift().error(n)
          }
        })
      }
      complete() {
        Fn(() => {
          if (this._throwIfClosed(), !this.isStopped) {
            this.isStopped = !0;
            let {
              observers: n
            } = this;
            for (; n.length;) n.shift().complete()
          }
        })
      }
      unsubscribe() {
        this.isStopped = this.closed = !0, this.observers = this.currentObservers = null
      }
      get observed() {
        var n;
        return ((n = this.observers) === null || n === void 0 ? void 0 : n.length) > 0
      }
      _trySubscribe(n) {
        return this._throwIfClosed(), super._trySubscribe(n)
      }
      _subscribe(n) {
        return this._throwIfClosed(), this._checkFinalizedStatuses(n), this._innerSubscribe(n)
      }
      _innerSubscribe(n) {
        let {
          hasError: r,
          isStopped: o,
          observers: i
        } = this;
        return r || o ? xa : (this.currentObservers = null, i.push(n), new W(() => {
          this.currentObservers = null, qt(i, n)
        }))
      }
      _checkFinalizedStatuses(n) {
        let {
          hasError: r,
          thrownError: o,
          isStopped: i
        } = this;
        r ? n.error(o) : i && n.complete()
      }
      asObservable() {
        let n = new R;
        return n.source = this, n
      }
    }
    return e.create = (t, n) => new si(t, n), e
  })(), si = class extends ge {
    constructor(t, n) {
      super(), this.destination = t, this.source = n
    }
    next(t) {
      var n, r;
      (r = (n = this.destination) === null || n === void 0 ? void 0 : n.next) === null || r === void 0 || r.call(n, t)
    }
    error(t) {
      var n, r;
      (r = (n = this.destination) === null || n === void 0 ? void 0 : n.error) === null || r === void 0 || r.call(n, t)
    }
    complete() {
      var t, n;
      (n = (t = this.destination) === null || t === void 0 ? void 0 : t.complete) === null || n === void 0 || n.call(t)
    }
    _subscribe(t) {
      var n, r;
      return (r = (n = this.source) === null || n === void 0 ? void 0 : n.subscribe(t)) !== null && r !== void 0 ? r : xa
    }
  }
});
var Rr, Vf = h(() => {
  xr();
  Rr = class extends ge {
    constructor(t) {
      super(), this._value = t
    }
    get value() {
      return this.getValue()
    }
    _subscribe(t) {
      let n = super._subscribe(t);
      return !n.closed && t.next(this._value), n
    }
    getValue() {
      let {
        hasError: t,
        thrownError: n,
        _value: r
      } = this;
      if (t) throw n;
      return this._throwIfClosed(), r
    }
    next(t) {
      super.next(this._value = t)
    }
  }
});
var Or, Ga = h(() => {
  Or = {
    now() {
      return (Or.delegate || Date).now()
    },
    delegate: void 0
  }
});
var Fr, Wa = h(() => {
  xr();
  Ga();
  Fr = class extends ge {
    constructor(t = 1 / 0, n = 1 / 0, r = Or) {
      super(), this._bufferSize = t, this._windowTime = n, this._timestampProvider = r, this._buffer = [], this._infiniteTimeWindow = !0, this._infiniteTimeWindow = n === 1 / 0, this._bufferSize = Math.max(1, t), this._windowTime = Math.max(1, n)
    }
    next(t) {
      let {
        isStopped: n,
        _buffer: r,
        _infiniteTimeWindow: o,
        _timestampProvider: i,
        _windowTime: s
      } = this;
      n || (r.push(t), !o && r.push(i.now() + s)), this._trimBuffer(), super.next(t)
    }
    _subscribe(t) {
      this._throwIfClosed(), this._trimBuffer();
      let n = this._innerSubscribe(t),
        {
          _infiniteTimeWindow: r,
          _buffer: o
        } = this,
        i = o.slice();
      for (let s = 0; s < i.length && !t.closed; s += r ? 1 : 2) t.next(i[s]);
      return this._checkFinalizedStatuses(t), n
    }
    _trimBuffer() {
      let {
        _bufferSize: t,
        _timestampProvider: n,
        _buffer: r,
        _infiniteTimeWindow: o
      } = this, i = (o ? 1 : 2) * t;
      if (t < 1 / 0 && i < r.length && r.splice(0, r.length - i), !o) {
        let s = n.now(),
          a = 0;
        for (let c = 1; c < r.length && r[c] <= s; c += 2) a = c;
        a && r.splice(0, a + 1)
      }
    }
  }
});
var ai, Hf = h(() => {
  Tt();
  ai = class extends W {
    constructor(t, n) {
      super()
    }
    schedule(t, n = 0) {
      return this
    }
  }
});
var kr, Uf = h(() => {
  kr = {
    setInterval(e, t, ...n) {
      let {
        delegate: r
      } = kr;
      return r?.setInterval ? r.setInterval(e, t, ...n) : setInterval(e, t, ...n)
    },
    clearInterval(e) {
      let {
        delegate: t
      } = kr;
      return (t?.clearInterval || clearInterval)(e)
    },
    delegate: void 0
  }
});
var Ln, qa = h(() => {
  Hf();
  Uf();
  Xo();
  Ln = class extends ai {
    constructor(t, n) {
      super(t, n), this.scheduler = t, this.work = n, this.pending = !1
    }
    schedule(t, n = 0) {
      var r;
      if (this.closed) return this;
      this.state = t;
      let o = this.id,
        i = this.scheduler;
      return o != null && (this.id = this.recycleAsyncId(i, o, n)), this.pending = !0, this.delay = n, this.id = (r = this.id) !== null && r !== void 0 ? r : this.requestAsyncId(i, this.id, n), this
    }
    requestAsyncId(t, n, r = 0) {
      return kr.setInterval(t.flush.bind(t, this), r)
    }
    recycleAsyncId(t, n, r = 0) {
      if (r != null && this.delay === r && this.pending === !1) return n;
      n != null && kr.clearInterval(n)
    }
    execute(t, n) {
      if (this.closed) return new Error("executing a cancelled action");
      this.pending = !1;
      let r = this._execute(t, n);
      if (r) return r;
      this.pending === !1 && this.id != null && (this.id = this.recycleAsyncId(this.scheduler, this.id, null))
    }
    _execute(t, n) {
      let r = !1,
        o;
      try {
        this.work(t)
      } catch (i) {
        r = !0, o = i || new Error("Scheduled action threw falsy error")
      }
      if (r) return this.unsubscribe(), o
    }
    unsubscribe() {
      if (!this.closed) {
        let {
          id: t,
          scheduler: n
        } = this, {
          actions: r
        } = n;
        this.work = this.state = this.scheduler = null, this.pending = !1, qt(r, this), t != null && (this.id = this.recycleAsyncId(n, t, null)), this.delay = null, super.unsubscribe()
      }
    }
  }
});
var jn, $f = h(() => {
  Ga();
  jn = class e {
    constructor(t, n = e.now) {
      this.schedulerActionCtor = t, this.now = n
    }
    schedule(t, n = 0, r) {
      return new this.schedulerActionCtor(this, t).schedule(r, n)
    }
  };
  jn.now = Or.now
});
var Bn, Za = h(() => {
  $f();
  Bn = class extends jn {
    constructor(t, n = jn.now) {
      super(t, n), this.actions = [], this._active = !1
    }
    flush(t) {
      let {
        actions: n
      } = this;
      if (this._active) {
        n.push(t);
        return
      }
      let r;
      this._active = !0;
      do
        if (r = t.execute(t.state, t.delay)) break; while (t = n.shift());
      if (this._active = !1, r) {
        for (; t = n.shift();) t.unsubscribe();
        throw r
      }
    }
  }
});
var ut, zf, Vn = h(() => {
  qa();
  Za();
  ut = new Bn(Ln), zf = ut
});
var ci, Gf = h(() => {
  qa();
  Lf();
  ci = class extends Ln {
    constructor(t, n) {
      super(t, n), this.scheduler = t, this.work = n
    }
    requestAsyncId(t, n, r = 0) {
      return r !== null && r > 0 ? super.requestAsyncId(t, n, r) : (t.actions.push(this), t._scheduled || (t._scheduled = Pn.requestAnimationFrame(() => t.flush(void 0))))
    }
    recycleAsyncId(t, n, r = 0) {
      var o;
      if (r != null ? r > 0 : this.delay > 0) return super.recycleAsyncId(t, n, r);
      let {
        actions: i
      } = t;
      n != null && n === t._scheduled && ((o = i[i.length - 1]) === null || o === void 0 ? void 0 : o.id) !== n && (Pn.cancelAnimationFrame(n), t._scheduled = void 0)
    }
  }
});
var ui, Wf = h(() => {
  Za();
  ui = class extends Bn {
    flush(t) {
      this._active = !0;
      let n;
      t ? n = t.id : (n = this._scheduled, this._scheduled = void 0);
      let {
        actions: r
      } = this, o;
      t = t || r.shift();
      do
        if (o = t.execute(t.state, t.delay)) break; while ((t = r[0]) && t.id === n && r.shift());
      if (this._active = !1, o) {
        for (;
          (t = r[0]) && t.id === n && r.shift();) t.unsubscribe();
        throw o
      }
    }
  }
});
var MD, qf = h(() => {
  Gf();
  Wf();
  MD = new ui(ci)
});
var Kt, Pr = h(() => {
  ie();
  Kt = new R(e => e.complete())
});

function li(e) {
  return e && b(e.schedule)
}
var Ya = h(() => {
  K()
});

function Qa(e) {
  return e[e.length - 1]
}

function di(e) {
  return b(Qa(e)) ? e.pop() : void 0
}

function We(e) {
  return li(Qa(e)) ? e.pop() : void 0
}

function Zf(e, t) {
  return typeof Qa(e) == "number" ? e.pop() : t
}
var Jt = h(() => {
  K();
  Ya()
});

function Qf(e, t, n, r) {
  function o(i) {
    return i instanceof n ? i : new n(function(s) {
      s(i)
    })
  }
  return new(n || (n = Promise))(function(i, s) {
    function a(l) {
      try {
        u(r.next(l))
      } catch (d) {
        s(d)
      }
    }

    function c(l) {
      try {
        u(r.throw(l))
      } catch (d) {
        s(d)
      }
    }

    function u(l) {
      l.done ? i(l.value) : o(l.value).then(a, c)
    }
    u((r = r.apply(e, t || [])).next())
  })
}

function Yf(e) {
  var t = typeof Symbol == "function" && Symbol.iterator,
    n = t && e[t],
    r = 0;
  if (n) return n.call(e);
  if (e && typeof e.length == "number") return {
    next: function() {
      return e && r >= e.length && (e = void 0), {
        value: e && e[r++],
        done: !e
      }
    }
  };
  throw new TypeError(t ? "Object is not iterable." : "Symbol.iterator is not defined.")
}

function Xt(e) {
  return this instanceof Xt ? (this.v = e, this) : new Xt(e)
}

function Kf(e, t, n) {
  if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
  var r = n.apply(e, t || []),
    o, i = [];
  return o = Object.create((typeof AsyncIterator == "function" ? AsyncIterator : Object).prototype), a("next"), a("throw"), a("return", s), o[Symbol.asyncIterator] = function() {
    return this
  }, o;

  function s(f) {
    return function(g) {
      return Promise.resolve(g).then(f, d)
    }
  }

  function a(f, g) {
    r[f] && (o[f] = function(I) {
      return new Promise(function(D, m) {
        i.push([f, I, D, m]) > 1 || c(f, I)
      })
    }, g && (o[f] = g(o[f])))
  }

  function c(f, g) {
    try {
      u(r[f](g))
    } catch (I) {
      p(i[0][3], I)
    }
  }

  function u(f) {
    f.value instanceof Xt ? Promise.resolve(f.value.v).then(l, d) : p(i[0][2], f)
  }

  function l(f) {
    c("next", f)
  }

  function d(f) {
    c("throw", f)
  }

  function p(f, g) {
    f(g), i.shift(), i.length && c(i[0][0], i[0][1])
  }
}

function Jf(e) {
  if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
  var t = e[Symbol.asyncIterator],
    n;
  return t ? t.call(e) : (e = typeof Yf == "function" ? Yf(e) : e[Symbol.iterator](), n = {}, r("next"), r("throw"), r("return"), n[Symbol.asyncIterator] = function() {
    return this
  }, n);

  function r(i) {
    n[i] = e[i] && function(s) {
      return new Promise(function(a, c) {
        s = e[i](s), o(a, c, s.done, s.value)
      })
    }
  }

  function o(i, s, a, c) {
    Promise.resolve(c).then(function(u) {
      i({
        value: u,
        done: a
      })
    }, s)
  }
}
var Ka = h(() => {});
var Hn, fi = h(() => {
  Hn = e => e && typeof e.length == "number" && typeof e != "function"
});

function pi(e) {
  return b(e?.then)
}
var Ja = h(() => {
  K()
});

function hi(e) {
  return b(e[kn])
}
var Xa = h(() => {
  ii();
  K()
});

function gi(e) {
  return Symbol.asyncIterator && b(e?.[Symbol.asyncIterator])
}
var ec = h(() => {
  K()
});

function mi(e) {
  return new TypeError(`You provided ${e!==null&&typeof e=="object"?"an invalid object":`'${e}'`} where a stream was expected. You can provide an Observable, Promise, ReadableStream, Array, AsyncIterable, or Iterable.`)
}
var tc = h(() => {});

function SD() {
  return typeof Symbol != "function" || !Symbol.iterator ? "@@iterator" : Symbol.iterator
}
var yi, nc = h(() => {
  yi = SD()
});

function vi(e) {
  return b(e?.[yi])
}
var rc = h(() => {
  nc();
  K()
});

function Di(e) {
  return Kf(this, arguments, function*() {
    let n = e.getReader();
    try {
      for (;;) {
        let {
          value: r,
          done: o
        } = yield Xt(n.read());
        if (o) return yield Xt(void 0);
        yield yield Xt(r)
      }
    } finally {
      n.releaseLock()
    }
  })
}

function Ei(e) {
  return b(e?.getReader)
}
var Ii = h(() => {
  Ka();
  K()
});

function O(e) {
  if (e instanceof R) return e;
  if (e != null) {
    if (hi(e)) return ND(e);
    if (Hn(e)) return AD(e);
    if (pi(e)) return xD(e);
    if (gi(e)) return Xf(e);
    if (vi(e)) return RD(e);
    if (Ei(e)) return OD(e)
  }
  throw mi(e)
}

function ND(e) {
  return new R(t => {
    let n = e[kn]();
    if (b(n.subscribe)) return n.subscribe(t);
    throw new TypeError("Provided object does not correctly implement Symbol.observable")
  })
}

function AD(e) {
  return new R(t => {
    for (let n = 0; n < e.length && !t.closed; n++) t.next(e[n]);
    t.complete()
  })
}

function xD(e) {
  return new R(t => {
    e.then(n => {
      t.closed || (t.next(n), t.complete())
    }, n => t.error(n)).then(null, ti)
  })
}

function RD(e) {
  return new R(t => {
    for (let n of e)
      if (t.next(n), t.closed) return;
    t.complete()
  })
}

function Xf(e) {
  return new R(t => {
    FD(e, t).catch(n => t.error(n))
  })
}

function OD(e) {
  return Xf(Di(e))
}

function FD(e, t) {
  var n, r, o, i;
  return Qf(this, void 0, void 0, function*() {
    try {
      for (n = Jf(e); r = yield n.next(), !r.done;) {
        let s = r.value;
        if (t.next(s), t.closed) return
      }
    } catch (s) {
      o = {
        error: s
      }
    } finally {
      try {
        r && !r.done && (i = n.return) && (yield i.call(n))
      } finally {
        if (o) throw o.error
      }
    }
    t.complete()
  })
}
var se = h(() => {
  Ka();
  fi();
  Ja();
  ie();
  Xa();
  ec();
  tc();
  rc();
  Ii();
  K();
  Oa();
  ii()
});

function me(e, t, n, r = 0, o = !1) {
  let i = t.schedule(function() {
    n(), o ? e.add(this.schedule(null, r)) : this.unsubscribe()
  }, r);
  if (e.add(i), !o) return i
}
var Un = h(() => {});

function wi(e, t = 0) {
  return _((n, r) => {
    n.subscribe(S(r, o => me(r, e, () => r.next(o), t), () => me(r, e, () => r.complete(), t), o => me(r, e, () => r.error(o), t)))
  })
}
var oc = h(() => {
  Un();
  j();
  $()
});

function Ci(e, t = 0) {
  return _((n, r) => {
    r.add(e.schedule(() => n.subscribe(r), t))
  })
}
var ic = h(() => {
  j()
});

function ep(e, t) {
  return O(e).pipe(Ci(t), wi(t))
}
var tp = h(() => {
  se();
  oc();
  ic()
});

function np(e, t) {
  return O(e).pipe(Ci(t), wi(t))
}
var rp = h(() => {
  se();
  oc();
  ic()
});

function op(e, t) {
  return new R(n => {
    let r = 0;
    return t.schedule(function() {
      r === e.length ? n.complete() : (n.next(e[r++]), n.closed || this.schedule())
    })
  })
}
var ip = h(() => {
  ie()
});

function sp(e, t) {
  return new R(n => {
    let r;
    return me(n, t, () => {
      r = e[yi](), me(n, t, () => {
        let o, i;
        try {
          ({
            value: o,
            done: i
          } = r.next())
        } catch (s) {
          n.error(s);
          return
        }
        i ? n.complete() : n.next(o)
      }, 0, !0)
    }), () => b(r?.return) && r.return()
  })
}
var ap = h(() => {
  ie();
  nc();
  K();
  Un()
});

function bi(e, t) {
  if (!e) throw new Error("Iterable cannot be null");
  return new R(n => {
    me(n, t, () => {
      let r = e[Symbol.asyncIterator]();
      me(n, t, () => {
        r.next().then(o => {
          o.done ? n.complete() : n.next(o.value)
        })
      }, 0, !0)
    })
  })
}
var sc = h(() => {
  ie();
  Un()
});

function cp(e, t) {
  return bi(Di(e), t)
}
var up = h(() => {
  sc();
  Ii()
});

function lp(e, t) {
  if (e != null) {
    if (hi(e)) return ep(e, t);
    if (Hn(e)) return op(e, t);
    if (pi(e)) return np(e, t);
    if (gi(e)) return bi(e, t);
    if (vi(e)) return sp(e, t);
    if (Ei(e)) return cp(e, t)
  }
  throw mi(e)
}
var dp = h(() => {
  tp();
  rp();
  ip();
  ap();
  sc();
  Xa();
  Ja();
  fi();
  rc();
  ec();
  tc();
  Ii();
  up()
});

function qe(e, t) {
  return t ? lp(e, t) : O(e)
}
var $n = h(() => {
  dp();
  se()
});

function Ti(...e) {
  let t = We(e);
  return qe(e, t)
}
var fp = h(() => {
  Jt();
  $n()
});

function kD(e, t) {
  let n = b(e) ? e : () => e,
    r = o => o.error(n());
  return new R(t ? o => t.schedule(r, 0, o) : r)
}
var pp = h(() => {
  ie();
  K()
});

function PD(e) {
  return !!e && (e instanceof R || b(e.lift) && b(e.subscribe))
}
var hp = h(() => {
  ie();
  K()
});
var lt, zn = h(() => {
  Ko();
  lt = Rn(e => function() {
    e(this), this.name = "EmptyError", this.message = "no elements in sequence"
  })
});

function LD(e, t) {
  let n = typeof t == "object";
  return new Promise((r, o) => {
    let i = new Oe({
      next: s => {
        r(s), i.unsubscribe()
      },
      error: o,
      complete: () => {
        n ? r(t.defaultValue) : o(new lt)
      }
    });
    e.subscribe(i)
  })
}
var gp = h(() => {
  zn();
  Ar()
});

function mp(e) {
  return e instanceof Date && !isNaN(e)
}
var yp = h(() => {});

function le(e, t) {
  return _((n, r) => {
    let o = 0;
    n.subscribe(S(r, i => {
      r.next(e.call(t, i, o++))
    }))
  })
}
var Gn = h(() => {
  j();
  $()
});

function BD(e, t) {
  return jD(t) ? e(...t) : e(t)
}

function Wn(e) {
  return le(t => BD(e, t))
}
var jD, _i = h(() => {
  Gn();
  ({
    isArray: jD
  } = Array)
});

function Mi(e) {
  if (e.length === 1) {
    let t = e[0];
    if (VD(t)) return {
      args: t,
      keys: null
    };
    if (zD(t)) {
      let n = $D(t);
      return {
        args: n.map(r => t[r]),
        keys: n
      }
    }
  }
  return {
    args: e,
    keys: null
  }
}

function zD(e) {
  return e && typeof e == "object" && HD(e) === UD
}
var VD, HD, UD, $D, ac = h(() => {
  ({
    isArray: VD
  } = Array), {
    getPrototypeOf: HD,
    prototype: UD,
    keys: $D
  } = Object
});

function Si(e, t) {
  return e.reduce((n, r, o) => (n[r] = t[o], n), {})
}
var cc = h(() => {});

function GD(...e) {
  let t = We(e),
    n = di(e),
    {
      args: r,
      keys: o
    } = Mi(e);
  if (r.length === 0) return qe([], t);
  let i = new R(WD(r, t, o ? s => Si(o, s) : ue));
  return n ? i.pipe(Wn(n)) : i
}

function WD(e, t, n = ue) {
  return r => {
    vp(t, () => {
      let {
        length: o
      } = e, i = new Array(o), s = o, a = o;
      for (let c = 0; c < o; c++) vp(t, () => {
        let u = qe(e[c], t),
          l = !1;
        u.subscribe(S(r, d => {
          i[c] = d, l || (l = !0, a--), a || r.next(n(i.slice()))
        }, () => {
          --s || r.complete()
        }))
      }, r)
    }, r)
  }
}

function vp(e, t, n) {
  e ? me(n, e, t) : t()
}
var Dp = h(() => {
  ie();
  ac();
  $n();
  _t();
  _i();
  Jt();
  cc();
  $();
  Un()
});

function Ni(e, t, n, r, o, i, s, a) {
  let c = [],
    u = 0,
    l = 0,
    d = !1,
    p = () => {
      d && !c.length && !u && t.complete()
    },
    f = I => u < r ? g(I) : c.push(I),
    g = I => {
      i && t.next(I), u++;
      let D = !1;
      O(n(I, l++)).subscribe(S(t, m => {
        o?.(m), i ? f(m) : t.next(m)
      }, () => {
        D = !0
      }, void 0, () => {
        if (D) try {
          for (u--; c.length && u < r;) {
            let m = c.shift();
            s ? me(t, s, () => g(m)) : g(m)
          }
          p()
        } catch (m) {
          t.error(m)
        }
      }))
    };
  return e.subscribe(S(t, f, () => {
    d = !0, p()
  })), () => {
    a?.()
  }
}
var uc = h(() => {
  se();
  Un();
  $()
});

function be(e, t, n = 1 / 0) {
  return b(t) ? be((r, o) => le((i, s) => t(r, i, o, s))(O(e(r, o))), n) : (typeof t == "number" && (n = t), _((r, o) => Ni(r, o, e, n)))
}
var en = h(() => {
  Gn();
  se();
  j();
  uc();
  K()
});

function Lr(e = 1 / 0) {
  return be(ue, e)
}
var Ai = h(() => {
  en();
  _t()
});

function Ep() {
  return Lr(1)
}
var Ip = h(() => {
  Ai()
});

function qn(...e) {
  return Ep()(qe(e, We(e)))
}
var xi = h(() => {
  Ip();
  Jt();
  $n()
});

function qD(e) {
  return new R(t => {
    O(e()).subscribe(t)
  })
}
var wp = h(() => {
  ie();
  se()
});

function ZD(...e) {
  let t = di(e),
    {
      args: n,
      keys: r
    } = Mi(e),
    o = new R(i => {
      let {
        length: s
      } = n;
      if (!s) {
        i.complete();
        return
      }
      let a = new Array(s),
        c = s,
        u = s;
      for (let l = 0; l < s; l++) {
        let d = !1;
        O(n[l]).subscribe(S(i, p => {
          d || (d = !0, u--), a[l] = p
        }, () => c--, void 0, () => {
          (!c || !d) && (u || i.next(r ? Si(r, a) : a), i.complete())
        }))
      }
    });
  return t ? o.pipe(Wn(t)) : o
}
var Cp = h(() => {
  ie();
  ac();
  se();
  Jt();
  $();
  _i();
  cc()
});

function lc(e, t, n, r) {
  if (b(n) && (r = n, n = void 0), r) return lc(e, t, n).pipe(Wn(r));
  let [o, i] = eE(e) ? QD.map(s => a => e[s](t, a, n)) : JD(e) ? YD.map(bp(e, t)) : XD(e) ? KD.map(bp(e, t)) : [];
  if (!o && Hn(e)) return be(s => lc(s, t, n))(O(e));
  if (!o) throw new TypeError("Invalid event target");
  return new R(s => {
    let a = (...c) => s.next(1 < c.length ? c : c[0]);
    return o(a), () => i(a)
  })
}

function bp(e, t) {
  return n => r => e[n](t, r)
}

function JD(e) {
  return b(e.addListener) && b(e.removeListener)
}

function XD(e) {
  return b(e.on) && b(e.off)
}

function eE(e) {
  return b(e.addEventListener) && b(e.removeEventListener)
}
var YD, QD, KD, Tp = h(() => {
  se();
  ie();
  en();
  fi();
  K();
  _i();
  YD = ["addListener", "removeListener"], QD = ["addEventListener", "removeEventListener"], KD = ["on", "off"]
});

function tn(e = 0, t, n = zf) {
  let r = -1;
  return t != null && (li(t) ? n = t : r = t), new R(o => {
    let i = mp(e) ? +e - n.now() : e;
    i < 0 && (i = 0);
    let s = 0;
    return n.schedule(function() {
      o.closed || (o.next(s++), 0 <= r ? this.schedule(void 0, r) : o.complete())
    }, i)
  })
}
var jr = h(() => {
  ie();
  Vn();
  Ya();
  yp()
});

function tE(e = 0, t = ut) {
  return e < 0 && (e = 0), tn(e, e, t)
}
var _p = h(() => {
  Vn();
  jr()
});

function nE(...e) {
  let t = We(e),
    n = Zf(e, 1 / 0),
    r = e;
  return r.length ? r.length === 1 ? O(r[0]) : Lr(n)(qe(r, t)) : Kt
}
var Mp = h(() => {
  Ai();
  se();
  Pr();
  Jt();
  $n()
});

function Ze(e, t) {
  return _((n, r) => {
    let o = 0;
    n.subscribe(S(r, i => e.call(t, i, o++) && r.next(i)))
  })
}
var Zn = h(() => {
  j();
  $()
});
var Sp = h(() => {});

function Np(e) {
  return _((t, n) => {
    let r = !1,
      o = null,
      i = null,
      s = !1,
      a = () => {
        if (i?.unsubscribe(), i = null, r) {
          r = !1;
          let u = o;
          o = null, n.next(u)
        }
        s && n.complete()
      },
      c = () => {
        i = null, s && n.complete()
      };
    t.subscribe(S(n, u => {
      r = !0, o = u, i || O(e(u)).subscribe(i = S(n, a, c))
    }, () => {
      s = !0, (!r || !i || i.closed) && n.complete()
    }))
  })
}
var Ap = h(() => {
  j();
  se();
  $()
});

function rE(e, t = ut) {
  return Np(() => tn(e, t))
}
var xp = h(() => {
  Vn();
  Ap();
  jr()
});

function dc(e) {
  return _((t, n) => {
    let r = null,
      o = !1,
      i;
    r = t.subscribe(S(n, void 0, void 0, s => {
      i = O(e(s, dc(e)(t))), r ? (r.unsubscribe(), r = null, i.subscribe(n)) : o = !0
    })), o && (r.unsubscribe(), r = null, i.subscribe(n))
  })
}
var fc = h(() => {
  se();
  $();
  j()
});

function Rp(e, t, n, r, o) {
  return (i, s) => {
    let a = n,
      c = t,
      u = 0;
    i.subscribe(S(s, l => {
      let d = u++;
      c = a ? e(c, l, d) : (a = !0, l), r && s.next(c)
    }, o && (() => {
      a && s.next(c), s.complete()
    })))
  }
}
var Op = h(() => {
  $()
});

function pc(e, t) {
  return b(t) ? be(e, t, 1) : be(e, 1)
}
var Fp = h(() => {
  en();
  K()
});

function kp(e, t = ut) {
  return _((n, r) => {
    let o = null,
      i = null,
      s = null,
      a = () => {
        if (o) {
          o.unsubscribe(), o = null;
          let u = i;
          i = null, r.next(u)
        }
      };

    function c() {
      let u = s + e,
        l = t.now();
      if (l < u) {
        o = this.schedule(void 0, u - l), r.add(o);
        return
      }
      a()
    }
    n.subscribe(S(r, u => {
      i = u, s = t.now(), o || (o = t.schedule(c, e), r.add(o))
    }, () => {
      a(), r.complete()
    }, void 0, () => {
      i = o = null
    }))
  })
}
var hc = h(() => {
  Vn();
  j();
  $()
});

function Br(e) {
  return _((t, n) => {
    let r = !1;
    t.subscribe(S(n, o => {
      r = !0, n.next(o)
    }, () => {
      r || n.next(e), n.complete()
    }))
  })
}
var Ri = h(() => {
  j();
  $()
});

function nn(e) {
  return e <= 0 ? () => Kt : _((t, n) => {
    let r = 0;
    t.subscribe(S(n, o => {
      ++r <= e && (n.next(o), e <= r && n.complete())
    }))
  })
}
var Vr = h(() => {
  Pr();
  j();
  $()
});

function Pp() {
  return _((e, t) => {
    e.subscribe(S(t, Zt))
  })
}
var Lp = h(() => {
  j();
  $();
  ni()
});

function gc(e) {
  return le(() => e)
}
var mc = h(() => {
  Gn()
});

function yc(e, t) {
  return t ? n => qn(t.pipe(nn(1), Pp()), n.pipe(yc(e))) : be((n, r) => O(e(n, r)).pipe(nn(1), gc(n)))
}
var jp = h(() => {
  xi();
  Vr();
  Lp();
  mc();
  en();
  se()
});

function oE(e, t = ut) {
  let n = tn(e, t);
  return yc(() => n)
}
var Bp = h(() => {
  Vn();
  jp();
  jr()
});

function Vp(e, t = ue) {
  return e = e ?? iE, _((n, r) => {
    let o, i = !0;
    n.subscribe(S(r, s => {
      let a = t(s);
      (i || !e(o, a)) && (i = !1, o = a, r.next(s))
    }))
  })
}

function iE(e, t) {
  return e === t
}
var vc = h(() => {
  _t();
  j();
  $()
});

function Oi(e = sE) {
  return _((t, n) => {
    let r = !1;
    t.subscribe(S(n, o => {
      r = !0, n.next(o)
    }, () => r ? n.complete() : n.error(e())))
  })
}

function sE() {
  return new lt
}
var Dc = h(() => {
  zn();
  j();
  $()
});

function aE(e, t = 1 / 0, n) {
  return t = (t || 0) < 1 ? 1 / 0 : t, _((r, o) => Ni(r, o, e, t, void 0, !0, n))
}
var Hp = h(() => {
  j();
  uc()
});

function Hr(e) {
  return _((t, n) => {
    try {
      t.subscribe(n)
    } finally {
      n.add(e)
    }
  })
}
var Ec = h(() => {
  j()
});

function cE(e, t) {
  let n = arguments.length >= 2;
  return r => r.pipe(e ? Ze((o, i) => e(o, i, r)) : ue, nn(1), n ? Br(t) : Oi(() => new lt))
}
var Up = h(() => {
  zn();
  Zn();
  Vr();
  Ri();
  Dc();
  _t()
});

function Ic(e) {
  return e <= 0 ? () => Kt : _((t, n) => {
    let r = [];
    t.subscribe(S(n, o => {
      r.push(o), e < r.length && r.shift()
    }, () => {
      for (let o of r) n.next(o);
      n.complete()
    }, void 0, () => {
      r = null
    }))
  })
}
var wc = h(() => {
  Pr();
  j();
  $()
});

function uE(e, t) {
  let n = arguments.length >= 2;
  return r => r.pipe(e ? Ze((o, i) => e(o, i, r)) : ue, Ic(1), n ? Br(t) : Oi(() => new lt))
}
var $p = h(() => {
  zn();
  Zn();
  wc();
  Dc();
  Ri();
  _t()
});

function lE() {
  return _((e, t) => {
    let n, r = !1;
    e.subscribe(S(t, o => {
      let i = n;
      n = o, r && t.next([i, o]), r = !0
    }))
  })
}
var zp = h(() => {
  j();
  $()
});

function dE(e, t) {
  return _(Rp(e, t, arguments.length >= 2, !0))
}
var Gp = h(() => {
  j();
  Op()
});

function bc(e = {}) {
  let {
    connector: t = () => new ge,
    resetOnError: n = !0,
    resetOnComplete: r = !0,
    resetOnRefCountZero: o = !0
  } = e;
  return i => {
    let s, a, c, u = 0,
      l = !1,
      d = !1,
      p = () => {
        a?.unsubscribe(), a = void 0
      },
      f = () => {
        p(), s = c = void 0, l = d = !1
      },
      g = () => {
        let I = s;
        f(), I?.unsubscribe()
      };
    return _((I, D) => {
      u++, !d && !l && p();
      let m = c = c ?? t();
      D.add(() => {
        u--, u === 0 && !d && !l && (a = Cc(g, o))
      }), m.subscribe(D), !s && u > 0 && (s = new Oe({
        next: F => m.next(F),
        error: F => {
          d = !0, p(), a = Cc(f, n, F), m.error(F)
        },
        complete: () => {
          l = !0, p(), a = Cc(f, r), m.complete()
        }
      }), O(I).subscribe(s))
    })(i)
  }
}

function Cc(e, t, ...n) {
  if (t === !0) {
    e();
    return
  }
  if (t === !1) return;
  let r = new Oe({
    next: () => {
      r.unsubscribe(), e()
    }
  });
  return O(t(...n)).subscribe(r)
}
var Tc = h(() => {
  se();
  xr();
  Ar();
  j()
});

function fE(e, t, n) {
  let r, o = !1;
  return e && typeof e == "object" ? {
    bufferSize: r = 1 / 0,
    windowTime: t = 1 / 0,
    refCount: o = !1,
    scheduler: n
  } = e : r = e ?? 1 / 0, bc({
    connector: () => new Fr(r, t, n),
    resetOnError: !0,
    resetOnComplete: !1,
    resetOnRefCountZero: o
  })
}
var Wp = h(() => {
  Wa();
  Tc()
});

function pE(e) {
  return Ze((t, n) => e <= n)
}
var qp = h(() => {
  Zn()
});

function Zp(...e) {
  let t = We(e);
  return _((n, r) => {
    (t ? qn(e, n, t) : qn(e, n)).subscribe(r)
  })
}
var _c = h(() => {
  xi();
  Jt();
  j()
});

function Fi(e, t) {
  return _((n, r) => {
    let o = null,
      i = 0,
      s = !1,
      a = () => s && !o && r.complete();
    n.subscribe(S(r, c => {
      o?.unsubscribe();
      let u = 0,
        l = i++;
      O(e(c, l)).subscribe(o = S(r, d => r.next(t ? t(c, d, l, u++) : d), () => {
        o = null, a()
      }))
    }, () => {
      s = !0, a()
    }))
  })
}
var Mc = h(() => {
  se();
  j();
  $()
});

function Yp(e) {
  return _((t, n) => {
    O(e).subscribe(S(n, () => n.complete(), Zt)), !n.closed && t.subscribe(n)
  })
}
var Sc = h(() => {
  j();
  $();
  se();
  ni()
});

function Qp(e, t = !1) {
  return _((n, r) => {
    let o = 0;
    n.subscribe(S(r, i => {
      let s = e(i, o++);
      (s || t) && r.next(i), !s && r.complete()
    }))
  })
}
var Nc = h(() => {
  j();
  $()
});

function Kp(e, t, n) {
  let r = b(e) || t || n ? {
    next: e,
    error: t,
    complete: n
  } : e;
  return r ? _((o, i) => {
    var s;
    (s = r.subscribe) === null || s === void 0 || s.call(r);
    let a = !0;
    o.subscribe(S(i, c => {
      var u;
      (u = r.next) === null || u === void 0 || u.call(r, c), i.next(c)
    }, () => {
      var c;
      a = !1, (c = r.complete) === null || c === void 0 || c.call(r), i.complete()
    }, c => {
      var u;
      a = !1, (u = r.error) === null || u === void 0 || u.call(r, c), i.error(c)
    }, () => {
      var c, u;
      a && ((c = r.unsubscribe) === null || c === void 0 || c.call(r)), (u = r.finalize) === null || u === void 0 || u.call(r)
    }))
  }) : ue
}
var Ac = h(() => {
  K();
  j();
  $();
  _t()
});
var Ur = h(() => {
  ie();
  Pf();
  xr();
  Vf();
  Wa();
  qf();
  Tt();
  Ba();
  hp();
  gp();
  zn();
  Dp();
  xi();
  wp();
  Cp();
  $n();
  Tp();
  _p();
  Mp();
  fp();
  pp();
  jr();
  Pr();
  Sp();
  fc();
  hc();
  Bp();
  vc();
  Hp();
  Zn();
  Ec();
  Gn();
  en();
  _c();
  Mc();
  Vr();
  Sc();
  Nc();
  Ac()
});

function Jp(e) {
  let t = M(null);
  try {
    return e()
  } finally {
    M(t)
  }
}

function eh(e) {
  if (e.dirty = !1, e.version > 0 && !Gt(e)) return;
  e.version++;
  let t = Ct(e);
  try {
    e.cleanup(), e.fn()
  } finally {
    zt(e, t)
  }
}
var Xp, th = h(() => {
  Wt();
  Xp = G(V({}, Ut), {
    consumerIsAlwaysLive: !0,
    consumerAllowSignalWrites: !0,
    dirty: !0,
    kind: "effect"
  })
});
var xc = h(() => {
  Wt();
});
var nh = h(() => {
  Ca();
});

function hE(e) {
  return `NG0${Math.abs(e)}`
}

function Ye(e, t) {
  return `${hE(e)}${t?": "+t:""}`
}

function k(e) {
  for (let t in e)
    if (e[t] === k) return t;
  throw Error("")
}

function ih(e, t) {
  for (let n in t) t.hasOwnProperty(n) && !e.hasOwnProperty(n) && (e[n] = t[n])
}

function ft(e) {
  if (typeof e == "string") return e;
  if (Array.isArray(e)) return `[${e.map(ft).join(", ")}]`;
  if (e == null) return "" + e;
  let t = e.overriddenName || e.name;
  if (t) return `${t}`;
  let n = e.toString();
  if (n == null) return "" + n;
  let r = n.indexOf(`
`);
  return r >= 0 ? n.slice(0, r) : n
}

function Bi(e, t) {
  return e ? t ? `${e} ${t}` : e : t || ""
}

function Vi(e) {
  return e.__forward_ref__ = Vi, e.toString = function() {
    return ft(this())
  }, e
}

function ee(e) {
  return $c(e) ? e() : e
}

function $c(e) {
  return typeof e == "function" && e.hasOwnProperty(gE) && e.__forward_ref__ === Vi
}

function N(e) {
  return {
    token: e.token,
    providedIn: e.providedIn || null,
    factory: e.factory,
    value: void 0
  }
}

function pt(e) {
  return {
    providers: e.providers || [],
    imports: e.imports || []
  }
}

function qr(e) {
  return yE(e, Hi)
}

function mE(e) {
  return qr(e) !== null
}

function yE(e, t) {
  return e.hasOwnProperty(t) && e[t] || null
}

function vE(e) {
  let t = e?.[Hi] ?? null;
  return t || null
}

function Oc(e) {
  return e && e.hasOwnProperty(Pi) ? e[Pi] : null
}

function zc(e) {
  return e && !!e.\u0275providers
}

function Ee(e) {
  return typeof e == "string" ? e : e == null ? "" : String(e)
}

function sh(e) {
  return typeof e == "function" ? e.name || e.toString() : typeof e == "object" && e != null && typeof e.type == "function" ? e.type.name || e.type.toString() : Ee(e)
}

function Yc(e, t) {
  return ch("", -200, t)
}

function Ui(e, t) {
  throw new v(-201, !1)
}

function ch(e, t, n) {
  let r = new v(t, e);
  return r[ah] = t, r[DE] = e, n && (r[EE] = n), r
}

function IE(e) {
  return e[ah]
}

function uh() {
  return Fc
}

function de(e) {
  let t = Fc;
  return Fc = e, t
}

function Qc(e, t, n) {
  let r = qr(e);
  if (r && r.providedIn == "root") return r.value === void 0 ? r.value = r.factory() : r.value;
  if (n & 8) return null;
  if (t !== void 0) return t;
  Ui(e, "Injector")
}

function CE(e, t = 0) {
  let n = Uo();
  if (n === void 0) throw new v(-203, !1);
  if (n === null) return Qc(e, void 0, t);
  {
    let r = bE(t),
      o = n.retrieve(e, r);
    if (Nn(o)) {
      if (r.optional) return null;
      throw o
    }
    return o
  }
}

function C(e, t = 0) {
  return (uh() || CE)(ee(e), t)
}

function y(e, t) {
  return C(e, on(t))
}

function on(e) {
  return typeof e > "u" || typeof e == "number" ? e : 0 | (e.optional && 8) | (e.host && 1) | (e.self && 2) | (e.skipSelf && 4)
}

function bE(e) {
  return {
    optional: !!(e & 8),
    host: !!(e & 1),
    self: !!(e & 2),
    skipSelf: !!(e & 4)
  }
}

function Lc(e) {
  let t = [];
  for (let n = 0; n < e.length; n++) {
    let r = ee(e[n]);
    if (Array.isArray(r)) {
      if (r.length === 0) throw new v(900, !1);
      let o, i = 0;
      for (let s = 0; s < r.length; s++) {
        let a = r[s],
          c = TE(a);
        typeof c == "number" ? c === -1 ? o = a.token : i |= c : o = a
      }
      t.push(C(o, i))
    } else t.push(C(r))
  }
  return t
}

function Kc(e, t) {
  return e[kc] = t, e.prototype[kc] = t, e
}

function TE(e) {
  return e[kc]
}

function Mt(e, t) {
  let n = e.hasOwnProperty(zr);
  return n ? e[zr] : null
}

function lh(e, t, n) {
  if (e.length !== t.length) return !1;
  for (let r = 0; r < e.length; r++) {
    let o = e[r],
      i = t[r];
    if (n && (o = n(o), i = n(i)), i !== o) return !1
  }
  return !0
}

function dh(e) {
  return e.flat(Number.POSITIVE_INFINITY)
}

function $i(e, t) {
  e.forEach(n => Array.isArray(n) ? $i(n, t) : t(n))
}

function Jc(e, t, n) {
  t >= e.length ? e.push(n) : e.splice(t, 0, n)
}

function Zr(e, t) {
  return t >= e.length - 1 ? e.pop() : e.splice(t, 1)[0]
}

function fh(e, t) {
  let n = [];
  for (let r = 0; r < e; r++) n.push(t);
  return n
}

function ph(e, t, n, r) {
  let o = e.length;
  if (o == t) e.push(n, r);
  else if (o === 1) e.push(r, e[0]), e[0] = n;
  else {
    for (o--, e.push(e[o - 1], e[o]); o > t;) {
      let i = o - 2;
      e[o] = e[i], o--
    }
    e[t] = n, e[t + 1] = r
  }
}

function zi(e, t, n) {
  let r = Qn(e, t);
  return r >= 0 ? e[r | 1] = n : (r = ~r, ph(e, r, t, n)), r
}

function Gi(e, t) {
  let n = Qn(e, t);
  if (n >= 0) return e[n | 1]
}

function Qn(e, t) {
  return _E(e, t, 1)
}

function _E(e, t, n) {
  let r = 0,
    o = e.length >> n;
  for (; o !== r;) {
    let i = r + (o - r >> 1),
      s = e[i << n];
    if (t === s) return i << n;
    s > t ? o = i : r = i + 1
  }
  return ~(o << n)
}

function tu(e) {
  return e[Zc] || null
}

function Qe(e) {
  return e[Gc] || null
}

function Wi(e) {
  return e[Wc] || null
}

function hh(e) {
  return e[qc] || null
}

function Kn(e) {
  return {
    \u0275providers: e
  }
}

function gh(...e) {
  return {
    \u0275providers: nu(!0, e),
    \u0275fromNgModule: !0
  }
}

function nu(e, ...t) {
  let n = [],
    r = new Set,
    o, i = s => {
      n.push(s)
    };
  return $i(t, s => {
    let a = s;
    Li(a, i, [], r) && (o ||= [], o.push(a))
  }), o !== void 0 && mh(o, i), n
}

function mh(e, t) {
  for (let n = 0; n < e.length; n++) {
    let {
      ngModule: r,
      providers: o
    } = e[n];
    ru(o, i => {
      t(i, r)
    })
  }
}

function Li(e, t, n, r) {
  if (e = ee(e), !e) return !1;
  let o = null,
    i = Oc(e),
    s = !i && Qe(e);
  if (!i && !s) {
    let c = e.ngModule;
    if (i = Oc(c), i) o = c;
    else return !1
  } else {
    if (s && !s.standalone) return !1;
    o = e
  }
  let a = r.has(o);
  if (s) {
    if (a) return !1;
    if (r.add(o), s.dependencies) {
      let c = typeof s.dependencies == "function" ? s.dependencies() : s.dependencies;
      for (let u of c) Li(u, t, n, r)
    }
  } else if (i) {
    if (i.imports != null && !a) {
      r.add(o);
      let u;
      try {
        $i(i.imports, l => {
          Li(l, t, n, r) && (u ||= [], u.push(l))
        })
      } finally {}
      u !== void 0 && mh(u, t)
    }
    if (!a) {
      let u = Mt(o) || (() => new o);
      t({
        provide: o,
        useFactory: u,
        deps: ae
      }, o), t({
        provide: eu,
        useValue: o,
        multi: !0
      }, o), t({
        provide: Nt,
        useValue: () => C(o),
        multi: !0
      }, o)
    }
    let c = i.providers;
    if (c != null && !a) {
      let u = e;
      ru(c, l => {
        t(l, u)
      })
    }
  } else return !1;
  return o !== e && e.providers !== void 0
}

function ru(e, t) {
  for (let n of e) zc(n) && (n = n.\u0275providers), Array.isArray(n) ? ru(n, t) : t(n)
}

function yh(e) {
  return e !== null && typeof e == "object" && ME in e
}

function SE(e) {
  return !!(e && e.useExisting)
}

function NE(e) {
  return !!(e && e.useFactory)
}

function sn(e) {
  return typeof e == "function"
}

function vh(e) {
  return !!e.useClass
}

function Jn() {
  return Rc === void 0 && (Rc = new Gr), Rc
}

function jc(e) {
  let t = qr(e),
    n = t !== null ? t.factory : Mt(e);
  if (n !== null) return n;
  if (e instanceof T) throw new v(204, !1);
  if (e instanceof Function) return AE(e);
  throw new v(204, !1)
}

function AE(e) {
  if (e.length > 0) throw new v(204, !1);
  let n = vE(e);
  return n !== null ? () => n.factory(e) : () => new e
}

function xE(e) {
  if (yh(e)) return Yn(void 0, e.useValue);
  {
    let t = ou(e);
    return Yn(t, ki)
  }
}

function ou(e, t, n) {
  let r;
  if (sn(e)) {
    let o = ee(e);
    return Mt(o) || jc(o)
  } else if (yh(e)) r = () => ee(e.useValue);
  else if (NE(e)) r = () => e.useFactory(...Lc(e.deps || []));
  else if (SE(e)) r = (o, i) => C(ee(e.useExisting), i !== void 0 && i & 8 ? 8 : void 0);
  else {
    let o = ee(e && (e.useClass || e.provide));
    if (RE(e)) r = () => new o(...Lc(e.deps));
    else return Mt(o) || jc(o)
  }
  return r
}

function $r(e) {
  if (e.destroyed) throw new v(205, !1)
}

function Yn(e, t, n = !1) {
  return {
    factory: e,
    value: t,
    multi: n ? [] : void 0
  }
}

function RE(e) {
  return !!e.deps
}

function OE(e) {
  return e !== null && typeof e == "object" && typeof e.ngOnDestroy == "function"
}

function FE(e) {
  return typeof e == "function" || typeof e == "object" && e.ngMetadataName === "InjectionToken"
}

function Bc(e, t) {
  for (let n of e) Array.isArray(n) ? Bc(n, t) : n && zc(n) ? Bc(n.\u0275providers, t) : t(n)
}

function Xn(e, t) {
  let n;
  e instanceof an ? ($r(e), n = e) : n = new Pc(e);
  let r, o = Ge(n),
    i = de(void 0);
  try {
    return t()
  } finally {
    Ge(o), de(i)
  }
}

function iu() {
  return uh() !== void 0 || Uo() != null
}

function Xe(e) {
  return Array.isArray(e) && typeof e[Dh] == "object"
}

function Pe(e) {
  return Array.isArray(e) && e[Dh] === !0
}

function uu(e) {
  return (e.flags & 4) !== 0
}

function mt(e) {
  return e.componentOffset > -1
}

function nr(e) {
  return (e.flags & 1) === 1
}

function Le(e) {
  return !!e.template
}

function rr(e) {
  return (e[A] & 512) !== 0
}

function gn(e) {
  return (e[A] & 256) === 256
}

function Me(e) {
  for (; Array.isArray(e);) e = e[ke];
  return e
}

function du(e, t) {
  return Me(t[e])
}

function Se(e, t) {
  return Me(t[e.index])
}

function Jr(e, t) {
  return e.data[t]
}

function Zi(e, t) {
  return e[t]
}

function fu(e, t, n, r) {
  n >= e.data.length && (e.data[n] = null, e.blueprint[n] = null), t[n] = r
}

function Ne(e, t) {
  let n = t[e];
  return Xe(n) ? n : n[ke]
}

function Ih(e) {
  return (e[A] & 4) === 4
}

function Yi(e) {
  return (e[A] & 128) === 128
}

function wh(e) {
  return Pe(e[te])
}

function we(e, t) {
  return t == null ? null : e[t]
}

function pu(e) {
  e[dn] = 0
}

function hu(e) {
  e[A] & 1024 || (e[A] |= 1024, Yi(e) && Rt(e))
}

function Ch(e, t) {
  for (; e > 0;) t = t[ln], e--;
  return t
}

function Xr(e) {
  return !!(e[A] & 9216 || e[Ie]?.dirty)
}

function Qi(e) {
  e[Ke].changeDetectionScheduler?.notify(8), e[A] & 64 && (e[A] |= 1024), Xr(e) && Rt(e)
}

function Rt(e) {
  e[Ke].changeDetectionScheduler?.notify(0);
  let t = St(e);
  for (; t !== null && !(t[A] & 8192 || (t[A] |= 8192, !Yi(t)));) t = St(t)
}

function gu(e, t) {
  if (gn(e)) throw new v(911, !1);
  e[dt] === null && (e[dt] = []), e[dt].push(t)
}

function bh(e, t) {
  if (e[dt] === null) return;
  let n = e[dt].indexOf(t);
  n !== -1 && e[dt].splice(n, 1)
}

function St(e) {
  let t = e[te];
  return Pe(t) ? t[te] : t
}

function mu(e) {
  return e[er] ??= []
}

function yu(e) {
  return e.cleanup ??= []
}

function Th(e, t, n, r) {
  let o = mu(t);
  o.push(n), e.firstCreatePass && yu(e).push(r, o.length - 1)
}

function _h() {
  return x.lFrame.elementDepthCount
}

function Mh() {
  x.lFrame.elementDepthCount++
}

function vu() {
  x.lFrame.elementDepthCount--
}

function Ki() {
  return x.bindingsEnabled
}

function Du() {
  return x.skipHydrationRootTNode !== null
}

function Eu(e) {
  return x.skipHydrationRootTNode === e
}

function Iu() {
  x.skipHydrationRootTNode = null
}

function E() {
  return x.lFrame.lView
}

function B() {
  return x.lFrame.tView
}

function Sh(e) {
  return x.lFrame.contextLView = e, e[q]
}

function Nh(e) {
  return x.lFrame.contextLView = null, e
}

function J() {
  let e = wu();
  for (; e !== null && e.type === 64;) e = e.parent;
  return e
}

function wu() {
  return x.lFrame.currentTNode
}

function Ah() {
  let e = x.lFrame,
    t = e.currentTNode;
  return e.isParent ? t : t.parent
}

function or(e, t) {
  let n = x.lFrame;
  n.currentTNode = e, n.isParent = t
}

function Cu() {
  return x.lFrame.isParent
}

function bu() {
  x.lFrame.isParent = !1
}

function xh() {
  return x.lFrame.contextLView
}

function Tu() {
  return Vc
}

function ir(e) {
  let t = Vc;
  return Vc = e, t
}

function mn() {
  let e = x.lFrame,
    t = e.bindingRootIndex;
  return t === -1 && (t = e.bindingRootIndex = e.tView.bindingStartIndex), t
}

function _u() {
  return x.lFrame.bindingIndex
}

function Rh(e) {
  return x.lFrame.bindingIndex = e
}

function et() {
  return x.lFrame.bindingIndex++
}

function eo(e) {
  let t = x.lFrame,
    n = t.bindingIndex;
  return t.bindingIndex = t.bindingIndex + e, n
}

function Oh() {
  return x.lFrame.inI18n
}

function Fh(e, t) {
  let n = x.lFrame;
  n.bindingIndex = n.bindingRootIndex = e, Ji(t)
}

function kh() {
  return x.lFrame.currentDirectiveIndex
}

function Ji(e) {
  x.lFrame.currentDirectiveIndex = e
}

function Ph(e) {
  let t = x.lFrame.currentDirectiveIndex;
  return t === -1 ? null : e[t]
}

function Xi() {
  return x.lFrame.currentQueryIndex
}

function to(e) {
  x.lFrame.currentQueryIndex = e
}

function kE(e) {
  let t = e[w];
  return t.type === 2 ? t.declTNode : t.type === 1 ? e[fe] : null
}

function Mu(e, t, n) {
  if (n & 4) {
    let o = t,
      i = e;
    for (; o = o.parent, o === null && !(n & 1);)
      if (o = kE(i), o === null || (i = i[ln], o.type & 10)) break;
    if (o === null) return !1;
    t = o, e = i
  }
  let r = x.lFrame = Lh();
  return r.currentTNode = t, r.lView = e, !0
}

function es(e) {
  let t = Lh(),
    n = e[w];
  x.lFrame = t, t.currentTNode = n.firstChild, t.lView = e, t.tView = n, t.contextLView = e, t.bindingIndex = n.bindingStartIndex, t.inI18n = !1
}

function Lh() {
  let e = x.lFrame,
    t = e === null ? null : e.child;
  return t === null ? jh(e) : t
}

function jh(e) {
  let t = {
    currentTNode: null,
    isParent: !0,
    lView: null,
    tView: null,
    selectedIndex: -1,
    contextLView: null,
    elementDepthCount: 0,
    currentNamespace: null,
    currentDirectiveIndex: -1,
    bindingRootIndex: -1,
    bindingIndex: -1,
    currentQueryIndex: 0,
    parent: e,
    child: null,
    inI18n: !1
  };
  return e !== null && (e.child = t), t
}

function Bh() {
  let e = x.lFrame;
  return x.lFrame = e.parent, e.currentTNode = null, e.lView = null, e
}

function ts() {
  let e = Bh();
  e.isParent = !0, e.tView = null, e.selectedIndex = -1, e.contextLView = null, e.elementDepthCount = 0, e.currentDirectiveIndex = -1, e.currentNamespace = null, e.bindingRootIndex = -1, e.bindingIndex = -1, e.currentQueryIndex = 0
}

function Vh(e) {
  return (x.lFrame.contextLView = Ch(e, x.lFrame.contextLView))[q]
}

function je() {
  return x.lFrame.selectedIndex
}

function Ot(e) {
  x.lFrame.selectedIndex = e
}

function sr() {
  let e = x.lFrame;
  return Jr(e.tView, e.selectedIndex)
}

function Hh() {
  x.lFrame.currentNamespace = lu
}

function Uh() {
  PE()
}

function PE() {
  x.lFrame.currentNamespace = null
}

function $h() {
  return x.lFrame.currentNamespace
}

function ns() {
  return zh
}

function no(e) {
  zh = e
}

function Hc(e, t = null, n = null, r) {
  let o = Nu(e, t, n, r);
  return o.resolveInjectorInitializers(), o
}

function Nu(e, t = null, n = null, r, o = new Set) {
  let i = [n || ae, gh(e)];
  return r = r || (typeof e == "object" ? void 0 : ft(e)), new an(i, t || Jn(), r || null, o)
}

function LE() {
  return new Wr(E())
}

function Au(e) {
  return typeof e == "function" && e[X] !== void 0
}

function rs(e, t) {
  let [n, r, o] = Na(e, t?.equal), i = n, s = i[X];
  return i.set = r, i.update = o, i.asReadonly = xu.bind(i), i
}

function xu() {
  let e = this[X];
  if (e.readonlyFn === void 0) {
    let t = () => this();
    t[X] = e, e.readonlyFn = t
  }
  return e.readonlyFn
}

function Ru(e) {
  return Au(e) && typeof e.set == "function"
}

function jE() {
  return new yn(E(), J())
}

function vn(...e) {}
var ji, v, ne, gE, Hi, Pi, T, Gc, Wc, qc, Zc, zr, cn, rh, ah, DE, EE, Fc, wE, rn, kc, Pc, Fe, ae, Nt, Xc, eu, Gr, ME, Yr, ki, oh, Rc, ye, an, ke, w, A, te, _e, fe, un, er, q, ht, Ke, P, tr, su, ln, ce, At, dn, Je, Qr, au, dt, qi, gt, Ie, fn, pn, H, Dh, cu, xt, Kr, hn, Z, lu, Eh, x, Vc, Su, zh, ve, Y, Ae, Wr, De, Be, Gh, yn, Te, ro, Ou, Fu, Ft, ar, oo, Uc, io = h(() => {
  Ca();
  Wt();
  Ur();
  xc();
  nh();
  ji = "https://angular.dev/best-practices/security#preventing-cross-site-scripting-xss", v = class extends Error {
    code;
    constructor(t, n) {
      super(Ye(t, n)), this.code = t
    }
  };
  ne = globalThis;
  gE = k({
    __forward_ref__: k
  });
  Hi = k({
    \u0275prov: k
  }), Pi = k({
    \u0275inj: k
  }), T = class {
    _desc;
    ngMetadataName = "InjectionToken";
    \u0275prov;
    constructor(t, n) {
      this._desc = t, this.\u0275prov = void 0, typeof n == "number" ? this.__NG_ELEMENT_ID__ = n : n !== void 0 && (this.\u0275prov = N({
        token: this,
        providedIn: n.providedIn || "root",
        factory: n.factory
      }))
    }
    get multi() {
      return this
    }
    toString() {
      return `InjectionToken ${this._desc}`
    }
  };
  Gc = k({
    \u0275cmp: k
  }), Wc = k({
    \u0275dir: k
  }), qc = k({
    \u0275pipe: k
  }), Zc = k({
    \u0275mod: k
  }), zr = k({
    \u0275fac: k
  }), cn = k({
    __NG_ELEMENT_ID__: k
  }), rh = k({
    __NG_ENV_ID__: k
  });
  ah = k({
    ngErrorCode: k
  }), DE = k({
    ngErrorMessage: k
  }), EE = k({
    ngTokenPath: k
  });
  wE = {}, rn = wE, kc = "__NG_DI_FLAG__", Pc = class {
    injector;
    constructor(t) {
      this.injector = t
    }
    retrieve(t, n) {
      let r = on(n) || 0;
      try {
        return this.injector.get(t, r & 8 ? null : rn, r)
      } catch (o) {
        if (Nn(o)) return o;
        throw o
      }
    }
  };
  Fe = {}, ae = [], Nt = new T(""), Xc = new T("", -1), eu = new T(""), Gr = class {
    get(t, n = rn) {
      if (n === rn) {
        let o = ch("", -201);
        throw o.name = "ɵNotFound", o
      }
      return n
    }
  };
  ME = k({
    provide: String,
    useValue: k
  });
  Yr = new T(""), ki = {}, oh = {};
  ye = class {}, an = class extends ye {
    parent;
    source;
    scopes;
    records = new Map;
    _ngOnDestroyHooks = new Set;
    _onDestroyHooks = [];
    get destroyed() {
      return this._destroyed
    }
    _destroyed = !1;
    injectorDefTypes;
    constructor(t, n, r, o) {
      super(), this.parent = n, this.source = r, this.scopes = o, Bc(t, s => this.processProvider(s)), this.records.set(Xc, Yn(void 0, this)), o.has("environment") && this.records.set(ye, Yn(void 0, this));
      let i = this.records.get(Yr);
      i != null && typeof i.value == "string" && this.scopes.add(i.value), this.injectorDefTypes = new Set(this.get(eu, ae, {
        self: !0
      }))
    }
    retrieve(t, n) {
      let r = on(n) || 0;
      try {
        return this.get(t, rn, r)
      } catch (o) {
        if (Nn(o)) return o;
        throw o
      }
    }
    destroy() {
      $r(this), this._destroyed = !0;
      let t = M(null);
      try {
        for (let r of this._ngOnDestroyHooks) r.ngOnDestroy();
        let n = this._onDestroyHooks;
        this._onDestroyHooks = [];
        for (let r of n) r()
      } finally {
        this.records.clear(), this._ngOnDestroyHooks.clear(), this.injectorDefTypes.clear(), M(t)
      }
    }
    onDestroy(t) {
      return $r(this), this._onDestroyHooks.push(t), () => this.removeOnDestroy(t)
    }
    runInContext(t) {
      $r(this);
      let n = Ge(this),
        r = de(void 0),
        o;
      try {
        return t()
      } finally {
        Ge(n), de(r)
      }
    }
    get(t, n = rn, r) {
      if ($r(this), t.hasOwnProperty(rh)) return t[rh](this);
      let o = on(r),
        i, s = Ge(this),
        a = de(void 0);
      try {
        if (!(o & 4)) {
          let u = this.records.get(t);
          if (u === void 0) {
            let l = FE(t) && qr(t);
            l && this.injectableDefInScope(l) ? u = Yn(jc(t), ki) : u = null, this.records.set(t, u)
          }
          if (u != null) return this.hydrate(t, u, o)
        }
        let c = o & 2 ? Jn() : this.parent;
        return n = o & 8 && n === rn ? null : n, c.get(t, n)
      } catch (c) {
        let u = IE(c);
        throw u === -200 || u === -201 ? new v(u, null) : c
      } finally {
        de(a), Ge(s)
      }
    }
    resolveInjectorInitializers() {
      let t = M(null),
        n = Ge(this),
        r = de(void 0),
        o;
      try {
        let i = this.get(Nt, ae, {
          self: !0
        });
        for (let s of i) s()
      } finally {
        Ge(n), de(r), M(t)
      }
    }
    toString() {
      let t = [],
        n = this.records;
      for (let r of n.keys()) t.push(ft(r));
      return `R3Injector[${t.join(", ")}]`
    }
    processProvider(t) {
      t = ee(t);
      let n = sn(t) ? t : ee(t && t.provide),
        r = xE(t);
      if (!sn(t) && t.multi === !0) {
        let o = this.records.get(n);
        o || (o = Yn(void 0, ki, !0), o.factory = () => Lc(o.multi), this.records.set(n, o)), n = t, o.multi.push(t)
      }
      this.records.set(n, r)
    }
    hydrate(t, n, r) {
      let o = M(null);
      try {
        if (n.value === oh) throw Yc(ft(t));
        return n.value === ki && (n.value = oh, n.value = n.factory(void 0, r)), typeof n.value == "object" && n.value && OE(n.value) && this._ngOnDestroyHooks.add(n.value), n.value
      } finally {
        M(o)
      }
    }
    injectableDefInScope(t) {
      if (!t.providedIn) return !1;
      let n = ee(t.providedIn);
      return typeof n == "string" ? n === "any" || this.scopes.has(n) : this.injectorDefTypes.has(n)
    }
    removeOnDestroy(t) {
      let n = this._onDestroyHooks.indexOf(t);
      n !== -1 && this._onDestroyHooks.splice(n, 1)
    }
  };
  ke = 0, w = 1, A = 2, te = 3, _e = 4, fe = 5, un = 6, er = 7, q = 8, ht = 9, Ke = 10, P = 11, tr = 12, su = 13, ln = 14, ce = 15, At = 16, dn = 17, Je = 18, Qr = 19, au = 20, dt = 21, qi = 22, gt = 23, Ie = 24, fn = 25, pn = 26, H = 27, Dh = 1, cu = 6, xt = 7, Kr = 8, hn = 9, Z = 10;
  lu = "svg", Eh = "math";
  x = {
    lFrame: jh(null),
    bindingsEnabled: !0,
    skipHydrationRootTNode: null
  }, Vc = !1;
  Su = Bh;
  zh = !0;
  ve = class e {
    static THROW_IF_NOT_FOUND = rn;
    static NULL = new Gr;
    static create(t, n) {
      if (Array.isArray(t)) return Hc({
        name: ""
      }, n, t, "");
      {
        let r = t.name ?? "";
        return Hc({
          name: r
        }, t.parent, t.providers, r)
      }
    }
    static \u0275prov = N({
      token: e,
      providedIn: "any",
      factory: () => C(Xc)
    });
    static __NG_ELEMENT_ID__ = -1
  }, Y = new T(""), Ae = (() => {
    class e {
      static __NG_ELEMENT_ID__ = LE;
      static __NG_ENV_ID__ = n => n
    }
    return e
  })(), Wr = class extends Ae {
    _lView;
    constructor(t) {
      super(), this._lView = t
    }
    get destroyed() {
      return gn(this._lView)
    }
    onDestroy(t) {
      let n = this._lView;
      return gu(n, t), () => bh(n, t)
    }
  };
  De = class {
    _console = console;
    handleError(t) {
      this._console.error("ERROR", t)
    }
  }, Be = new T("", {
    providedIn: "root",
    factory: () => {
      let e = y(ye),
        t;
      return n => {
        e.destroyed && !t ? setTimeout(() => {
          throw n
        }) : (t ??= e.get(De), t.handleError(n))
      }
    }
  }), Gh = {
    provide: Nt,
    useValue: () => void y(De),
    multi: !0
  };
  yn = (() => {
    class e {
      view;
      node;
      constructor(n, r) {
        this.view = n, this.node = r
      }
      static __NG_ELEMENT_ID__ = jE
    }
    return e
  })();
  Te = class {}, ro = new T("", {
    providedIn: "root",
    factory: () => !1
  }), Ou = new T(""), Fu = new T(""), Ft = (() => {
    class e {
      taskId = 0;
      pendingTasks = new Set;
      destroyed = !1;
      pendingTask = new Rr(!1);
      get hasPendingTasks() {
        return this.destroyed ? !1 : this.pendingTask.value
      }
      get hasPendingTasksObservable() {
        return this.destroyed ? new R(n => {
          n.next(!1), n.complete()
        }) : this.pendingTask
      }
      add() {
        !this.hasPendingTasks && !this.destroyed && this.pendingTask.next(!0);
        let n = this.taskId++;
        return this.pendingTasks.add(n), n
      }
      has(n) {
        return this.pendingTasks.has(n)
      }
      remove(n) {
        this.pendingTasks.delete(n), this.pendingTasks.size === 0 && this.hasPendingTasks && this.pendingTask.next(!1)
      }
      ngOnDestroy() {
        this.pendingTasks.clear(), this.hasPendingTasks && this.pendingTask.next(!1), this.destroyed = !0, this.pendingTask.unsubscribe()
      }
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: () => new e
      })
    }
    return e
  })(), ar = (() => {
    class e {
      internalPendingTasks = y(Ft);
      scheduler = y(Te);
      errorHandler = y(Be);
      add() {
        let n = this.internalPendingTasks.add();
        return () => {
          this.internalPendingTasks.has(n) && (this.scheduler.notify(11), this.internalPendingTasks.remove(n))
        }
      }
      run(n) {
        let r = this.add();
        n().catch(this.errorHandler).finally(r)
      }
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: () => new e
      })
    }
    return e
  })();
  oo = (() => {
    class e {
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: () => new Uc
      })
    }
    return e
  })(), Uc = class {
    dirtyEffectCount = 0;
    queues = new Map;
    add(t) {
      this.enqueue(t), this.schedule(t)
    }
    schedule(t) {
      t.dirty && this.dirtyEffectCount++
    }
    remove(t) {
      let n = t.zone,
        r = this.queues.get(n);
      r.has(t) && (r.delete(t), t.dirty && this.dirtyEffectCount--)
    }
    enqueue(t) {
      let n = t.zone;
      this.queues.has(n) || this.queues.set(n, new Set);
      let r = this.queues.get(n);
      r.has(t) || r.add(t)
    }
    flush() {
      for (; this.dirtyEffectCount > 0;) {
        let t = !1;
        for (let [n, r] of this.queues) n === null ? t ||= this.flushQueue(r) : t ||= n.run(() => this.flushQueue(r));
        t || (this.dirtyEffectCount = 0)
      }
    }
    flushQueue(t) {
      let n = !1;
      for (let r of t) r.dirty && (this.dirtyEffectCount--, n = !0, r.run());
      return n
    }
  }
});
var ku = h(() => {
  xp();
  fc();
  Fp();
  hc();
  Ri();
  vc();
  Zn();
  Ec();
  Up();
  $p();
  Gn();
  mc();
  Ai();
  en();
  zp();
  $a();
  Gp();
  Tc();
  Wp();
  qp();
  _c();
  Mc();
  Vr();
  wc();
  Sc();
  Nc();
  Ac()
});

function gr(e) {
  return {
    toString: e
  }.toString()
}

function GE(e) {
  return function(...n) {
    if (e) {
      let r = e(...n);
      for (let o in r) this[o] = r[o]
    }
  }
}

function Sg(e, t, n) {
  return gr(() => {
    let r = GE(t);

    function o(...i) {
      if (this instanceof o) return r.apply(this, i), this;
      let s = new o(...i);
      return a.annotation = s, a;

      function a(c, u, l) {
        let d = c.hasOwnProperty(os) ? c[os] : Object.defineProperty(c, os, {
          value: []
        })[os];
        for (; d.length <= l;) d.push(null);
        return (d[l] = d[l] || []).push(s), c
      }
    }
    return o.prototype.ngMetadataName = e, o.annotationCls = o, o
  })
}

function qE(e) {
  return typeof e == "function"
}

function Ag(e, t, n, r) {
  t !== null ? t.applyValueToInputSignal(t, r) : e[n] = r
}

function xg(e) {
  return e.type.prototype.ngOnChanges && (e.setInput = YE), ZE
}

function ZE() {
  let e = Og(this),
    t = e?.current;
  if (t) {
    let n = e.previous;
    if (n === Fe) e.previous = t;
    else
      for (let r in t) n[r] = t[r];
    e.current = null, this.ngOnChanges(t)
  }
}

function YE(e, t, n, r, o) {
  let i = this.declaredInputs[r],
    s = Og(e) || QE(e, {
      previous: Fe,
      current: null
    }),
    a = s.current || (s.current = {}),
    c = s.previous,
    u = c[i];
  a[i] = new gs(u && u.currentValue, n, c === Fe), Ag(e, t, o, n)
}

function Og(e) {
  return e[Rg] || null
}

function QE(e, t) {
  return e[Rg] = t
}

function KE(e, t, n) {
  let {
    ngOnChanges: r,
    ngOnInit: o,
    ngDoCheck: i
  } = t.type.prototype;
  if (r) {
    let s = xg(t);
    (n.preOrderHooks ??= []).push(e, s), (n.preOrderCheckHooks ??= []).push(e, s)
  }
  o && (n.preOrderHooks ??= []).push(0 - e, o), i && ((n.preOrderHooks ??= []).push(e, i), (n.preOrderCheckHooks ??= []).push(e, i))
}

function Fg(e, t) {
  for (let n = t.directiveStart, r = t.directiveEnd; n < r; n++) {
    let i = e.data[n].type.prototype,
      {
        ngAfterContentInit: s,
        ngAfterContentChecked: a,
        ngAfterViewInit: c,
        ngAfterViewChecked: u,
        ngOnDestroy: l
      } = i;
    s && (e.contentHooks ??= []).push(-n, s), a && ((e.contentHooks ??= []).push(n, a), (e.contentCheckHooks ??= []).push(n, a)), c && (e.viewHooks ??= []).push(-n, c), u && ((e.viewHooks ??= []).push(n, u), (e.viewCheckHooks ??= []).push(n, u)), l != null && (e.destroyHooks ??= []).push(n, l)
  }
}

function ls(e, t, n) {
  kg(e, t, 3, n)
}

function ds(e, t, n, r) {
  (e[A] & 3) === n && kg(e, t, n, r)
}

function Pu(e, t) {
  let n = e[A];
  (n & 3) === t && (n &= 16383, n += 1, e[A] = n)
}

function kg(e, t, n, r) {
  let o = r !== void 0 ? e[dn] & 65535 : 0,
    i = r ?? -1,
    s = t.length - 1,
    a = 0;
  for (let c = o; c < s; c++)
    if (typeof t[c + 1] == "number") {
      if (a = t[c], r != null && a >= r) break
    } else t[c] < 0 && (e[dn] += 65536), (a < i || i == -1) && (JE(e, n, t, c), e[dn] = (e[dn] & 4294901760) + c + 2), c++
}

function qh(e, t) {
  L(4, e, t);
  let n = M(null);
  try {
    t.call(e)
  } finally {
    M(n), L(5, e, t)
  }
}

function JE(e, t, n, r) {
  let o = n[r] < 0,
    i = n[r + 1],
    s = o ? -n[r] : n[r],
    a = e[s];
  o ? e[A] >> 14 < e[dn] >> 16 && (e[A] & 3) === t && (e[A] += 16384, qh(a, i)) : qh(a, i)
}

function XE(e) {
  return (e.flags & 8) !== 0
}

function eI(e) {
  return (e.flags & 16) !== 0
}

function tI(e, t, n) {
  let r = 0;
  for (; r < n.length;) {
    let o = n[r];
    if (typeof o == "number") {
      if (o !== 0) break;
      r++;
      let i = n[r++],
        s = n[r++],
        a = n[r++];
      e.setAttribute(t, s, a, i)
    } else {
      let i = o,
        s = n[++r];
      nI(i) ? e.setProperty(t, i, s) : e.setAttribute(t, i, s), r++
    }
  }
  return r
}

function Pg(e) {
  return e === 3 || e === 4 || e === 6
}

function nI(e) {
  return e.charCodeAt(0) === 64
}

function lr(e, t) {
  if (!(t === null || t.length === 0))
    if (e === null || e.length === 0) e = t.slice();
    else {
      let n = -1;
      for (let r = 0; r < t.length; r++) {
        let o = t[r];
        typeof o == "number" ? n = o : n === 0 || (n === -1 || n === 2 ? Zh(e, n, o, null, t[++r]) : Zh(e, n, o, null, null))
      }
    } return e
}

function Zh(e, t, n, r, o) {
  let i = 0,
    s = e.length;
  if (t === -1) s = -1;
  else
    for (; i < e.length;) {
      let a = e[i++];
      if (typeof a == "number") {
        if (a === t) {
          s = -1;
          break
        } else if (a > t) {
          s = i - 1;
          break
        }
      }
    }
  for (; i < e.length;) {
    let a = e[i];
    if (typeof a == "number") break;
    if (a === n) {
      o !== null && (e[i + 1] = o);
      return
    }
    i++, o !== null && i++
  }
  s !== -1 && (e.splice(s, 0, t), i = s + 1), e.splice(i++, 0, n), o !== null && e.splice(i++, 0, o)
}

function Lg(e) {
  return e !== ur
}

function ms(e) {
  return e & 32767
}

function rI(e) {
  return e >> 16
}

function ys(e, t) {
  let n = rI(e),
    r = t;
  for (; n > 0;) r = r[ln], n--;
  return r
}

function vs(e) {
  let t = qu;
  return qu = e, t
}

function sI(e, t, n) {
  let r;
  typeof n == "string" ? r = n.charCodeAt(0) || 0 : n.hasOwnProperty(cn) && (r = n[cn]), r == null && (r = n[cn] = iI++);
  let o = r & jg,
    i = 1 << o;
  t.data[e + (o >> Bg)] |= i
}

function Ds(e, t) {
  let n = Vg(e, t);
  if (n !== -1) return n;
  let r = t[w];
  r.firstCreatePass && (e.injectorIndex = t.length, Lu(r.data, e), Lu(t, null), Lu(r.blueprint, null));
  let o = Fl(e, t),
    i = e.injectorIndex;
  if (Lg(o)) {
    let s = ms(o),
      a = ys(o, t),
      c = a[w].data;
    for (let u = 0; u < 8; u++) t[i + u] = a[s + u] | c[s + u]
  }
  return t[i + 8] = o, i
}

function Lu(e, t) {
  e.push(0, 0, 0, 0, 0, 0, 0, 0, t)
}

function Vg(e, t) {
  return e.injectorIndex === -1 || e.parent && e.parent.injectorIndex === e.injectorIndex || t[e.injectorIndex + 8] === null ? -1 : e.injectorIndex
}

function Fl(e, t) {
  if (e.parent && e.parent.injectorIndex !== -1) return e.parent.injectorIndex;
  let n = 0,
    r = null,
    o = t;
  for (; o !== null;) {
    if (r = Gg(o), r === null) return ur;
    if (n++, o = o[ln], r.injectorIndex !== -1) return r.injectorIndex | n << 16
  }
  return ur
}

function Zu(e, t, n) {
  sI(e, t, n)
}

function aI(e, t) {
  if (t === "class") return e.classes;
  if (t === "style") return e.styles;
  let n = e.attrs;
  if (n) {
    let r = n.length,
      o = 0;
    for (; o < r;) {
      let i = n[o];
      if (Pg(i)) break;
      if (i === 0) o = o + 2;
      else if (typeof i == "number")
        for (o++; o < r && typeof n[o] == "string";) o++;
      else {
        if (i === t) return n[o + 1];
        o = o + 2
      }
    }
  }
  return null
}

function Hg(e, t, n) {
  if (n & 8 || e !== void 0) return e;
  Ui(t, "NodeInjector")
}

function Ug(e, t, n, r) {
  if (n & 8 && r === void 0 && (r = null), (n & 3) === 0) {
    let o = e[ht],
      i = de(void 0);
    try {
      return o ? o.get(t, r, n & 8) : Qc(t, r, n & 8)
    } finally {
      de(i)
    }
  }
  return Hg(r, t, n)
}

function $g(e, t, n, r = 0, o) {
  if (e !== null) {
    if (t[A] & 2048 && !(r & 2)) {
      let s = fI(e, t, n, r, tt);
      if (s !== tt) return s
    }
    let i = zg(e, t, n, r, tt);
    if (i !== tt) return i
  }
  return Ug(t, n, r, o)
}

function zg(e, t, n, r, o) {
  let i = uI(n);
  if (typeof i == "function") {
    if (!Mu(t, e, r)) return r & 1 ? Hg(o, n, r) : Ug(t, n, r, o);
    try {
      let s;
      if (s = i(r), s == null && !(r & 8)) Ui(n);
      else return s
    } finally {
      Su()
    }
  } else if (typeof i == "number") {
    let s = null,
      a = Vg(e, t),
      c = ur,
      u = r & 1 ? t[ce][fe] : null;
    for ((a === -1 || r & 4) && (c = a === -1 ? Fl(e, t) : t[a + 8], c === ur || !Qh(r, !1) ? a = -1 : (s = t[w], a = ms(c), t = ys(c, t))); a !== -1;) {
      let l = t[w];
      if (Yh(i, a, l.data)) {
        let d = cI(a, t, n, s, r, u);
        if (d !== tt) return d
      }
      c = t[a + 8], c !== ur && Qh(r, t[w].data[a + 8] === u) && Yh(i, a, t) ? (s = l, a = ms(c), t = ys(c, t)) : a = -1
    }
  }
  return o
}

function cI(e, t, n, r, o, i) {
  let s = t[w],
    a = s.data[e + 8],
    c = r == null ? mt(a) && qu : r != s && (a.type & 3) !== 0,
    u = o & 1 && i === a,
    l = fs(a, s, n, c, u);
  return l !== null ? co(t, s, l, a, o) : tt
}

function fs(e, t, n, r, o) {
  let i = e.providerIndexes,
    s = t.data,
    a = i & 1048575,
    c = e.directiveStart,
    u = e.directiveEnd,
    l = i >> 20,
    d = r ? a : a + l,
    p = o ? a + l : u;
  for (let f = d; f < p; f++) {
    let g = s[f];
    if (f < c && n === g || f >= c && g.type === n) return f
  }
  if (o) {
    let f = s[c];
    if (f && Le(f) && f.type === n) return c
  }
  return null
}

function co(e, t, n, r, o) {
  let i = e[n],
    s = t.data;
  if (i instanceof En) {
    let a = i;
    if (a.resolving) {
      let f = sh(s[n]);
      throw Yc(f)
    }
    let c = vs(a.canSeeViewProviders);
    a.resolving = !0;
    let u = s[n].type || s[n],
      l, d = a.injectImpl ? de(a.injectImpl) : null,
      p = Mu(e, r, 0);
    try {
      i = e[n] = a.factory(void 0, o, s, e, r), t.firstCreatePass && n >= r.directiveStart && KE(n, s[n], t)
    } finally {
      d !== null && de(d), vs(c), a.resolving = !1, Su()
    }
  }
  return i
}

function uI(e) {
  if (typeof e == "string") return e.charCodeAt(0) || 0;
  let t = e.hasOwnProperty(cn) ? e[cn] : void 0;
  return typeof t == "number" ? t >= 0 ? t & jg : lI : t
}

function Yh(e, t, n) {
  let r = 1 << e;
  return !!(n[t + (e >> Bg)] & r)
}

function Qh(e, t) {
  return !(e & 2) && !(e & 1 && t)
}

function lI() {
  return new Dn(J(), E())
}

function dI(e) {
  return gr(() => {
    let t = e.prototype.constructor,
      n = t[zr] || Yu(t),
      r = Object.prototype,
      o = Object.getPrototypeOf(e.prototype).constructor;
    for (; o && o !== r;) {
      let i = o[zr] || Yu(o);
      if (i && i !== n) return i;
      o = Object.getPrototypeOf(o)
    }
    return i => new i
  })
}

function Yu(e) {
  return $c(e) ? () => {
    let t = Yu(ee(e));
    return t && t()
  } : Mt(e)
}

function fI(e, t, n, r, o) {
  let i = e,
    s = t;
  for (; i !== null && s !== null && s[A] & 2048 && !rr(s);) {
    let a = zg(i, s, n, r | 2, tt);
    if (a !== tt) return a;
    let c = i.parent;
    if (!c) {
      let u = s[au];
      if (u) {
        let l = u.get(n, tt, r);
        if (l !== tt) return l
      }
      c = Gg(s), s = s[ln]
    }
    i = c
  }
  return o
}

function Gg(e) {
  let t = e[w],
    n = t.type;
  return n === 2 ? t.declTNode : n === 1 ? e[fe] : null
}

function kl(e) {
  return aI(J(), e)
}

function pI() {
  return mr(J(), E())
}

function mr(e, t) {
  return new Et(Se(e, t))
}

function Wg(e) {
  return e instanceof Et ? e.nativeElement : e
}

function hI() {
  return this._results[Symbol.iterator]()
}

function qg(e) {
  return (e.flags & 128) === 128
}

function mI() {
  return gI++
}

function yI(e) {
  Zg.set(e[Qr], e)
}

function Qu(e) {
  Zg.delete(e[Qr])
}

function dr(e, t) {
  Xe(t) ? (e[Kh] = t[Qr], yI(t)) : e[Kh] = t
}

function Yg(e) {
  return Kg(e[tr])
}

function Qg(e) {
  return Kg(e[_e])
}

function Kg(e) {
  for (; e !== null && !Pe(e);) e = e[_e];
  return e
}

function Ll(e) {
  Ku = e
}

function jl() {
  if (Ku !== void 0) return Ku;
  if (typeof document < "u") return document;
  throw new v(210, !1)
}

function CI(e, t, n, r) {
  wI(e, t, n, r)
}

function js(e) {
  return (e.flags & 32) === 32
}

function rm(e, t, n = !1) {
  return bI(e, t, n)
}

function om(e, t) {
  let n = e.contentQueries;
  if (n !== null) {
    let r = M(null);
    try {
      for (let o = 0; o < n.length; o += 2) {
        let i = n[o],
          s = n[o + 1];
        if (s !== -1) {
          let a = e.data[s];
          to(i), a.contentQueries(2, t[s], s)
        }
      }
    } finally {
      M(r)
    }
  }
}

function Ju(e, t, n) {
  to(0);
  let r = M(null);
  try {
    t(e, n)
  } finally {
    M(r)
  }
}

function Bl(e, t, n) {
  if (uu(t)) {
    let r = M(null);
    try {
      let o = t.directiveStart,
        i = t.directiveEnd;
      for (let s = o; s < i; s++) {
        let a = e.data[s];
        if (a.contentQueries) {
          let c = n[s];
          a.contentQueries(1, c, s)
        }
      }
    } finally {
      M(r)
    }
  }
}

function TI() {
  if (is === void 0 && (is = null, ne.trustedTypes)) try {
    is = ne.trustedTypes.createPolicy("angular", {
      createHTML: e => e,
      createScript: e => e,
      createScriptURL: e => e
    })
  } catch {}
  return is
}

function Bs(e) {
  return TI()?.createHTML(e) || e
}

function im() {
  if (ss === void 0 && (ss = null, ne.trustedTypes)) try {
    ss = ne.trustedTypes.createPolicy("angular#unsafe-bypass", {
      createHTML: e => e,
      createScript: e => e,
      createScriptURL: e => e
    })
  } catch {}
  return ss
}

function Jh(e) {
  return im()?.createHTML(e) || e
}

function Xh(e) {
  return im()?.createScriptURL(e) || e
}

function Ce(e) {
  return e instanceof Dt ? e.changingThisBreaksApplicationSecurity : e
}

function rt(e, t) {
  let n = sm(e);
  if (n != null && n !== t) {
    if (n === "ResourceURL" && t === "URL") return !0;
    throw new Error(`Required a safe ${t}, got a ${n} (see ${ji})`)
  }
  return n === t
}

function sm(e) {
  return e instanceof Dt && e.getTypeName() || null
}

function Vl(e) {
  return new Xu(e)
}

function Hl(e) {
  return new el(e)
}

function Ul(e) {
  return new tl(e)
}

function $l(e) {
  return new nl(e)
}

function zl(e) {
  return new rl(e)
}

function _I(e) {
  let t = new il(e);
  return MI() ? new ol(t) : t
}

function MI() {
  try {
    return !!new window.DOMParser().parseFromString(Bs(""), "text/html")
  } catch {
    return !1
  }
}

function yo(e) {
  return e = String(e), e.match(SI) ? e : "unsafe:" + e
}

function It(e) {
  let t = {};
  for (let n of e.split(",")) t[n] = !0;
  return t
}

function vo(...e) {
  let t = {};
  for (let n of e)
    for (let r in n) n.hasOwnProperty(r) && (t[r] = !0);
  return t
}

function PI(e, t) {
  return (e.compareDocumentPosition(t) & Node.DOCUMENT_POSITION_CONTAINED_BY) !== Node.DOCUMENT_POSITION_CONTAINED_BY
}

function LI(e) {
  let t = e.nextSibling;
  if (t && e !== t.previousSibling) throw dm(t);
  return t
}

function jI(e) {
  let t = e.firstChild;
  if (t && PI(e, t)) throw dm(t);
  return t
}

function tg(e) {
  let t = e.nodeName;
  return typeof t == "string" ? t : "FORM"
}

function dm(e) {
  return new Error(`Failed to sanitize html because the element is clobbered: ${e.outerHTML}`)
}

function ng(e) {
  return e.replace(/&/g, "&amp;").replace(BI, function(t) {
    let n = t.charCodeAt(0),
      r = t.charCodeAt(1);
    return "&#" + ((n - 55296) * 1024 + (r - 56320) + 65536) + ";"
  }).replace(VI, function(t) {
    return "&#" + t.charCodeAt(0) + ";"
  }).replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

function Vs(e, t) {
  let n = null;
  try {
    as = as || _I(e);
    let r = t ? String(t) : "";
    n = as.getInertBodyElement(r);
    let o = 5,
      i = r;
    do {
      if (o === 0) throw new Error("Failed to sanitize html because the input is unstable");
      o--, r = i, i = n.innerHTML, n = as.getInertBodyElement(r)
    } while (r !== i);
    let a = new sl().sanitizeChildren(rg(n) || n);
    return Bs(a)
  } finally {
    if (n) {
      let r = rg(n) || n;
      for (; r.firstChild;) r.firstChild.remove()
    }
  }
}

function rg(e) {
  return "content" in e && HI(e) ? e.content : null
}

function HI(e) {
  return e.nodeType === Node.ELEMENT_NODE && e.nodeName === "TEMPLATE"
}

function GI(e) {
  return e.replace(UI, t => t.replace($I, zI))
}

function WI(e, t) {
  return e.createText(t)
}

function qI(e, t, n) {
  e.setValue(t, n)
}

function ZI(e, t) {
  return e.createComment(GI(t))
}

function fm(e, t, n) {
  return e.createElement(t, n)
}

function Is(e, t, n, r, o) {
  e.insertBefore(t, n, r, o)
}

function pm(e, t, n) {
  e.appendChild(t, n)
}

function og(e, t, n, r, o) {
  r !== null ? Is(e, t, n, r, o) : pm(e, t, n)
}

function hm(e, t, n, r) {
  e.removeChild(null, t, n, r)
}

function YI(e, t, n) {
  e.setAttribute(t, "style", n)
}

function QI(e, t, n) {
  n === "" ? e.removeAttribute(t, "class") : e.setAttribute(t, "class", n)
}

function gm(e, t, n) {
  let {
    mergedAttrs: r,
    classes: o,
    styles: i
  } = n;
  r !== null && tI(e, t, r), o !== null && QI(e, t, o), i !== null && YI(e, t, i)
}

function KI(e) {
  let t = Gl();
  return t ? Jh(t.sanitize(xe.HTML, e) || "") : rt(e, "HTML") ? Jh(Ce(e)) : Vs(jl(), Ee(e))
}

function mm(e) {
  let t = Gl();
  return t ? t.sanitize(xe.URL, e) || "" : rt(e, "URL") ? Ce(e) : yo(Ee(e))
}

function ym(e) {
  let t = Gl();
  if (t) return Xh(t.sanitize(xe.RESOURCE_URL, e) || "");
  if (rt(e, "ResourceURL")) return Xh(Ce(e));
  throw new v(904, !1)
}

function ew(e, t) {
  return t === "src" && JI.has(e) || t === "href" && XI.has(e) || t === "xlink:href" && e === "script" ? ym : mm
}

function tw(e, t, n) {
  return ew(t, n)(e)
}

function Gl() {
  let e = E();
  return e && e[Ke].sanitizer
}

function nw(e) {
  return e.ownerDocument.defaultView
}

function vm(e) {
  return e instanceof Function ? e() : e
}

function rw(e, t, n) {
  let r = e.length;
  for (;;) {
    let o = e.indexOf(t, n);
    if (o === -1) return o;
    if (o === 0 || e.charCodeAt(o - 1) <= 32) {
      let i = t.length;
      if (o + i === r || e.charCodeAt(o + i) <= 32) return o
    }
    n = o + 1
  }
}

function ow(e, t, n, r) {
  let o = 0;
  if (r) {
    for (; o < t.length && typeof t[o] == "string"; o += 2)
      if (t[o] === "class" && rw(t[o + 1].toLowerCase(), n, 0) !== -1) return !0
  } else if (Wl(e)) return !1;
  if (o = t.indexOf(1, o), o > -1) {
    let i;
    for (; ++o < t.length && typeof(i = t[o]) == "string";)
      if (i.toLowerCase() === n) return !0
  }
  return !1
}

function Wl(e) {
  return e.type === 4 && e.value !== Dm
}

function iw(e, t, n) {
  let r = e.type === 4 && !n ? Dm : e.value;
  return t === r
}

function sw(e, t, n) {
  let r = 4,
    o = e.attrs,
    i = o !== null ? uw(o) : 0,
    s = !1;
  for (let a = 0; a < t.length; a++) {
    let c = t[a];
    if (typeof c == "number") {
      if (!s && !Ve(r) && !Ve(c)) return !1;
      if (s && Ve(c)) continue;
      s = !1, r = c | r & 1;
      continue
    }
    if (!s)
      if (r & 4) {
        if (r = 2 | r & 1, c !== "" && !iw(e, c, n) || c === "" && t.length === 1) {
          if (Ve(r)) return !1;
          s = !0
        }
      } else if (r & 8) {
      if (o === null || !ow(e, o, c, n)) {
        if (Ve(r)) return !1;
        s = !0
      }
    } else {
      let u = t[++a],
        l = aw(c, o, Wl(e), n);
      if (l === -1) {
        if (Ve(r)) return !1;
        s = !0;
        continue
      }
      if (u !== "") {
        let d;
        if (l > i ? d = "" : d = o[l + 1].toLowerCase(), r & 2 && u !== d) {
          if (Ve(r)) return !1;
          s = !0
        }
      }
    }
  }
  return Ve(r) || s
}

function Ve(e) {
  return (e & 1) === 0
}

function aw(e, t, n, r) {
  if (t === null) return -1;
  let o = 0;
  if (r || !n) {
    let i = !1;
    for (; o < t.length;) {
      let s = t[o];
      if (s === e) return o;
      if (s === 3 || s === 6) i = !0;
      else if (s === 1 || s === 2) {
        let a = t[++o];
        for (; typeof a == "string";) a = t[++o];
        continue
      } else {
        if (s === 4) break;
        if (s === 0) {
          o += 4;
          continue
        }
      }
      o += i ? 1 : 2
    }
    return -1
  } else return lw(t, e)
}

function Em(e, t, n = !1) {
  for (let r = 0; r < t.length; r++)
    if (sw(e, t[r], n)) return !0;
  return !1
}

function cw(e) {
  let t = e.attrs;
  if (t != null) {
    let n = t.indexOf(5);
    if ((n & 1) === 0) return t[n + 1]
  }
  return null
}

function uw(e) {
  for (let t = 0; t < e.length; t++) {
    let n = e[t];
    if (Pg(n)) return t
  }
  return e.length
}

function lw(e, t) {
  let n = e.indexOf(4);
  if (n > -1)
    for (n++; n < e.length;) {
      let r = e[n];
      if (typeof r == "number") return -1;
      if (r === t) return n;
      n++
    }
  return -1
}

function dw(e, t) {
  e: for (let n = 0; n < t.length; n++) {
    let r = t[n];
    if (e.length === r.length) {
      for (let o = 0; o < e.length; o++)
        if (e[o] !== r[o]) continue e;
      return !0
    }
  }
  return !1
}

function ig(e, t) {
  return e ? ":not(" + t.trim() + ")" : t
}

function fw(e) {
  let t = e[0],
    n = 1,
    r = 2,
    o = "",
    i = !1;
  for (; n < e.length;) {
    let s = e[n];
    if (typeof s == "string")
      if (r & 2) {
        let a = e[++n];
        o += "[" + s + (a.length > 0 ? '="' + a + '"' : "") + "]"
      } else r & 8 ? o += "." + s : r & 4 && (o += " " + s);
    else o !== "" && !Ve(s) && (t += ig(i, o), o = ""), r = s, i = i || !Ve(r);
    n++
  }
  return o !== "" && (t += ig(i, o)), t
}

function pw(e) {
  return e.map(fw).join(",")
}

function hw(e) {
  let t = [],
    n = [],
    r = 1,
    o = 2;
  for (; r < e.length;) {
    let i = e[r];
    if (typeof i == "string") o === 2 ? i !== "" && t.push(i, e[++r]) : o === 8 && n.push(i);
    else {
      if (!Ve(o)) break;
      o = i
    }
    r++
  }
  return n.length && t.push(1, ...n), t
}

function ql(e, t, n, r, o, i, s, a, c, u, l) {
  let d = H + r,
    p = d + o,
    f = gw(d, p),
    g = typeof u == "function" ? u() : u;
  return f[w] = {
    type: e,
    blueprint: f,
    template: n,
    queries: null,
    viewQuery: a,
    declTNode: t,
    data: f.slice().fill(null, d),
    bindingStartIndex: d,
    expandoStartIndex: p,
    hostBindingOpCodes: null,
    firstCreatePass: !0,
    firstUpdatePass: !0,
    staticViewQueries: !1,
    staticContentQueries: !1,
    preOrderHooks: null,
    preOrderCheckHooks: null,
    contentHooks: null,
    contentCheckHooks: null,
    viewHooks: null,
    viewCheckHooks: null,
    destroyHooks: null,
    cleanup: null,
    contentQueries: null,
    components: null,
    directiveRegistry: typeof i == "function" ? i() : i,
    pipeRegistry: typeof s == "function" ? s() : s,
    firstChild: null,
    schemas: c,
    consts: g,
    incompleteFirstPass: !1,
    ssrId: l
  }
}

function gw(e, t) {
  let n = [];
  for (let r = 0; r < t; r++) n.push(r < e ? null : re);
  return n
}

function mw(e) {
  let t = e.tView;
  return t === null || t.incompleteFirstPass ? e.tView = ql(1, null, e.template, e.decls, e.vars, e.directiveDefs, e.pipeDefs, e.viewQuery, e.schemas, e.consts, e.id) : t
}

function Zl(e, t, n, r, o, i, s, a, c, u, l) {
  let d = t.blueprint.slice();
  return d[ke] = o, d[A] = r | 4 | 128 | 8 | 64 | 1024, (u !== null || e && e[A] & 2048) && (d[A] |= 2048), pu(d), d[te] = d[ln] = e, d[q] = n, d[Ke] = s || e && e[Ke], d[P] = a || e && e[P], d[ht] = c || e && e[ht] || null, d[fe] = i, d[Qr] = mI(), d[un] = l, d[au] = u, d[ce] = t.type == 2 ? e[ce] : d, d
}

function yw(e, t, n) {
  let r = Se(t, e),
    o = mw(n),
    i = e[Ke].rendererFactory,
    s = Yl(e, Zl(e, o, null, Im(n), r, t, null, i.createRenderer(r, n), null, null, null));
  return e[t.index] = s
}

function Im(e) {
  let t = 16;
  return e.signals ? t = 4096 : e.onPush && (t = 64), t
}

function wm(e, t, n, r) {
  if (n === 0) return -1;
  let o = t.length;
  for (let i = 0; i < n; i++) t.push(r), e.blueprint.push(r), e.data.push(null);
  return o
}

function Yl(e, t) {
  return e[tr] ? e[su][_e] = t : e[tr] = t, e[su] = t, t
}

function vw(e = 1) {
  Cm(B(), E(), je() + e, !1)
}

function Cm(e, t, n, r) {
  if (!r)
    if ((t[A] & 3) === 3) {
      let i = e.preOrderCheckHooks;
      i !== null && ls(t, i, n)
    } else {
      let i = e.preOrderHooks;
      i !== null && ds(t, i, 0, n)
    } Ot(n)
}

function al(e, t, n, r) {
  let o = M(null);
  try {
    let [i, s, a] = e.inputs[n], c = null;
    (s & Hs.SignalBased) !== 0 && (c = t[i][X]), c !== null && c.transformFn !== void 0 ? r = c.transformFn(r) : a !== null && (r = a.call(t, r)), e.setInput !== null ? e.setInput(t, c, r, n, i) : Ag(t, c, i, r)
  } finally {
    M(o)
  }
}

function Ql(e, t) {
  return Dw(e, t)
}

function jt(e) {
  sg.has(e) || (sg.add(e), performance?.mark?.("mark_feature_usage", {
    detail: {
      feature: e
    }
  }))
}

function Tm(e) {
  let t, n;

  function r() {
    e = vn;
    try {
      n !== void 0 && typeof cancelAnimationFrame == "function" && cancelAnimationFrame(n), t !== void 0 && clearTimeout(t)
    } catch {}
  }
  return t = setTimeout(() => {
    e(), r()
  }), typeof requestAnimationFrame == "function" && (n = requestAnimationFrame(() => {
    e(), r()
  })), () => r()
}

function ag(e) {
  return queueMicrotask(() => e()), () => {
    e = vn
  }
}

function Jl(e) {
  if (e._nesting == 0 && !e.hasPendingMicrotasks && !e.isStable) try {
    e._nesting++, e.onMicrotaskEmpty.emit(null)
  } finally {
    if (e._nesting--, !e.hasPendingMicrotasks) try {
      e.runOutsideAngular(() => e.onStable.emit(null))
    } finally {
      e.isStable = !0
    }
  }
}

function ww(e) {
  if (e.isCheckStableRunning || e.callbackScheduled) return;
  e.callbackScheduled = !0;

  function t() {
    Tm(() => {
      e.callbackScheduled = !1, ul(e), e.isCheckStableRunning = !0, Jl(e), e.isCheckStableRunning = !1
    })
  }
  e.scheduleInRootZone ? Zone.root.run(() => {
    t()
  }) : e._outer.run(() => {
    t()
  }), ul(e)
}

function Cw(e) {
  let t = () => {
      ww(e)
    },
    n = Ew++;
  e._inner = e._inner.fork({
    name: "angular",
    properties: {
      [Kl]: !0,
      [ws]: n,
      [ws + n]: !0
    },
    onInvokeTask: (r, o, i, s, a, c) => {
      if (bw(c)) return r.invokeTask(i, s, a, c);
      try {
        return cg(e), r.invokeTask(i, s, a, c)
      } finally {
        (e.shouldCoalesceEventChangeDetection && s.type === "eventTask" || e.shouldCoalesceRunChangeDetection) && t(), ug(e)
      }
    },
    onInvoke: (r, o, i, s, a, c, u) => {
      try {
        return cg(e), r.invoke(i, s, a, c, u)
      } finally {
        e.shouldCoalesceRunChangeDetection && !e.callbackScheduled && !Tw(c) && t(), ug(e)
      }
    },
    onHasTask: (r, o, i, s) => {
      r.hasTask(i, s), o === i && (s.change == "microTask" ? (e._hasPendingMicrotasks = s.microTask, ul(e), Jl(e)) : s.change == "macroTask" && (e.hasPendingMacrotasks = s.macroTask))
    },
    onHandleError: (r, o, i, s) => (r.handleError(i, s), e.runOutsideAngular(() => e.onError.emit(s)), !1)
  })
}

function ul(e) {
  e._hasPendingMicrotasks || (e.shouldCoalesceEventChangeDetection || e.shouldCoalesceRunChangeDetection) && e.callbackScheduled === !0 ? e.hasPendingMicrotasks = !0 : e.hasPendingMicrotasks = !1
}

function cg(e) {
  e._nesting++, e.isStable && (e.isStable = !1, e.onUnstable.emit(null))
}

function ug(e) {
  e._nesting--, Jl(e)
}

function bw(e) {
  return _m(e, "__ignore_ng_zone__")
}

function Tw(e) {
  return _m(e, "__scheduler_tick__")
}

function _m(e, t) {
  return !Array.isArray(e) || e.length !== 1 ? !1 : e[0]?.data?.[t] === !0
}

function _w(e, t) {
  let n = t?.injector ?? y(ve);
  return jt("NgAfterNextRender"), Sw(e, n, t, !0)
}

function Mw(e) {
  return e instanceof Function ? [void 0, void 0, e, void 0] : [e.earlyRead, e.write, e.mixedReadWrite, e.read]
}

function Sw(e, t, n, r) {
  let o = t.get($s);
  o.impl ??= t.get(ed);
  let i = t.get(Lt, null, {
      optional: !0
    }),
    s = n?.manualCleanup !== !0 ? t.get(Ae) : null,
    a = t.get(yn, null, {
      optional: !0
    }),
    c = new uo(o.impl, Mw(e), a?.view, r, s, i?.snapshot(null));
  return o.impl.register(c), c
}

function Sm(e, t, n) {
  let r = e.get(Mm);
  if (Array.isArray(t))
    for (let o of t) r.queue.add(o), n?.detachedLeaveAnimationFns?.push(o);
  else r.queue.add(t), n?.detachedLeaveAnimationFns?.push(t);
  r.scheduler && r.scheduler(e)
}

function Nw(e, t) {
  let n = e.get(Mm);
  if (t.detachedLeaveAnimationFns) {
    for (let r of t.detachedLeaveAnimationFns) n.queue.delete(r);
    t.detachedLeaveAnimationFns = void 0
  }
}

function Aw(e, t) {
  for (let [n, r] of t) Sm(e, r.animateFns)
}

function lg(e, t, n, r) {
  let o = e?.[pn]?.enter;
  t !== null && o && o.has(n.index) && Aw(r, o)
}

function cr(e, t, n, r, o, i, s, a) {
  if (o != null) {
    let c, u = !1;
    Pe(o) ? c = o : Xe(o) && (u = !0, o = o[ke]);
    let l = Me(o);
    e === 0 && r !== null ? (lg(a, r, i, n), s == null ? pm(t, r, l) : Is(t, r, l, s || null, !0)) : e === 1 && r !== null ? (lg(a, r, i, n), Is(t, r, l, s || null, !0)) : e === 2 ? dg(a, i, n, d => {
      hm(t, l, u, d)
    }) : e === 3 && dg(a, i, n, () => {
      t.destroyNode(l)
    }), c != null && Hw(t, e, n, c, i, r, s)
  }
}

function xw(e, t) {
  Nm(e, t), t[ke] = null, t[fe] = null
}

function Rw(e, t, n, r, o, i) {
  r[ke] = o, r[fe] = t, Gs(e, r, n, 1, o, i)
}

function Nm(e, t) {
  t[Ke].changeDetectionScheduler?.notify(9), Gs(e, t, t[P], 2, null, null)
}

function Ow(e) {
  let t = e[tr];
  if (!t) return ju(e[w], e);
  for (; t;) {
    let n = null;
    if (Xe(t)) n = t[tr];
    else {
      let r = t[Z];
      r && (n = r)
    }
    if (!n) {
      for (; t && !t[_e] && t !== e;) Xe(t) && ju(t[w], t), t = t[te];
      t === null && (t = e), Xe(t) && ju(t[w], t), n = t && t[_e]
    }
    t = n
  }
}

function td(e, t) {
  let n = e[hn],
    r = n.indexOf(t);
  n.splice(r, 1)
}

function zs(e, t) {
  if (gn(t)) return;
  let n = t[P];
  n.destroyNode && Gs(e, t, n, 3, null, null), Ow(t)
}

function ju(e, t) {
  if (gn(t)) return;
  let n = M(null);
  try {
    t[A] &= -129, t[A] |= 256, t[Ie] && bt(t[Ie]), Pw(e, t), kw(e, t), t[w].type === 1 && t[P].destroy();
    let r = t[At];
    if (r !== null && Pe(t[te])) {
      r !== t[te] && td(r, t);
      let o = t[Je];
      o !== null && o.detachView(e)
    }
    Qu(t)
  } finally {
    M(n)
  }
}

function dg(e, t, n, r) {
  let o = e?.[pn];
  if (o == null || o.leave == null || !o.leave.has(t.index)) return r(!1);
  e && In.add(e), Sm(n, () => {
    if (o.leave && o.leave.has(t.index)) {
      let s = o.leave.get(t.index),
        a = [];
      if (s) {
        for (let c = 0; c < s.animateFns.length; c++) {
          let u = s.animateFns[c],
            {
              promise: l
            } = u();
          a.push(l)
        }
        o.detachedLeaveAnimationFns = void 0
      }
      o.running = Promise.allSettled(a), Fw(e, r)
    } else e && In.delete(e), r(!1)
  }, o)
}

function Fw(e, t) {
  let n = e[pn]?.running;
  if (n) {
    n.then(() => {
      e[pn].running = void 0, In.delete(e), t(!0)
    });
    return
  }
  t(!1)
}

function kw(e, t) {
  let n = e.cleanup,
    r = t[er];
  if (n !== null)
    for (let s = 0; s < n.length - 1; s += 2)
      if (typeof n[s] == "string") {
        let a = n[s + 3];
        a >= 0 ? r[a]() : r[-a].unsubscribe(), s += 2
      } else {
        let a = r[n[s + 1]];
        n[s].call(a)
      } r !== null && (t[er] = null);
  let o = t[dt];
  if (o !== null) {
    t[dt] = null;
    for (let s = 0; s < o.length; s++) {
      let a = o[s];
      a()
    }
  }
  let i = t[gt];
  if (i !== null) {
    t[gt] = null;
    for (let s of i) s.destroy()
  }
}

function Pw(e, t) {
  let n;
  if (e != null && (n = e.destroyHooks) != null)
    for (let r = 0; r < n.length; r += 2) {
      let o = t[n[r]];
      if (!(o instanceof En)) {
        let i = n[r + 1];
        if (Array.isArray(i))
          for (let s = 0; s < i.length; s += 2) {
            let a = o[i[s]],
              c = i[s + 1];
            L(4, a, c);
            try {
              c.call(a)
            } finally {
              L(5, a, c)
            }
          } else {
            L(4, o, i);
            try {
              i.call(o)
            } finally {
              L(5, o, i)
            }
          }
      }
    }
}

function Am(e, t, n) {
  return Lw(e, t.parent, n)
}

function Lw(e, t, n) {
  let r = t;
  for (; r !== null && r.type & 168;) t = r, r = t.parent;
  if (r === null) return n[ke];
  if (mt(r)) {
    let {
      encapsulation: o
    } = e.data[r.directiveStart + r.componentOffset];
    if (o === vt.None || o === vt.Emulated) return null
  }
  return Se(r, n)
}

function xm(e, t, n) {
  return Bw(e, t, n)
}

function jw(e, t, n) {
  return e.type & 40 ? Se(e, n) : null
}

function nd(e, t, n, r) {
  let o = Am(e, r, t),
    i = t[P],
    s = r.parent || t[fe],
    a = xm(s, r, t);
  if (o != null)
    if (Array.isArray(n))
      for (let c = 0; c < n.length; c++) og(i, o, n[c], a, !1);
    else og(i, o, n, a, !1);
  fg !== void 0 && fg(i, r, t, n, o)
}

function so(e, t) {
  if (t !== null) {
    let n = t.type;
    if (n & 3) return Se(t, e);
    if (n & 4) return ll(-1, e[t.index]);
    if (n & 8) {
      let r = t.child;
      if (r !== null) return so(e, r);
      {
        let o = e[t.index];
        return Pe(o) ? ll(-1, o) : Me(o)
      }
    } else {
      if (n & 128) return so(e, t.next);
      if (n & 32) return Ql(t, e)() || Me(e[t.index]);
      {
        let r = Rm(e, t);
        if (r !== null) {
          if (Array.isArray(r)) return r[0];
          let o = St(e[ce]);
          return so(o, r)
        } else return so(e, t.next)
      }
    }
  }
  return null
}

function Rm(e, t) {
  if (t !== null) {
    let r = e[ce][fe],
      o = t.projection;
    return r.projection[o]
  }
  return null
}

function ll(e, t) {
  let n = Z + e + 1;
  if (n < t.length) {
    let r = t[n],
      o = r[w].firstChild;
    if (o !== null) return so(r, o)
  }
  return t[xt]
}

function rd(e, t, n, r, o, i, s) {
  for (; n != null;) {
    let a = r[ht];
    if (n.type === 128) {
      n = n.next;
      continue
    }
    let c = r[n.index],
      u = n.type;
    if (s && t === 0 && (c && dr(Me(c), r), n.flags |= 2), !js(n))
      if (u & 8) rd(e, t, n.child, r, o, i, !1), cr(t, e, a, o, c, n, i, r);
      else if (u & 32) {
      let l = Ql(n, r),
        d;
      for (; d = l();) cr(t, e, a, o, d, n, i, r);
      cr(t, e, a, o, c, n, i, r)
    } else u & 16 ? Om(e, t, r, n, o, i) : cr(t, e, a, o, c, n, i, r);
    n = s ? n.projectionNext : n.next
  }
}

function Gs(e, t, n, r, o, i) {
  rd(n, r, e.firstChild, t, o, i, !1)
}

function Vw(e, t, n) {
  let r = t[P],
    o = Am(e, n, t),
    i = n.parent || t[fe],
    s = xm(i, n, t);
  Om(r, 0, t, n, o, s)
}

function Om(e, t, n, r, o, i) {
  let s = n[ce],
    c = s[fe].projection[r.projection];
  if (Array.isArray(c))
    for (let u = 0; u < c.length; u++) {
      let l = c[u];
      cr(t, e, n[ht], o, l, r, i, n)
    } else {
      let u = c,
        l = s[te];
      qg(r) && (u.flags |= 128), rd(e, t, u, l, o, i, !0)
    }
}

function Hw(e, t, n, r, o, i, s) {
  let a = r[xt],
    c = Me(r);
  a !== c && cr(t, e, n, i, a, o, s);
  for (let u = Z; u < r.length; u++) {
    let l = r[u];
    Gs(l[w], l, e, t, i, a)
  }
}

function Uw(e, t, n, r, o) {
  if (t) o ? e.addClass(n, r) : e.removeClass(n, r);
  else {
    let i = r.indexOf("-") === -1 ? void 0 : Ue.DashCase;
    o == null ? e.removeStyle(n, r, i) : (typeof o == "string" && o.endsWith("!important") && (o = o.slice(0, -10), i |= Ue.Important), e.setStyle(n, r, o, i))
  }
}

function Fm(e, t, n, r, o) {
  let i = je(),
    s = r & 2;
  try {
    Ot(-1), s && t.length > H && Cm(e, t, H, !1), L(s ? 2 : 0, o, n), n(r, o)
  } finally {
    Ot(i), L(s ? 3 : 1, o, n)
  }
}

function Ws(e, t, n) {
  qw(e, t, n), (n.flags & 64) === 64 && Zw(e, t, n)
}

function Do(e, t, n = Se) {
  let r = t.localNames;
  if (r !== null) {
    let o = t.index + 1;
    for (let i = 0; i < r.length; i += 2) {
      let s = r[i + 1],
        a = s === -1 ? n(t, e) : e[s];
      e[o++] = a
    }
  }
}

function $w(e, t, n, r) {
  let i = r.get(tm, em) || n === vt.ShadowDom,
    s = e.selectRootElement(t, i);
  return zw(s), s
}

function zw(e) {
  Gw(e)
}

function Ww(e) {
  return e === "class" ? "className" : e === "for" ? "htmlFor" : e === "formaction" ? "formAction" : e === "innerHtml" ? "innerHTML" : e === "readonly" ? "readOnly" : e === "tabindex" ? "tabIndex" : e
}

function km(e, t, n, r, o, i) {
  let s = t[w];
  if (qs(e, s, t, n, r)) {
    mt(e) && Lm(t, e.index);
    return
  }
  e.type & 3 && (n = Ww(n)), Pm(e, t, n, r, o, i)
}

function Pm(e, t, n, r, o, i) {
  if (e.type & 3) {
    let s = Se(e, t);
    r = i != null ? i(r, e.value || "", n) : r, o.setProperty(s, n, r)
  } else e.type & 12
}

function Lm(e, t) {
  let n = Ne(t, e);
  n[A] & 16 || (n[A] |= 64)
}

function qw(e, t, n) {
  let r = n.directiveStart,
    o = n.directiveEnd;
  mt(n) && yw(t, n, e.data[r + n.componentOffset]), e.firstCreatePass || Ds(n, t);
  let i = n.initialInputs;
  for (let s = r; s < o; s++) {
    let a = e.data[s],
      c = co(t, e, s, n);
    if (dr(c, t), i !== null && Kw(t, s - r, c, a, n, i), Le(a)) {
      let u = Ne(n.index, t);
      u[q] = co(t, e, s, n)
    }
  }
}

function Zw(e, t, n) {
  let r = n.directiveStart,
    o = n.directiveEnd,
    i = n.index,
    s = kh();
  try {
    Ot(i);
    for (let a = r; a < o; a++) {
      let c = e.data[a],
        u = t[a];
      Ji(a), (c.hostBindings !== null || c.hostVars !== 0 || c.hostAttrs !== null) && Yw(c, u)
    }
  } finally {
    Ot(-1), Ji(s)
  }
}

function Yw(e, t) {
  e.hostBindings !== null && e.hostBindings(1, t)
}

function od(e, t) {
  let n = e.directiveRegistry,
    r = null;
  if (n)
    for (let o = 0; o < n.length; o++) {
      let i = n[o];
      Em(t, i.selectors, !1) && (r ??= [], Le(i) ? r.unshift(i) : r.push(i))
    }
  return r
}

function Qw(e, t, n, r, o, i) {
  let s = Se(e, t);
  jm(t[P], s, i, e.value, n, r, o)
}

function jm(e, t, n, r, o, i, s) {
  if (i == null) e.removeAttribute(t, o, n);
  else {
    let a = s == null ? Ee(i) : s(i, r || "", o);
    e.setAttribute(t, o, a, n)
  }
}

function Kw(e, t, n, r, o, i) {
  let s = i[t];
  if (s !== null)
    for (let a = 0; a < s.length; a += 2) {
      let c = s[a],
        u = s[a + 1];
      al(r, n, c, u)
    }
}

function id(e, t, n, r, o) {
  let i = H + n,
    s = t[w],
    a = o(s, t, e, r, n);
  t[i] = a, or(e, !0);
  let c = e.type === 2;
  return c ? (gm(t[P], a, e), (_h() === 0 || nr(e)) && dr(a, t), Mh()) : dr(a, t), ns() && (!c || !js(e)) && nd(s, t, a, e), e
}

function sd(e) {
  let t = e;
  return Cu() ? bu() : (t = t.parent, or(t, !1)), t
}

function Jw(e, t) {
  let n = e[ht];
  if (!n) return;
  let r;
  try {
    r = n.get(Be, null)
  } catch {
    r = null
  }
  r?.(t)
}

function qs(e, t, n, r, o) {
  let i = e.inputs?.[r],
    s = e.hostDirectiveInputs?.[r],
    a = !1;
  if (s)
    for (let c = 0; c < s.length; c += 2) {
      let u = s[c],
        l = s[c + 1],
        d = t.data[u];
      al(d, n[u], l, o), a = !0
    }
  if (i)
    for (let c of i) {
      let u = n[c],
        l = t.data[c];
      al(l, u, r, o), a = !0
    }
  return a
}

function Xw(e, t) {
  let n = Ne(t, e),
    r = n[w];
  eC(r, n);
  let o = n[ke];
  o !== null && n[un] === null && (n[un] = rm(o, n[ht])), L(18), ad(r, n, n[q]), L(19, n[q])
}

function eC(e, t) {
  for (let n = t.length; n < e.blueprint.length; n++) t.push(e.blueprint[n])
}

function ad(e, t, n) {
  es(t);
  try {
    let r = e.viewQuery;
    r !== null && Ju(1, r, n);
    let o = e.template;
    o !== null && Fm(e, t, o, 1, n), e.firstCreatePass && (e.firstCreatePass = !1), t[Je]?.finishViewCreation(e), e.staticContentQueries && om(e, t), e.staticViewQueries && Ju(2, e.viewQuery, n);
    let i = e.components;
    i !== null && tC(t, i)
  } catch (r) {
    throw e.firstCreatePass && (e.incompleteFirstPass = !0, e.firstCreatePass = !1), r
  } finally {
    t[A] &= -5, ts()
  }
}

function tC(e, t) {
  for (let n = 0; n < t.length; n++) Xw(e, t[n])
}

function Eo(e, t, n, r) {
  let o = M(null);
  try {
    let i = t.tView,
      a = e[A] & 4096 ? 4096 : 16,
      c = Zl(e, i, n, a, null, t, null, null, r?.injector ?? null, r?.embeddedViewInjector ?? null, r?.dehydratedView ?? null),
      u = e[t.index];
    c[At] = u;
    let l = e[Je];
    return l !== null && (c[Je] = l.createEmbeddedView(i)), ad(i, c, n), c
  } finally {
    M(o)
  }
}

function fr(e, t) {
  return !t || t.firstChild === null || qg(e)
}

function lo(e, t, n, r, o = !1) {
  for (; n !== null;) {
    if (n.type === 128) {
      n = o ? n.projectionNext : n.next;
      continue
    }
    let i = t[n.index];
    i !== null && r.push(Me(i)), Pe(i) && Bm(i, r);
    let s = n.type;
    if (s & 8) lo(e, t, n.child, r);
    else if (s & 32) {
      let a = Ql(n, t),
        c;
      for (; c = a();) r.push(c)
    } else if (s & 16) {
      let a = Rm(t, n);
      if (Array.isArray(a)) r.push(...a);
      else {
        let c = St(t[ce]);
        lo(c[w], c, a, r, !0)
      }
    }
    n = o ? n.projectionNext : n.next
  }
  return r
}

function Bm(e, t) {
  for (let n = Z; n < e.length; n++) {
    let r = e[n],
      o = r[w].firstChild;
    o !== null && lo(r[w], r, o, t)
  }
  e[xt] !== e[ke] && t.push(e[xt])
}

function Vm(e) {
  if (e[fn] !== null) {
    for (let t of e[fn]) t.impl.addSequence(t);
    e[fn].length = 0
  }
}

function nC(e) {
  return e[Ie] ?? rC(e)
}

function rC(e) {
  let t = Hm.pop() ?? Object.create(iC);
  return t.lView = e, t
}

function oC(e) {
  e.lView[Ie] !== e && (e.lView = null, Hm.push(e))
}

function sC(e) {
  let t = e[Ie] ?? Object.create(aC);
  return t.lView = e, t
}

function Um(e) {
  return e.type !== 2
}

function $m(e) {
  if (e[gt] === null) return;
  let t = !0;
  for (; t;) {
    let n = !1;
    for (let r of e[gt]) r.dirty && (n = !0, r.zone === null || Zone.current === r.zone ? r.run() : r.zone.run(() => r.run()));
    t = n && !!(e[A] & 8192)
  }
}

function zm(e, t = 0) {
  let r = e[Ke].rendererFactory,
    o = !1;
  o || r.begin?.();
  try {
    uC(e, t)
  } finally {
    o || r.end?.()
  }
}

function uC(e, t) {
  let n = Tu();
  try {
    ir(!0), dl(e, t);
    let r = 0;
    for (; Xr(e);) {
      if (r === cC) throw new v(103, !1);
      r++, dl(e, 1)
    }
  } finally {
    ir(n)
  }
}

function lC(e, t, n, r) {
  if (gn(t)) return;
  let o = t[A],
    i = !1,
    s = !1;
  es(t);
  let a = !0,
    c = null,
    u = null;
  i || (Um(e) ? (u = nC(t), c = Ct(u)) : qo() === null ? (a = !1, u = sC(t), c = Ct(u)) : t[Ie] && (bt(t[Ie]), t[Ie] = null));
  try {
    pu(t), Rh(e.bindingStartIndex), n !== null && Fm(e, t, n, 2, r);
    let l = (o & 3) === 3;
    if (!i)
      if (l) {
        let f = e.preOrderCheckHooks;
        f !== null && ls(t, f, null)
      } else {
        let f = e.preOrderHooks;
        f !== null && ds(t, f, 0, null), Pu(t, 0)
      } if (s || dC(t), $m(t), Gm(t, 0), e.contentQueries !== null && om(e, t), !i)
      if (l) {
        let f = e.contentCheckHooks;
        f !== null && ls(t, f)
      } else {
        let f = e.contentHooks;
        f !== null && ds(t, f, 1), Pu(t, 1)
      } pC(e, t);
    let d = e.components;
    d !== null && qm(t, d, 0);
    let p = e.viewQuery;
    if (p !== null && Ju(2, p, r), !i)
      if (l) {
        let f = e.viewCheckHooks;
        f !== null && ls(t, f)
      } else {
        let f = e.viewHooks;
        f !== null && ds(t, f, 2), Pu(t, 2)
      } if (e.firstUpdatePass === !0 && (e.firstUpdatePass = !1), t[qi]) {
      for (let f of t[qi]) f();
      t[qi] = null
    }
    i || (Vm(t), t[A] &= -73)
  } catch (l) {
    throw i || Rt(t), l
  } finally {
    u !== null && (zt(u, c), a && oC(u)), ts()
  }
}

function Gm(e, t) {
  for (let n = Yg(e); n !== null; n = Qg(n))
    for (let r = Z; r < n.length; r++) {
      let o = n[r];
      Wm(o, t)
    }
}

function dC(e) {
  for (let t = Yg(e); t !== null; t = Qg(t)) {
    if (!(t[A] & 2)) continue;
    let n = t[hn];
    for (let r = 0; r < n.length; r++) {
      let o = n[r];
      hu(o)
    }
  }
}

function fC(e, t, n) {
  L(18);
  let r = Ne(t, e);
  Wm(r, n), L(19, r[q])
}

function Wm(e, t) {
  Yi(e) && dl(e, t)
}

function dl(e, t) {
  let r = e[w],
    o = e[A],
    i = e[Ie],
    s = !!(t === 0 && o & 16);
  if (s ||= !!(o & 64 && t === 0), s ||= !!(o & 1024), s ||= !!(i?.dirty && Gt(i)), s ||= !1, i && (i.dirty = !1), e[A] &= -9217, s) lC(r, e, r.template, e[q]);
  else if (o & 8192) {
    let a = M(null);
    try {
      $m(e), Gm(e, 1);
      let c = r.components;
      c !== null && qm(e, c, 1), Vm(e)
    } finally {
      M(a)
    }
  }
}

function qm(e, t, n) {
  for (let r = 0; r < t.length; r++) fC(e, t[r], n)
}

function pC(e, t) {
  let n = e.hostBindingOpCodes;
  if (n !== null) try {
    for (let r = 0; r < n.length; r++) {
      let o = n[r];
      if (o < 0) Ot(~o);
      else {
        let i = o,
          s = n[++r],
          a = n[++r];
        Fh(s, i);
        let c = t[i];
        L(24, c), a(2, c), L(25, c)
      }
    }
  } finally {
    Ot(-1)
  }
}

function cd(e, t) {
  let n = Tu() ? 64 : 1088;
  for (e[Ke].changeDetectionScheduler?.notify(t); e;) {
    e[A] |= n;
    let r = St(e);
    if (rr(e) && !r) return e;
    e = r
  }
  return null
}

function Zm(e, t, n, r) {
  return [e, !0, 0, t, null, r, null, n, null, null]
}

function Ym(e, t) {
  let n = Z + t;
  if (n < e.length) return e[n]
}

function Io(e, t, n, r = !0) {
  let o = t[w];
  if (hC(o, t, e, n), r) {
    let s = ll(n, e),
      a = t[P],
      c = a.parentNode(e[xt]);
    c !== null && Rw(o, e[fe], a, t, c, s)
  }
  let i = t[un];
  i !== null && i.firstChild !== null && (i.firstChild = null)
}

function Qm(e, t) {
  let n = fo(e, t);
  return n !== void 0 && zs(n[w], n), n
}

function fo(e, t) {
  if (e.length <= Z) return;
  let n = Z + t,
    r = e[n];
  if (r) {
    let o = r[At];
    o !== null && o !== e && td(o, r), t > 0 && (e[n - 1][_e] = r[_e]);
    let i = Zr(e, Z + t);
    xw(r[w], r);
    let s = i[Je];
    s !== null && s.detachView(i[w]), r[te] = null, r[_e] = null, r[A] &= -129
  }
  return r
}

function hC(e, t, n, r) {
  let o = Z + r,
    i = n.length;
  r > 0 && (n[o - 1][_e] = t), r < i - Z ? (t[_e] = n[o], Jc(n, Z + r, t)) : (n.push(t), t[_e] = null), t[te] = n;
  let s = t[At];
  s !== null && n !== s && Km(s, t);
  let a = t[Je];
  a !== null && a.insertView(e), Qi(t), t[A] |= 128
}

function Km(e, t) {
  let n = e[hn],
    r = t[te];
  if (Xe(r)) e[A] |= 2;
  else {
    let o = r[te][ce];
    t[ce] !== o && (e[A] |= 2)
  }
  n === null ? e[hn] = [t] : n.push(t)
}

function gC() {
  return Zs(J(), E())
}

function Zs(e, t) {
  return e.type & 4 ? new nt(t, e, mr(e, t)) : null
}

function yr(e, t, n, r, o) {
  let i = e.data[t];
  if (i === null) i = mC(e, t, n, r, o), Oh() && (i.flags |= 32);
  else if (i.type & 64) {
    i.type = n, i.value = r, i.attrs = o;
    let s = Ah();
    i.injectorIndex = s === null ? -1 : s.injectorIndex
  }
  return or(i, !0), i
}

function mC(e, t, n, r, o) {
  let i = wu(),
    s = Cu(),
    a = s ? i : i && i.parent,
    c = e.data[t] = vC(e, a, n, t, r, o);
  return yC(e, c, i, s), c
}

function yC(e, t, n, r) {
  e.firstChild === null && (e.firstChild = t), n !== null && (r ? n.child == null && t.parent !== null && (n.child = t) : n.next === null && (n.next = t, t.prev = n))
}

function vC(e, t, n, r, o, i) {
  let s = t ? t.injectorIndex : -1,
    a = 0;
  return Du() && (a |= 128), {
    type: n,
    index: r,
    insertBeforeIndex: null,
    injectorIndex: s,
    directiveStart: -1,
    directiveEnd: -1,
    directiveStylingLast: -1,
    componentOffset: -1,
    propertyBindings: null,
    flags: a,
    providerIndexes: 0,
    value: o,
    attrs: i,
    mergedAttrs: null,
    localNames: null,
    initialInputs: null,
    inputs: null,
    hostDirectiveInputs: null,
    outputs: null,
    hostDirectiveOutputs: null,
    directiveToIndex: null,
    tView: null,
    next: null,
    prev: null,
    projectionNext: null,
    child: null,
    parent: t,
    projection: null,
    styles: null,
    stylesWithoutHost: null,
    residualStyles: void 0,
    classes: null,
    classesWithoutHost: null,
    residualClasses: void 0,
    classBindings: 0,
    styleBindings: 0
  }
}

function DC(e) {
  let t = e[cu] ?? [],
    r = e[te][P],
    o = [];
  for (let i of t) i.data[Xg] !== void 0 ? o.push(i) : EC(i, r);
  e[cu] = o
}

function EC(e, t) {
  let n = 0,
    r = e.firstChild;
  if (r) {
    let o = e.data[Jg];
    for (; n < o;) {
      let i = r.nextSibling;
      hm(t, r, !1), r = i, n++
    }
  }
}

function bs(e, t) {
  return IC(e, t)
}

function Jm(e, t, n) {
  return wC(e, t, n)
}

function CC() {
  let e = E(),
    t = J(),
    n = Ne(t.index, e);
  return (Xe(n) ? n : e)[P]
}

function Ts(e, t, n) {
  let r = n ? e.styles : null,
    o = n ? e.classes : null,
    i = 0;
  if (t !== null)
    for (let s = 0; s < t.length; s++) {
      let a = t[s];
      if (typeof a == "number") i = a;
      else if (i == 1) o = Bi(o, a);
      else if (i == 2) {
        let c = a,
          u = t[++s];
        r = Bi(r, c + ": " + u + ";")
      }
    }
  n ? e.styles = r : e.stylesWithoutHost = r, n ? e.classes = o : e.classesWithoutHost = o
}

function U(e, t = 0) {
  let n = E();
  if (n === null) return C(e, t);
  let r = J();
  return $g(r, n, ee(e), t)
}

function bC() {
  let e = "invalid";
  throw new Error(e)
}

function ty(e, t, n, r, o) {
  let i = r === null ? null : {
      "": -1
    },
    s = o(e, n);
  if (s !== null) {
    let a = s,
      c = null,
      u = null;
    for (let l of s)
      if (l.resolveHostDirectives !== null) {
        [a, c, u] = l.resolveHostDirectives(s);
        break
      } MC(e, t, n, a, i, c, u)
  }
  i !== null && r !== null && TC(n, r, i)
}

function TC(e, t, n) {
  let r = e.localNames = [];
  for (let o = 0; o < t.length; o += 2) {
    let i = n[t[o + 1]];
    if (i == null) throw new v(-301, !1);
    r.push(t[o], i)
  }
}

function _C(e, t, n) {
  t.componentOffset = n, (e.components ??= []).push(t.index)
}

function MC(e, t, n, r, o, i, s) {
  let a = r.length,
    c = !1;
  for (let p = 0; p < a; p++) {
    let f = r[p];
    !c && Le(f) && (c = !0, _C(e, n, p)), Zu(Ds(n, t), e, f.type)
  }
  OC(n, e.data.length, a);
  for (let p = 0; p < a; p++) {
    let f = r[p];
    f.providersResolver && f.providersResolver(f)
  }
  let u = !1,
    l = !1,
    d = wm(e, t, a, null);
  a > 0 && (n.directiveToIndex = new Map);
  for (let p = 0; p < a; p++) {
    let f = r[p];
    if (n.mergedAttrs = lr(n.mergedAttrs, f.hostAttrs), NC(e, n, t, d, f), RC(d, f, o), s !== null && s.has(f)) {
      let [I, D] = s.get(f);
      n.directiveToIndex.set(f.type, [d, I + n.directiveStart, D + n.directiveStart])
    } else(i === null || !i.has(f)) && n.directiveToIndex.set(f.type, d);
    f.contentQueries !== null && (n.flags |= 4), (f.hostBindings !== null || f.hostAttrs !== null || f.hostVars !== 0) && (n.flags |= 64);
    let g = f.type.prototype;
    !u && (g.ngOnChanges || g.ngOnInit || g.ngDoCheck) && ((e.preOrderHooks ??= []).push(n.index), u = !0), !l && (g.ngOnChanges || g.ngDoCheck) && ((e.preOrderCheckHooks ??= []).push(n.index), l = !0), d++
  }
  SC(e, n, i)
}

function SC(e, t, n) {
  for (let r = t.directiveStart; r < t.directiveEnd; r++) {
    let o = e.data[r];
    if (n === null || !n.has(o)) pg(0, t, o, r), pg(1, t, o, r), gg(t, r, !1);
    else {
      let i = n.get(o);
      hg(0, t, i, r), hg(1, t, i, r), gg(t, r, !0)
    }
  }
}

function pg(e, t, n, r) {
  let o = e === 0 ? n.inputs : n.outputs;
  for (let i in o)
    if (o.hasOwnProperty(i)) {
      let s;
      e === 0 ? s = t.inputs ??= {} : s = t.outputs ??= {}, s[i] ??= [], s[i].push(r), ny(t, i)
    }
}

function hg(e, t, n, r) {
  let o = e === 0 ? n.inputs : n.outputs;
  for (let i in o)
    if (o.hasOwnProperty(i)) {
      let s = o[i],
        a;
      e === 0 ? a = t.hostDirectiveInputs ??= {} : a = t.hostDirectiveOutputs ??= {}, a[s] ??= [], a[s].push(r, i), ny(t, s)
    }
}

function ny(e, t) {
  t === "class" ? e.flags |= 8 : t === "style" && (e.flags |= 16)
}

function gg(e, t, n) {
  let {
    attrs: r,
    inputs: o,
    hostDirectiveInputs: i
  } = e;
  if (r === null || !n && o === null || n && i === null || Wl(e)) {
    e.initialInputs ??= [], e.initialInputs.push(null);
    return
  }
  let s = null,
    a = 0;
  for (; a < r.length;) {
    let c = r[a];
    if (c === 0) {
      a += 4;
      continue
    } else if (c === 5) {
      a += 2;
      continue
    } else if (typeof c == "number") break;
    if (!n && o.hasOwnProperty(c)) {
      let u = o[c];
      for (let l of u)
        if (l === t) {
          s ??= [], s.push(c, r[a + 1]);
          break
        }
    } else if (n && i.hasOwnProperty(c)) {
      let u = i[c];
      for (let l = 0; l < u.length; l += 2)
        if (u[l] === t) {
          s ??= [], s.push(u[l + 1], r[a + 1]);
          break
        }
    }
    a += 2
  }
  e.initialInputs ??= [], e.initialInputs.push(s)
}

function NC(e, t, n, r, o) {
  e.data[r] = o;
  let i = o.factory || (o.factory = Mt(o.type, !0)),
    s = new En(i, Le(o), U, null);
  e.blueprint[r] = s, n[r] = s, AC(e, t, r, wm(e, n, o.hostVars, re), o)
}

function AC(e, t, n, r, o) {
  let i = o.hostBindings;
  if (i) {
    let s = e.hostBindingOpCodes;
    s === null && (s = e.hostBindingOpCodes = []);
    let a = ~t.index;
    xC(s) != a && s.push(a), s.push(n, r, i)
  }
}

function xC(e) {
  let t = e.length;
  for (; t > 0;) {
    let n = e[--t];
    if (typeof n == "number" && n < 0) return n
  }
  return 0
}

function RC(e, t, n) {
  if (n) {
    if (t.exportAs)
      for (let r = 0; r < t.exportAs.length; r++) n[t.exportAs[r]] = e;
    Le(t) && (n[""] = e)
  }
}

function OC(e, t, n) {
  e.flags |= 1, e.directiveStart = t, e.directiveEnd = t + n, e.providerIndexes = t
}

function ud(e, t, n, r, o, i, s, a) {
  let c = t[w],
    u = c.consts,
    l = we(u, s),
    d = yr(c, e, n, r, l);
  return i && ty(c, t, d, we(u, a), o), d.mergedAttrs = lr(d.mergedAttrs, d.attrs), d.attrs !== null && Ts(d, d.attrs, !1), d.mergedAttrs !== null && Ts(d, d.mergedAttrs, !0), c.queries !== null && c.queries.elementStart(c, d), d
}

function ld(e, t) {
  Fg(e, t), uu(t) && e.queries.elementEnd(t)
}

function FC(e, t, n, r, o, i) {
  let s = t.consts,
    a = we(s, o),
    c = yr(t, e, n, r, a);
  if (c.mergedAttrs = lr(c.mergedAttrs, c.attrs), i != null) {
    let u = we(s, i);
    c.localNames = [];
    for (let l = 0; l < u.length; l += 2) c.localNames.push(u[l], -1)
  }
  return c.attrs !== null && Ts(c, c.attrs, !1), c.mergedAttrs !== null && Ts(c, c.mergedAttrs, !0), t.queries !== null && t.queries.elementStart(t, c), c
}

function dd(e) {
  return Qs(e) ? Array.isArray(e) || !(e instanceof Map) && Symbol.iterator in e : !1
}

function ry(e, t) {
  if (Array.isArray(e))
    for (let n = 0; n < e.length; n++) t(e[n]);
  else {
    let n = e[Symbol.iterator](),
      r;
    for (; !(r = n.next()).done;) t(r.value)
  }
}

function Qs(e) {
  return e !== null && (typeof e == "function" || typeof e == "object")
}

function Ks(e, t, n) {
  return e[t] = n
}

function kC(e, t) {
  return e[t]
}

function pe(e, t, n) {
  if (n === re) return !1;
  let r = e[t];
  return Object.is(r, n) ? !1 : (e[t] = n, !0)
}

function po(e, t, n, r) {
  let o = pe(e, t, n);
  return pe(e, t + 1, r) || o
}

function PC(e, t, n, r, o) {
  let i = po(e, t, n, r);
  return pe(e, t + 2, o) || i
}

function LC(e, t, n, r, o, i) {
  let s = po(e, t, n, r);
  return po(e, t + 2, o, i) || s
}

function hs(e, t, n) {
  return function r(o) {
    let i = mt(e) ? Ne(e.index, t) : t;
    cd(i, 5);
    let s = t[q],
      a = mg(t, s, n, o),
      c = r.__ngNextListenerFn__;
    for (; c;) a = mg(t, s, c, o) && a, c = c.__ngNextListenerFn__;
    return a
  }
}

function mg(e, t, n, r) {
  let o = M(null);
  try {
    return L(6, t, n), n(r) !== !1
  } catch (i) {
    return Jw(e, i), !1
  } finally {
    L(7, t, n), M(o)
  }
}

function oy(e, t, n, r, o, i, s, a) {
  let c = nr(e),
    u = !1,
    l = null;
  if (!r && c && (l = BC(t, n, i, e.index)), l !== null) {
    let d = l.__ngLastListenerFn__ || l;
    d.__ngNextListenerFn__ = s, l.__ngLastListenerFn__ = s, u = !0
  } else {
    let d = Se(e, n),
      p = r ? r(d) : d;
    CI(n, p, i, a);
    let f = o.listen(p, i, a);
    if (!jC(i)) {
      let g = r ? I => r(Me(I[e.index])) : e.index;
      iy(g, t, n, i, a, f, !1)
    }
  }
  return u
}

function jC(e) {
  return e.startsWith("animation") || e.startsWith("transition")
}

function BC(e, t, n, r) {
  let o = e.cleanup;
  if (o != null)
    for (let i = 0; i < o.length - 1; i += 2) {
      let s = o[i];
      if (s === n && o[i + 1] === r) {
        let a = t[er],
          c = o[i + 2];
        return a && a.length > c ? a[c] : null
      }
      typeof s == "string" && (i += 2)
    }
  return null
}

function iy(e, t, n, r, o, i, s) {
  let a = t.firstCreatePass ? yu(t) : null,
    c = mu(n),
    u = c.length;
  c.push(o, i), a && a.push(r, e, u, (u + 1) * (s ? -1 : 1))
}

function yg(e, t, n, r, o, i) {
  let s = t[n],
    a = t[w],
    u = a.data[n].outputs[r],
    d = s[u].subscribe(i);
  iy(e.index, a, t, o, i, d, !0)
}

function VC(e) {
  return Object.keys(e).map(t => {
    let [n, r, o] = e[t], i = {
      propName: n,
      templateName: t,
      isSignal: (r & Hs.SignalBased) !== 0
    };
    return o && (i.transform = o), i
  })
}

function HC(e) {
  return Object.keys(e).map(t => ({
    propName: e[t],
    templateName: t
  }))
}

function UC(e, t, n) {
  let r = t instanceof ye ? t : t?.injector;
  return r && e.getStandaloneInjector !== null && (r = e.getStandaloneInjector(r) || r), r ? new pl(n, r) : n
}

function $C(e) {
  let t = e.get(wn, null);
  if (t === null) throw new v(407, !1);
  let n = e.get(ey, null),
    r = e.get(Te, null);
  return {
    rendererFactory: t,
    sanitizer: n,
    changeDetectionScheduler: r,
    ngReflect: !1
  }
}

function zC(e, t) {
  let n = sy(e);
  return fm(t, n, n === "svg" ? lu : n === "math" ? Eh : null)
}

function sy(e) {
  return (e.selectors[0][0] || "div").toLowerCase()
}

function GC(e, t, n, r) {
  let o = e ? ["ng-version", "20.3.18"] : hw(t.selectors[0]),
    i = null,
    s = null,
    a = 0;
  if (n)
    for (let l of n) a += l[hl].requiredVars, l.create && (l.targetIdx = 0, (i ??= []).push(l)), l.update && (l.targetIdx = 0, (s ??= []).push(l));
  if (r)
    for (let l = 0; l < r.length; l++) {
      let d = r[l];
      if (typeof d != "function")
        for (let p of d.bindings) {
          a += p[hl].requiredVars;
          let f = l + 1;
          p.create && (p.targetIdx = f, (i ??= []).push(p)), p.update && (p.targetIdx = f, (s ??= []).push(p))
        }
    }
  let c = [t];
  if (r)
    for (let l of r) {
      let d = typeof l == "function" ? l : l.type,
        p = Wi(d);
      c.push(p)
    }
  return ql(0, null, WC(i, s), 1, a, c, null, null, null, [o], null)
}

function WC(e, t) {
  return !e && !t ? null : n => {
    if (n & 1 && e)
      for (let r of e) r.create();
    if (n & 2 && t)
      for (let r of t) r.update()
  }
}

function vg(e) {
  let t = e[hl].kind;
  return t === "input" || t === "twoWay"
}

function qC(e, t, n) {
  let r = e.projection = [];
  for (let o = 0; o < t.length; o++) {
    let i = n[o];
    r.push(i != null && i.length ? Array.from(i) : null)
  }
}

function ZC() {
  let e = J();
  return cy(e, E())
}

function Dg(e) {
  return e[Kr]
}

function Bu(e) {
  return e[Kr] || (e[Kr] = [])
}

function cy(e, t) {
  let n, r = t[e.index];
  return Pe(r) ? n = r : (n = Zm(r, t, null, e), t[e.index] = n, Yl(t, n)), KC(n, t, e, r), new ay(n, e, t)
}

function QC(e, t) {
  let n = e[P],
    r = n.createComment(""),
    o = Se(t, e),
    i = n.parentNode(o);
  return Is(n, i, r, n.nextSibling(o), !1), r
}

function XC(e, t, n) {
  return JC(e, t, n)
}

function eb(e, t, n, r) {
  if (e[xt]) return;
  let o;
  n.type & 8 ? o = Me(r) : o = QC(t, n), e[xt] = o
}

function tb(e, t) {
  let n = e.localNames;
  if (n !== null) {
    for (let r = 0; r < n.length; r += 2)
      if (n[r] === t) return n[r + 1]
  }
  return null
}

function nb(e, t) {
  return e.type & 11 ? mr(e, t) : e.type & 4 ? Zs(e, t) : null
}

function rb(e, t, n, r) {
  return n === -1 ? nb(t, e) : n === -2 ? ob(e, t, r) : co(e, e[w], n, t)
}

function ob(e, t, n) {
  if (n === Et) return mr(t, e);
  if (n === nt) return Zs(t, e);
  if (n === ot) return cy(t, e)
}

function uy(e, t, n, r) {
  let o = t[Je].queries[r];
  if (o.matches === null) {
    let i = e.data,
      s = n.matches,
      a = [];
    for (let c = 0; s !== null && c < s.length; c += 2) {
      let u = s[c];
      if (u < 0) a.push(null);
      else {
        let l = i[u];
        a.push(rb(t, l, s[c + 1], n.metadata.read))
      }
    }
    o.matches = a
  }
  return o.matches
}

function Dl(e, t, n, r) {
  let o = e.queries.getByIndex(n),
    i = o.matches;
  if (i !== null) {
    let s = uy(e, t, o, n);
    for (let a = 0; a < i.length; a += 2) {
      let c = i[a];
      if (c > 0) r.push(s[a / 2]);
      else {
        let u = i[a + 1],
          l = t[-c];
        for (let d = Z; d < l.length; d++) {
          let p = l[d];
          p[At] === p[te] && Dl(p[w], p, u, r)
        }
        if (l[hn] !== null) {
          let d = l[hn];
          for (let p = 0; p < d.length; p++) {
            let f = d[p];
            Dl(f[w], f, u, r)
          }
        }
      }
    }
  }
  return r
}

function fd(e, t) {
  return e[Je].queries[t].queryList
}

function ly(e, t, n) {
  let r = new Es((n & 4) === 4);
  return Th(e, t, r, r.destroy), (t[Je] ??= new ml).queries.push(new gl(r)) - 1
}

function dy(e, t, n) {
  let r = B();
  return r.firstCreatePass && (py(r, new Ss(e, t, n), -1), (t & 2) === 2 && (r.staticViewQueries = !0)), ly(r, E(), t)
}

function fy(e, t, n, r) {
  let o = B();
  if (o.firstCreatePass) {
    let i = J();
    py(o, new Ss(t, n, r), i.index), sb(o, e), (n & 2) === 2 && (o.staticContentQueries = !0)
  }
  return ly(o, E(), n)
}

function ib(e) {
  return e.split(",").map(t => t.trim())
}

function py(e, t, n) {
  e.queries === null && (e.queries = new yl), e.queries.track(new vl(t, n))
}

function sb(e, t) {
  let n = e.contentQueries || (e.contentQueries = []),
    r = n.length ? n[n.length - 1] : -1;
  t !== r && n.push(e.queries.length - 1, t)
}

function pd(e, t) {
  return e.queries.getByIndex(t)
}

function hy(e, t) {
  let n = e[w],
    r = pd(n, t);
  return r.crossesNgTemplate ? Dl(n, e, t, []) : uy(n, e, r, t)
}

function gy(e, t, n) {
  let r, o = Mr(() => {
    r._dirtyCounter();
    let i = ab(r, e);
    if (t && i === void 0) throw new v(-951, !1);
    return i
  });
  return r = o[X], r._dirtyCounter = rs(0), r._flatValue = void 0, o
}

function hd(e) {
  return gy(!0, !1, e)
}

function gd(e) {
  return gy(!0, !0, e)
}

function my(e, t) {
  let n = e[X];
  n._lView = E(), n._queryIndex = t, n._queryList = fd(n._lView, t), n._queryList.onDirty(() => n._dirtyCounter.update(r => r + 1))
}

function ab(e, t) {
  let n = e._lView,
    r = e._queryIndex;
  if (n === void 0 || r === void 0 || n[A] & 4) return t ? void 0 : ae;
  let o = fd(n, r),
    i = hy(n, r);
  return o.reset(i, Wg), t ? o.first : o._changesDetected || e._flatValue === void 0 ? e._flatValue = o.toArray() : e._flatValue
}

function vy(e, t, n = null) {
  return new ho({
    providers: e,
    parent: t,
    debugName: n,
    runEnvironmentInitializers: !0
  }).injector
}

function ub(e) {
  return gr(() => {
    let t = Dy(e),
      n = G(V({}, t), {
        decls: e.decls,
        vars: e.vars,
        template: e.template,
        consts: e.consts || null,
        ngContentSelectors: e.ngContentSelectors,
        onPush: e.changeDetection === Pl.OnPush,
        directiveDefs: null,
        pipeDefs: null,
        dependencies: t.standalone && e.dependencies || null,
        getStandaloneInjector: t.standalone ? o => o.get(cb).getOrCreateStandaloneInjector(n) : null,
        getExternalStyles: null,
        signals: e.signals ?? !1,
        data: e.data || {},
        encapsulation: e.encapsulation || vt.Emulated,
        styles: e.styles || ae,
        _: null,
        schemas: e.schemas || null,
        tView: null,
        id: ""
      });
    t.standalone && jt("NgStandalone"), Ey(n);
    let r = e.dependencies;
    return n.directiveDefs = Eg(r, lb), n.pipeDefs = Eg(r, hh), n.id = pb(n), n
  })
}

function lb(e) {
  return Qe(e) || Wi(e)
}

function Bt(e) {
  return gr(() => ({
    type: e.type,
    bootstrap: e.bootstrap || ae,
    declarations: e.declarations || ae,
    imports: e.imports || ae,
    exports: e.exports || ae,
    transitiveCompileScopes: null,
    schemas: e.schemas || null,
    id: e.id || null
  }))
}

function db(e, t) {
  if (e == null) return Fe;
  let n = {};
  for (let r in e)
    if (e.hasOwnProperty(r)) {
      let o = e[r],
        i, s, a, c;
      Array.isArray(o) ? (a = o[0], i = o[1], s = o[2] ?? i, c = o[3] || null) : (i = o, s = o, a = Hs.None, c = null), n[i] = [r, a, c], t[i] = s
    } return n
}

function fb(e) {
  if (e == null) return Fe;
  let t = {};
  for (let n in e) e.hasOwnProperty(n) && (t[e[n]] = n);
  return t
}

function it(e) {
  return gr(() => {
    let t = Dy(e);
    return Ey(t), t
  })
}

function bo(e) {
  return {
    type: e.type,
    name: e.name,
    factory: null,
    pure: e.pure !== !1,
    standalone: e.standalone ?? !0,
    onDestroy: e.type.prototype.ngOnDestroy || null
  }
}

function Dy(e) {
  let t = {};
  return {
    type: e.type,
    providersResolver: null,
    factory: null,
    hostBindings: e.hostBindings || null,
    hostVars: e.hostVars || 0,
    hostAttrs: e.hostAttrs || null,
    contentQueries: e.contentQueries || null,
    declaredInputs: t,
    inputConfig: e.inputs || Fe,
    exportAs: e.exportAs || null,
    standalone: e.standalone ?? !0,
    signals: e.signals === !0,
    selectors: e.selectors || ae,
    viewQuery: e.viewQuery || null,
    features: e.features || null,
    setInput: null,
    resolveHostDirectives: null,
    hostDirectives: null,
    inputs: db(e.inputs, t),
    outputs: fb(e.outputs),
    debugInfo: null
  }
}

function Ey(e) {
  e.features?.forEach(t => t(e))
}

function Eg(e, t) {
  return e ? () => {
    let n = typeof e == "function" ? e() : e,
      r = [];
    for (let o of n) {
      let i = t(o);
      i !== null && r.push(i)
    }
    return r
  } : null
}

function pb(e) {
  let t = 0,
    n = typeof e.consts == "function" ? "" : e.consts,
    r = [e.selectors, e.ngContentSelectors, e.hostVars, e.hostAttrs, n, e.vars, e.decls, e.encapsulation, e.standalone, e.signals, e.exportAs, JSON.stringify(e.inputs), JSON.stringify(e.outputs), Object.getOwnPropertyNames(e.type.prototype), !!e.contentQueries, !!e.viewQuery];
  for (let i of r.join("|")) t = Math.imul(31, t) + i.charCodeAt(0) << 0;
  return t += 2147483648, "c" + t
}

function hb(e) {
  return Object.getPrototypeOf(e.prototype).constructor
}

function Iy(e) {
  let t = hb(e.type),
    n = !0,
    r = [e];
  for (; t;) {
    let o;
    if (Le(e)) o = t.\u0275cmp || t.\u0275dir;
    else {
      if (t.\u0275cmp) throw new v(903, !1);
      o = t.\u0275dir
    }
    if (o) {
      if (n) {
        r.push(o);
        let s = e;
        s.inputs = Vu(e.inputs), s.declaredInputs = Vu(e.declaredInputs), s.outputs = Vu(e.outputs);
        let a = o.hostBindings;
        a && Db(e, a);
        let c = o.viewQuery,
          u = o.contentQueries;
        if (c && yb(e, c), u && vb(e, u), gb(e, o), ih(e.outputs, o.outputs), Le(o) && o.data.animation) {
          let l = e.data;
          l.animation = (l.animation || []).concat(o.data.animation)
        }
      }
      let i = o.features;
      if (i)
        for (let s = 0; s < i.length; s++) {
          let a = i[s];
          a && a.ngInherit && a(e), a === Iy && (n = !1)
        }
    }
    t = Object.getPrototypeOf(t)
  }
  mb(r)
}

function gb(e, t) {
  for (let n in t.inputs) {
    if (!t.inputs.hasOwnProperty(n) || e.inputs.hasOwnProperty(n)) continue;
    let r = t.inputs[n];
    r !== void 0 && (e.inputs[n] = r, e.declaredInputs[n] = t.declaredInputs[n])
  }
}

function mb(e) {
  let t = 0,
    n = null;
  for (let r = e.length - 1; r >= 0; r--) {
    let o = e[r];
    o.hostVars = t += o.hostVars, o.hostAttrs = lr(o.hostAttrs, n = lr(n, o.hostAttrs))
  }
}

function Vu(e) {
  return e === Fe ? {} : e === ae ? [] : e
}

function yb(e, t) {
  let n = e.viewQuery;
  n ? e.viewQuery = (r, o) => {
    t(r, o), n(r, o)
  } : e.viewQuery = t
}

function vb(e, t) {
  let n = e.contentQueries;
  n ? e.contentQueries = (r, o, i) => {
    t(r, o, i), n(r, o, i)
  } : e.contentQueries = t
}

function Db(e, t) {
  let n = e.hostBindings;
  n ? e.hostBindings = (r, o) => {
    t(r, o), n(r, o)
  } : e.hostBindings = t
}

function Eb(e) {
  let t = n => {
    let r = Array.isArray(e);
    n.hostDirectives === null ? (n.resolveHostDirectives = Ib, n.hostDirectives = r ? e.map(El) : [e]) : r ? n.hostDirectives.unshift(...e.map(El)) : n.hostDirectives.unshift(e)
  };
  return t.ngInherit = !0, t
}

function Ib(e) {
  let t = [],
    n = !1,
    r = null,
    o = null;
  for (let i = 0; i < e.length; i++) {
    let s = e[i];
    if (s.hostDirectives !== null) {
      let a = t.length;
      r ??= new Map, o ??= new Map, wy(s, t, r), o.set(s, [a, t.length - 1])
    }
    i === 0 && Le(s) && (n = !0, t.push(s))
  }
  for (let i = n ? 1 : 0; i < e.length; i++) t.push(e[i]);
  return [t, r, o]
}

function wy(e, t, n) {
  if (e.hostDirectives !== null)
    for (let r of e.hostDirectives)
      if (typeof r == "function") {
        let o = r();
        for (let i of o) Ig(El(i), t, n)
      } else Ig(r, t, n)
}

function Ig(e, t, n) {
  let r = Wi(e.directive);
  wb(r.declaredInputs, e.inputs), wy(r, t, n), n.set(r, e), t.push(r)
}

function El(e) {
  return typeof e == "function" ? {
    directive: ee(e),
    inputs: Fe,
    outputs: Fe
  } : {
    directive: ee(e.directive),
    inputs: wg(e.inputs),
    outputs: wg(e.outputs)
  }
}

function wg(e) {
  if (e === void 0 || e.length === 0) return Fe;
  let t = {};
  for (let n = 0; n < e.length; n += 2) t[e[n]] = e[n + 1];
  return t
}

function wb(e, t) {
  for (let n in t)
    if (t.hasOwnProperty(n)) {
      let r = t[n],
        o = e[n];
      e[r] = o
    }
}

function Cy(e, t, n, r, o, i, s, a) {
  if (n.firstCreatePass) {
    e.mergedAttrs = lr(e.mergedAttrs, e.attrs);
    let l = e.tView = ql(2, e, o, i, s, n.directiveRegistry, n.pipeRegistry, null, n.schemas, n.consts, null);
    n.queries !== null && (n.queries.template(n, e), l.queries = n.queries.embeddedTView(e))
  }
  a && (e.flags |= a), or(e, !1);
  let c = bb(n, t, e, r);
  ns() && nd(n, t, c, e), dr(c, t);
  let u = Zm(c, t, c, e);
  t[r + H] = u, Yl(t, u), XC(u, e, t)
}

function Cb(e, t, n, r, o, i, s, a, c, u, l) {
  let d = n + H,
    p;
  return t.firstCreatePass ? (p = yr(t, d, 4, s || null, a || null), Ki() && ty(t, e, p, we(t.consts, u), od), Fg(t, p)) : p = t.data[d], Cy(p, e, t, n, r, o, i, c), nr(p) && Ws(t, e, p), u != null && Do(e, p, l), p
}

function pr(e, t, n, r, o, i, s, a, c, u, l) {
  let d = n + H,
    p;
  if (t.firstCreatePass) {
    if (p = yr(t, d, 4, s || null, a || null), u != null) {
      let f = we(t.consts, u);
      p.localNames = [];
      for (let g = 0; g < f.length; g += 2) p.localNames.push(f[g], -1)
    }
  } else p = t.data[d];
  return Cy(p, e, t, n, r, o, i, c), u != null && Do(e, p, l), p
}

function by(e, t, n, r, o, i, s, a) {
  let c = E(),
    u = B(),
    l = we(u.consts, i);
  return Cb(c, u, e, t, n, r, o, l, void 0, s, a), by
}

function Ty(e, t, n, r, o, i, s, a) {
  let c = E(),
    u = B(),
    l = we(u.consts, i);
  return pr(c, u, e, t, n, r, o, l, void 0, s, a), Ty
}

function Tb(e, t, n, r) {
  return no(!0), t[P].createComment("")
}

function My(e) {
  md = e
}

function Mo(e) {
  return !!e && typeof e.then == "function"
}

function Xs(e) {
  return !!e && typeof e.subscribe == "function"
}

function _b(e) {
  return Kn([{
    provide: yd,
    multi: !0,
    useValue: e
  }])
}

function Ny() {
  Sa(() => {
    let e = "";
    throw new v(600, e)
  })
}

function Ay(e) {
  return e.isBoundToModule
}

function ao(e, t) {
  let n = e.indexOf(t);
  n > -1 && e.splice(n, 1)
}

function xy(e, t) {
  let n = E(),
    r = et();
  if (pe(n, r, t)) {
    let o = B(),
      i = sr();
    if (qs(i, o, n, e, t)) mt(i) && Lm(n, i.index);
    else {
      let a = Se(i, n);
      jm(n[P], a, null, i.value, e, t, null)
    }
  }
  return xy
}

function Ry(e, t, n, r) {
  let o = E(),
    i = et();
  if (pe(o, i, t)) {
    let s = B(),
      a = sr();
    Qw(a, o, e, t, n, r)
  }
  return Ry
}

function Sb() {
  return E()[ce][q]
}

function Hu(e, t, n, r, o) {
  return e === n && Object.is(t, r) ? 1 : Object.is(o(e, t), o(n, r)) ? -1 : 0
}

function Nb(e, t, n) {
  let r, o, i = 0,
    s = e.length - 1,
    a = void 0;
  if (Array.isArray(t)) {
    let c = t.length - 1;
    for (; i <= s && i <= c;) {
      let u = e.at(i),
        l = t[i],
        d = Hu(i, u, i, l, n);
      if (d !== 0) {
        d < 0 && e.updateValue(i, l), i++;
        continue
      }
      let p = e.at(s),
        f = t[c],
        g = Hu(s, p, c, f, n);
      if (g !== 0) {
        g < 0 && e.updateValue(s, f), s--, c--;
        continue
      }
      let I = n(i, u),
        D = n(s, p),
        m = n(i, l);
      if (Object.is(m, D)) {
        let F = n(c, f);
        Object.is(F, I) ? (e.swap(i, s), e.updateValue(s, f), c--, s--) : e.move(s, i), e.updateValue(i, l), i++;
        continue
      }
      if (r ??= new xs, o ??= bg(e, i, s, n), wl(e, r, i, m)) e.updateValue(i, l), i++, s++;
      else if (o.has(m)) r.set(I, e.detach(i)), s--;
      else {
        let F = e.create(i, t[i]);
        e.attach(i, F), i++, s++
      }
    }
    for (; i <= c;) Cg(e, r, n, i, t[i]), i++
  } else if (t != null) {
    let c = t[Symbol.iterator](),
      u = c.next();
    for (; !u.done && i <= s;) {
      let l = e.at(i),
        d = u.value,
        p = Hu(i, l, i, d, n);
      if (p !== 0) p < 0 && e.updateValue(i, d), i++, u = c.next();
      else {
        r ??= new xs, o ??= bg(e, i, s, n);
        let f = n(i, d);
        if (wl(e, r, i, f)) e.updateValue(i, d), i++, s++, u = c.next();
        else if (!o.has(f)) e.attach(i, e.create(i, d)), i++, s++, u = c.next();
        else {
          let g = n(i, l);
          r.set(g, e.detach(i)), s--
        }
      }
    }
    for (; !u.done;) Cg(e, r, n, e.length, u.value), u = c.next()
  }
  for (; i <= s;) e.destroy(e.detach(s--));
  r?.forEach(c => {
    e.destroy(c)
  })
}

function wl(e, t, n, r) {
  return t !== void 0 && t.has(r) ? (e.attach(n, t.get(r)), t.delete(r), !0) : !1
}

function Cg(e, t, n, r, o) {
  if (wl(e, t, r, n(r, o))) e.updateValue(r, o);
  else {
    let i = e.create(r, o);
    e.attach(r, i)
  }
}

function bg(e, t, n, r) {
  let o = new Set;
  for (let i = t; i <= n; i++) o.add(r(i, e.at(i)));
  return o
}

function Ab(e, t, n, r, o, i, s, a) {
  jt("NgControlFlow");
  let c = E(),
    u = B(),
    l = we(u.consts, i);
  return pr(c, u, e, t, n, r, o, l, 256, s, a), Dd
}

function Dd(e, t, n, r, o, i, s, a) {
  jt("NgControlFlow");
  let c = E(),
    u = B(),
    l = we(u.consts, i);
  return pr(c, u, e, t, n, r, o, l, 512, s, a), Dd
}

function xb(e, t) {
  jt("NgControlFlow");
  let n = E(),
    r = et(),
    o = n[r] !== re ? n[r] : -1,
    i = o !== -1 ? Rs(n, H + o) : void 0,
    s = 0;
  if (pe(n, r, e)) {
    let a = M(null);
    try {
      if (i !== void 0 && Qm(i, s), e !== -1) {
        let c = H + e,
          u = Rs(n, c),
          l = _l(n[w], c),
          d = Jm(u, l, n),
          p = Eo(n, l, t, {
            dehydratedView: d
          });
        Io(u, p, s, fr(l, d))
      }
    } finally {
      M(a)
    }
  } else if (i !== void 0) {
    let a = Ym(i, s);
    a !== void 0 && (a[q] = t)
  }
}

function Rb(e) {
  return e
}

function Ob(e, t) {
  return t
}

function Fb(e, t, n, r, o, i, s, a, c, u, l, d, p) {
  jt("NgControlFlow");
  let f = E(),
    g = B(),
    I = c !== void 0,
    D = E(),
    m = a ? s.bind(D[ce][q]) : s,
    F = new bl(I, m);
  D[H + e] = F, pr(f, g, e + 1, t, n, r, o, we(g.consts, i), 256), I && pr(f, g, e + 2, c, u, l, d, we(g.consts, p), 512)
}

function kb(e) {
  let t = M(null),
    n = je();
  try {
    let r = E(),
      o = r[w],
      i = r[n],
      s = n + 1,
      a = Rs(r, s);
    if (i.liveCollection === void 0) {
      let u = _l(o, s);
      i.liveCollection = new Tl(a, r, u)
    } else i.liveCollection.reset();
    let c = i.liveCollection;
    if (Nb(c, e, i.trackByFn), c.updateIndexes(), i.hasEmptyBlock) {
      let u = et(),
        l = c.length === 0;
      if (pe(r, u, l)) {
        let d = n + 2,
          p = Rs(r, d);
        if (l) {
          let f = _l(o, d),
            g = Jm(p, f, r),
            I = Eo(r, f, void 0, {
              dehydratedView: g
            });
          Io(p, I, 0, fr(f, g))
        } else o.firstUpdatePass && DC(p), Qm(p, 0)
      }
    }
  } finally {
    M(t)
  }
}

function Rs(e, t) {
  return e[t]
}

function Pb(e, t) {
  if (e.length <= Z) return;
  let n = Z + t,
    r = e[n],
    o = r ? r[pn] : void 0;
  if (r && o && o.detachedLeaveAnimationFns && o.detachedLeaveAnimationFns.length > 0) {
    let i = r[ht];
    Nw(i, o), In.delete(r), o.detachedLeaveAnimationFns = void 0
  }
}

function Lb(e, t) {
  if (e.length <= Z) return;
  let n = Z + t,
    r = e[n],
    o = r ? r[pn] : void 0;
  o && o.leave && o.leave.size > 0 && (o.detachedLeaveAnimationFns = [])
}

function jb(e, t) {
  return fo(e, t)
}

function Bb(e, t) {
  return Ym(e, t)
}

function _l(e, t) {
  return Jr(e, t)
}

function Oy(e, t, n) {
  let r = E(),
    o = et();
  if (pe(r, o, t)) {
    let i = B(),
      s = sr();
    km(s, r, e, t, r[P], n)
  }
  return Oy
}

function Ml(e, t, n, r, o) {
  qs(t, e, n, o ? "class" : "style", r)
}

function Ed(e, t, n, r) {
  let o = E(),
    i = o[w],
    s = e + H,
    a = i.firstCreatePass ? ud(s, o, 2, t, od, Ki(), n, r) : i.data[s];
  if (id(a, o, e, t, Py), nr(a)) {
    let c = o[w];
    Ws(c, o, a), Bl(c, a, o)
  }
  return r != null && Do(o, a), Ed
}

function Id() {
  let e = B(),
    t = J(),
    n = sd(t);
  return e.firstCreatePass && ld(e, n), Eu(n) && Iu(), vu(), n.classesWithoutHost != null && XE(n) && Ml(e, n, E(), n.classesWithoutHost, !0), n.stylesWithoutHost != null && eI(n) && Ml(e, n, E(), n.stylesWithoutHost, !1), Id
}

function Fy(e, t, n, r) {
  return Ed(e, t, n, r), Id(), Fy
}

function wd(e, t, n, r) {
  let o = E(),
    i = o[w],
    s = e + H,
    a = i.firstCreatePass ? FC(s, i, 2, t, n, r) : i.data[s];
  return id(a, o, e, t, Py), r != null && Do(o, a), wd
}

function Cd() {
  let e = J(),
    t = sd(e);
  return Eu(t) && Iu(), vu(), Cd
}

function ky(e, t, n, r) {
  return wd(e, t, n, r), Cd(), ky
}

function bd(e, t, n) {
  let r = E(),
    o = r[w],
    i = e + H,
    s = o.firstCreatePass ? ud(i, r, 8, "ng-container", od, Ki(), t, n) : o.data[i];
  if (id(s, r, e, "ng-container", Vb), nr(s)) {
    let a = r[w];
    Ws(a, r, s), Bl(a, s, r)
  }
  return n != null && Do(r, s), bd
}

function Td() {
  let e = B(),
    t = J(),
    n = sd(t);
  return e.firstCreatePass && ld(e, n), Td
}

function Ly(e, t, n) {
  return bd(e, t, n), Td(), Ly
}

function Hb() {
  return E()
}

function jy(e, t, n) {
  let r = E(),
    o = et();
  if (pe(r, o, t)) {
    let i = B(),
      s = sr();
    Pm(s, r, e, t, r[P], n)
  }
  return jy
}

function Ub(e) {
  let t = Math.floor(Math.abs(e)),
    n = e.toString().replace(/^[^.]*\.?/, "").length;
  return t === 1 && n === 0 ? 1 : 5
}

function ea(e) {
  let t = zb(e),
    n = Tg(t);
  if (n) return n;
  let r = t.split("-")[0];
  if (n = Tg(r), n) return n;
  if (r === "en") return $b;
  throw new v(701, !1)
}

function Tg(e) {
  return e in Uu || (Uu[e] = ne.ng && ne.ng.common && ne.ng.common.locales && ne.ng.common.locales[e]), Uu[e]
}

function zb(e) {
  return e.toLowerCase().replace(/_/g, "-")
}

function By(e) {
  typeof e == "string" && (Gb = e.toLowerCase().replace(/_/g, "-"))
}

function Vy(e, t, n) {
  let r = E(),
    o = B(),
    i = J();
  return Uy(o, r, r[P], i, e, t, n), Vy
}

function Hy(e, t, n) {
  let r = E(),
    o = B(),
    i = J();
  return (i.type & 3 || n) && oy(i, o, r, n, r[P], e, t, hs(i, r, t)), Hy
}

function Uy(e, t, n, r, o, i, s) {
  let a = !0,
    c = null;
  if ((r.type & 3 || s) && (c ??= hs(r, t, i), oy(r, e, t, s, n, o, i, c) && (a = !1)), a) {
    let u = r.outputs?.[o],
      l = r.hostDirectiveOutputs?.[o];
    if (l && l.length)
      for (let d = 0; d < l.length; d += 2) {
        let p = l[d],
          f = l[d + 1];
        c ??= hs(r, t, i), yg(r, t, p, f, o, c)
      }
    if (u && u.length)
      for (let d of u) c ??= hs(r, t, i), yg(r, t, d, o, o, c)
  }
}

function Wb(e = 1) {
  return Vh(e)
}

function qb(e, t) {
  let n = null,
    r = cw(e);
  for (let o = 0; o < t.length; o++) {
    let i = t[o];
    if (i === "*") {
      n = o;
      continue
    }
    if (r === null ? Em(e, i, !0) : dw(r, i)) return o
  }
  return n
}

function Zb(e) {
  let t = E()[ce][fe];
  if (!t.projection) {
    let n = e ? e.length : 1,
      r = t.projection = fh(n, null),
      o = r.slice(),
      i = t.child;
    for (; i !== null;) {
      if (i.type !== 128) {
        let s = e ? qb(i, e) : 0;
        s !== null && (o[s] ? o[s].projectionNext = i : r[s] = i, o[s] = i)
      }
      i = i.next
    }
  }
}

function Yb(e, t = 0, n, r, o, i) {
  let s = E(),
    a = B(),
    c = r ? e + 1 : null;
  c !== null && pr(s, a, c, r, o, i, null, n);
  let u = yr(a, H + e, 16, null, n || null);
  u.projection === null && (u.projection = t), bu();
  let d = !s[un] || Du();
  s[ce][fe].projection[u.projection] === null && c !== null ? Qb(s, a, c) : d && !js(u) && Vw(a, s, u)
}

function Qb(e, t, n) {
  let r = H + n,
    o = t.data[r],
    i = e[r],
    s = bs(i, o.tView.ssrId),
    a = Eo(e, o, void 0, {
      dehydratedView: s
    });
  Io(i, a, 0, fr(o, s))
}

function Kb(e, t, n, r) {
  fy(e, t, n, r)
}

function Jb(e, t, n) {
  dy(e, t, n)
}

function Xb(e) {
  let t = E(),
    n = B(),
    r = Xi();
  to(r + 1);
  let o = pd(n, r);
  if (e.dirty && Ih(t) === ((o.metadata.flags & 2) === 2)) {
    if (o.matches === null) e.reset([]);
    else {
      let i = hy(t, r);
      e.reset(i, Wg), e.notifyOnChanges()
    }
    return !0
  }
  return !1
}

function eT() {
  return fd(E(), Xi())
}

function tT(e, t, n, r, o) {
  my(t, fy(e, n, r, o))
}

function nT(e, t, n, r) {
  my(e, dy(t, n, r))
}

function rT(e = 1) {
  to(Xi() + e)
}

function oT(e) {
  let t = xh();
  return Zi(t, H + e)
}

function us(e, t) {
  return e << 17 | t << 2
}

function bn(e) {
  return e >> 17 & 32767
}

function iT(e) {
  return (e & 2) == 2
}

function sT(e, t) {
  return e & 131071 | t << 17
}

function Sl(e) {
  return e | 2
}

function hr(e) {
  return (e & 131068) >> 2
}

function $u(e, t) {
  return e & -131069 | t << 2
}

function aT(e) {
  return (e & 1) === 1
}

function Nl(e) {
  return e | 1
}

function cT(e, t, n, r, o, i) {
  let s = i ? t.classBindings : t.styleBindings,
    a = bn(s),
    c = hr(s);
  e[r] = n;
  let u = !1,
    l;
  if (Array.isArray(n)) {
    let d = n;
    l = d[1], (l === null || Qn(d, l) > 0) && (u = !0)
  } else l = n;
  if (o)
    if (c !== 0) {
      let p = bn(e[a + 1]);
      e[r + 1] = us(p, a), p !== 0 && (e[p + 1] = $u(e[p + 1], r)), e[a + 1] = sT(e[a + 1], r)
    } else e[r + 1] = us(a, 0), a !== 0 && (e[a + 1] = $u(e[a + 1], r)), a = r;
  else e[r + 1] = us(c, 0), a === 0 ? a = r : e[c + 1] = $u(e[c + 1], r), c = r;
  u && (e[r + 1] = Sl(e[r + 1])), _g(e, l, r, !0), _g(e, l, r, !1), uT(t, l, e, r, i), s = us(a, c), i ? t.classBindings = s : t.styleBindings = s
}

function uT(e, t, n, r, o) {
  let i = o ? e.residualClasses : e.residualStyles;
  i != null && typeof t == "string" && Qn(i, t) >= 0 && (n[r + 1] = Nl(n[r + 1]))
}

function _g(e, t, n, r) {
  let o = e[n + 1],
    i = t === null,
    s = r ? bn(o) : hr(o),
    a = !1;
  for (; s !== 0 && (a === !1 || i);) {
    let c = e[s],
      u = e[s + 1];
    lT(c, t) && (a = !0, e[s + 1] = r ? Nl(u) : Sl(u)), s = r ? bn(u) : hr(u)
  }
  a && (e[n + 1] = r ? Sl(o) : Nl(o))
}

function lT(e, t) {
  return e === null || t == null || (Array.isArray(e) ? e[1] : e) === t ? !0 : Array.isArray(e) && typeof t == "string" ? Qn(e, t) >= 0 : !1
}

function dT(e) {
  return e.substring(He.key, He.keyEnd)
}

function fT(e) {
  return pT(e), $y(e, zy(e, 0, He.textEnd))
}

function $y(e, t) {
  let n = He.textEnd;
  return n === t ? -1 : (t = He.keyEnd = hT(e, He.key = t, n), zy(e, t, n))
}

function pT(e) {
  He.key = 0, He.keyEnd = 0, He.value = 0, He.valueEnd = 0, He.textEnd = e.length
}

function zy(e, t, n) {
  for (; t < n && e.charCodeAt(t) <= 32;) t++;
  return t
}

function hT(e, t, n) {
  for (; t < n && e.charCodeAt(t) > 32;) t++;
  return t
}

function Gy(e, t, n) {
  return qy(e, t, n, !1), Gy
}

function Wy(e, t) {
  return qy(e, t, null, !0), Wy
}

function gT(e) {
  yT(CT, mT, e, !0)
}

function mT(e, t) {
  for (let n = fT(t); n >= 0; n = $y(t, n)) zi(e, dT(t), !0)
}

function qy(e, t, n, r) {
  let o = E(),
    i = B(),
    s = eo(2);
  if (i.firstUpdatePass && Yy(i, e, s, r), t !== re && pe(o, s, t)) {
    let a = i.data[je()];
    Qy(i, a, o, o[P], e, o[s + 1] = TT(t, n), r, s)
  }
}

function yT(e, t, n, r) {
  let o = B(),
    i = eo(2);
  o.firstUpdatePass && Yy(o, null, i, r);
  let s = E();
  if (n !== re && pe(s, i, n)) {
    let a = o.data[je()];
    if (Ky(a, r) && !Zy(o, i)) {
      let c = r ? a.classesWithoutHost : a.stylesWithoutHost;
      c !== null && (n = Bi(c, n || "")), Ml(o, a, s, n, r)
    } else bT(o, a, s, s[P], s[i + 1], s[i + 1] = wT(e, t, n), r, i)
  }
}

function Zy(e, t) {
  return t >= e.expandoStartIndex
}

function Yy(e, t, n, r) {
  let o = e.data;
  if (o[n + 1] === null) {
    let i = o[je()],
      s = Zy(e, n);
    Ky(i, r) && t === null && !s && (t = !1), t = vT(o, i, t, r), cT(o, i, t, n, s, r)
  }
}

function vT(e, t, n, r) {
  let o = Ph(e),
    i = r ? t.residualClasses : t.residualStyles;
  if (o === null)(r ? t.classBindings : t.styleBindings) === 0 && (n = zu(null, e, t, n, r), n = go(n, t.attrs, r), i = null);
  else {
    let s = t.directiveStylingLast;
    if (s === -1 || e[s] !== o)
      if (n = zu(o, e, t, n, r), i === null) {
        let c = DT(e, t, r);
        c !== void 0 && Array.isArray(c) && (c = zu(null, e, t, c[1], r), c = go(c, t.attrs, r), ET(e, t, r, c))
      } else i = IT(e, t, r)
  }
  return i !== void 0 && (r ? t.residualClasses = i : t.residualStyles = i), n
}

function DT(e, t, n) {
  let r = n ? t.classBindings : t.styleBindings;
  if (hr(r) !== 0) return e[bn(r)]
}

function ET(e, t, n, r) {
  let o = n ? t.classBindings : t.styleBindings;
  e[bn(o)] = r
}

function IT(e, t, n) {
  let r, o = t.directiveEnd;
  for (let i = 1 + t.directiveStylingLast; i < o; i++) {
    let s = e[i].hostAttrs;
    r = go(r, s, n)
  }
  return go(r, t.attrs, n)
}

function zu(e, t, n, r, o) {
  let i = null,
    s = n.directiveEnd,
    a = n.directiveStylingLast;
  for (a === -1 ? a = n.directiveStart : a++; a < s && (i = t[a], r = go(r, i.hostAttrs, o), i !== e);) a++;
  return e !== null && (n.directiveStylingLast = a), r
}

function go(e, t, n) {
  let r = n ? 1 : 2,
    o = -1;
  if (t !== null)
    for (let i = 0; i < t.length; i++) {
      let s = t[i];
      typeof s == "number" ? o = s : o === r && (Array.isArray(e) || (e = e === void 0 ? [] : ["", e]), zi(e, s, n ? !0 : t[++i]))
    }
  return e === void 0 ? null : e
}

function wT(e, t, n) {
  if (n == null || n === "") return ae;
  let r = [],
    o = Ce(n);
  if (Array.isArray(o))
    for (let i = 0; i < o.length; i++) e(r, o[i], !0);
  else if (typeof o == "object")
    for (let i in o) o.hasOwnProperty(i) && e(r, i, o[i]);
  else typeof o == "string" && t(r, o);
  return r
}

function CT(e, t, n) {
  let r = String(t);
  r !== "" && !r.includes(" ") && zi(e, r, n)
}

function bT(e, t, n, r, o, i, s, a) {
  o === re && (o = ae);
  let c = 0,
    u = 0,
    l = 0 < o.length ? o[0] : null,
    d = 0 < i.length ? i[0] : null;
  for (; l !== null || d !== null;) {
    let p = c < o.length ? o[c + 1] : void 0,
      f = u < i.length ? i[u + 1] : void 0,
      g = null,
      I;
    l === d ? (c += 2, u += 2, p !== f && (g = d, I = f)) : d === null || l !== null && l < d ? (c += 2, g = l) : (u += 2, g = d, I = f), g !== null && Qy(e, t, n, r, g, I, s, a), l = c < o.length ? o[c] : null, d = u < i.length ? i[u] : null
  }
}

function Qy(e, t, n, r, o, i, s, a) {
  if (!(t.type & 3)) return;
  let c = e.data,
    u = c[a + 1],
    l = aT(u) ? Mg(c, t, n, o, hr(u), s) : void 0;
  if (!Os(l)) {
    Os(i) || iT(u) && (i = Mg(c, null, n, o, a, s));
    let d = du(je(), n);
    Uw(r, s, d, o, i)
  }
}

function Mg(e, t, n, r, o, i) {
  let s = t === null,
    a;
  for (; o > 0;) {
    let c = e[o],
      u = Array.isArray(c),
      l = u ? c[1] : c,
      d = l === null,
      p = n[o + 1];
    p === re && (p = d ? ae : void 0);
    let f = d ? Gi(p, r) : l === r ? p : void 0;
    if (u && !Os(f) && (f = Gi(c, r)), Os(f) && (a = f, s)) return a;
    let g = e[o + 1];
    o = s ? bn(g) : hr(g)
  }
  if (t !== null) {
    let c = i ? t.residualClasses : t.residualStyles;
    c != null && (a = Gi(c, r))
  }
  return a
}

function Os(e) {
  return e !== void 0
}

function TT(e, t) {
  return e == null || e === "" || (typeof t == "string" ? e = e + t : typeof e == "object" && (e = ft(Ce(e)))), e
}

function Ky(e, t) {
  return (e.flags & (t ? 8 : 16)) !== 0
}

function _T(e, t = "") {
  let n = E(),
    r = B(),
    o = e + H,
    i = r.firstCreatePass ? yr(r, o, 1, t, null) : r.data[o],
    s = MT(r, n, i, t, e);
  n[o] = s, ns() && nd(r, n, s, i), or(i, !1)
}

function Jy(e, t, n, r = "") {
  return pe(e, et(), n) ? t + Ee(n) + r : re
}

function Xy(e, t, n, r, o, i = "") {
  let s = _u(),
    a = po(e, s, n, o);
  return eo(2), a ? t + Ee(n) + r + Ee(o) + i : re
}

function ST(e, t, n, r, o, i, s, a, c, u = "") {
  let l = _u(),
    d = LC(e, l, n, o, s, c);
  return eo(4), d ? t + Ee(n) + r + Ee(o) + i + Ee(s) + a + Ee(c) + u : re
}

function ev(e) {
  return _d("", e), ev
}

function _d(e, t, n) {
  let r = E(),
    o = Jy(r, e, t, n);
  return o !== re && Md(r, je(), o), _d
}

function tv(e, t, n, r, o) {
  let i = E(),
    s = Xy(i, e, t, n, r, o);
  return s !== re && Md(i, je(), s), tv
}

function nv(e, t, n, r, o, i, s, a, c) {
  let u = E(),
    l = ST(u, e, t, n, r, o, i, s, a, c);
  return l !== re && Md(u, je(), l), nv
}

function Md(e, t, n) {
  let r = du(t, e);
  qI(e[P], r, n)
}

function rv(e, t, n) {
  Ru(t) && (t = t());
  let r = E(),
    o = et();
  if (pe(r, o, t)) {
    let i = B(),
      s = sr();
    km(s, r, e, t, r[P], n)
  }
  return rv
}

function NT(e, t) {
  let n = Ru(e);
  return n && e.set(t), n
}

function ov(e, t) {
  let n = E(),
    r = B(),
    o = J();
  return Uy(r, n, n[P], o, e, t), ov
}

function AT(e) {
  return pe(E(), et(), e) ? Ee(e) : re
}

function xT(e, t, n = "") {
  return Jy(E(), e, t, n)
}

function RT(e, t, n, r, o = "") {
  return Xy(E(), e, t, n, r, o)
}

function OT(e, t, n) {
  let r = B();
  if (r.firstCreatePass) {
    let o = Le(e);
    Al(n, r.data, r.blueprint, o, !0), Al(t, r.data, r.blueprint, o, !1)
  }
}

function Al(e, t, n, r, o) {
  if (e = ee(e), Array.isArray(e))
    for (let i = 0; i < e.length; i++) Al(e[i], t, n, r, o);
  else {
    let i = B(),
      s = E(),
      a = J(),
      c = sn(e) ? e : ee(e.provide),
      u = ou(e),
      l = a.providerIndexes & 1048575,
      d = a.directiveStart,
      p = a.providerIndexes >> 20;
    if (sn(e) || !e.multi) {
      let f = new En(u, o, U, null),
        g = Wu(c, t, o ? l : l + p, d);
      g === -1 ? (Zu(Ds(a, s), i, c), Gu(i, e, t.length), t.push(c), a.directiveStart++, a.directiveEnd++, o && (a.providerIndexes += 1048576), n.push(f), s.push(f)) : (n[g] = f, s[g] = f)
    } else {
      let f = Wu(c, t, l + p, d),
        g = Wu(c, t, l, l + p),
        I = f >= 0 && n[f],
        D = g >= 0 && n[g];
      if (o && !D || !o && !I) {
        Zu(Ds(a, s), i, c);
        let m = PT(o ? kT : FT, n.length, o, r, u, e);
        !o && D && (n[g].providerFactory = m), Gu(i, e, t.length, 0), t.push(c), a.directiveStart++, a.directiveEnd++, o && (a.providerIndexes += 1048576), n.push(m), s.push(m)
      } else {
        let m = iv(n[o ? g : f], u, !o && r);
        Gu(i, e, f > -1 ? f : g, m)
      }!o && r && D && n[g].componentProviders++
    }
  }
}

function Gu(e, t, n, r) {
  let o = sn(t),
    i = vh(t);
  if (o || i) {
    let c = (i ? ee(t.useClass) : t).prototype.ngOnDestroy;
    if (c) {
      let u = e.destroyHooks || (e.destroyHooks = []);
      if (!o && t.multi) {
        let l = u.indexOf(n);
        l === -1 ? u.push(n, [r, c]) : u[l + 1].push(r, c)
      } else u.push(n, c)
    }
  }
}

function iv(e, t, n) {
  return n && e.componentProviders++, e.multi.push(t) - 1
}

function Wu(e, t, n, r) {
  for (let o = n; o < r; o++)
    if (t[o] === e) return o;
  return -1
}

function FT(e, t, n, r, o) {
  return xl(this.multi, [])
}

function kT(e, t, n, r, o) {
  let i = this.multi,
    s;
  if (this.providerFactory) {
    let a = this.providerFactory.componentProviders,
      c = co(r, r[w], this.providerFactory.index, o);
    s = c.slice(0, a), xl(i, s);
    for (let u = a; u < c.length; u++) s.push(c[u])
  } else s = [], xl(i, s);
  return s
}

function xl(e, t) {
  for (let n = 0; n < e.length; n++) {
    let r = e[n];
    t.push(r())
  }
  return t
}

function PT(e, t, n, r, o, i) {
  let s = new En(e, n, U, null);
  return s.multi = [], s.index = t, s.componentProviders = 0, iv(s, o, r && !n), s
}

function LT(e, t = []) {
  return n => {
    n.providersResolver = (r, o) => OT(r, o ? o(e) : e, t)
  }
}

function jT(e, t, n) {
  let r = mn() + e,
    o = E();
  return o[r] === re ? Ks(o, r, n ? t.call(n) : t()) : kC(o, r)
}

function BT(e, t, n, r) {
  return sv(E(), mn(), e, t, n, r)
}

function VT(e, t, n, r, o) {
  return av(E(), mn(), e, t, n, r, o)
}

function HT(e, t, n, r, o, i) {
  return UT(E(), mn(), e, t, n, r, o, i)
}

function Sd(e, t) {
  let n = e[t];
  return n === re ? void 0 : n
}

function sv(e, t, n, r, o, i) {
  let s = t + n;
  return pe(e, s, o) ? Ks(e, s + 1, i ? r.call(i, o) : r(o)) : Sd(e, s + 1)
}

function av(e, t, n, r, o, i, s) {
  let a = t + n;
  return po(e, a, o, i) ? Ks(e, a + 2, s ? r.call(s, o, i) : r(o, i)) : Sd(e, a + 2)
}

function UT(e, t, n, r, o, i, s, a) {
  let c = t + n;
  return PC(e, c, o, i, s) ? Ks(e, c + 3, a ? r.call(a, o, i, s) : r(o, i, s)) : Sd(e, c + 3)
}

function $T(e, t) {
  let n = B(),
    r, o = e + H;
  n.firstCreatePass ? (r = zT(t, n.pipeRegistry), n.data[o] = r, r.onDestroy && (n.destroyHooks ??= []).push(o, r.onDestroy)) : r = n.data[o];
  let i = r.factory || (r.factory = Mt(r.type, !0)),
    s, a = de(U);
  try {
    let c = vs(!1),
      u = i();
    return vs(c), fu(n, E(), o, u), u
  } finally {
    de(a)
  }
}

function zT(e, t) {
  if (t)
    for (let n = t.length - 1; n >= 0; n--) {
      let r = t[n];
      if (e === r.name) return r
    }
}

function GT(e, t, n) {
  let r = e + H,
    o = E(),
    i = Zi(o, r);
  return cv(o, r) ? sv(o, mn(), t, i.transform, n, i) : i.transform(n)
}

function WT(e, t, n, r) {
  let o = e + H,
    i = E(),
    s = Zi(i, o);
  return cv(i, o) ? av(i, mn(), t, s.transform, n, r, s) : s.transform(n, r)
}

function cv(e, t) {
  return e[w].data[t].pure
}

function qT(e, t) {
  return Zs(e, t)
}

function uv({
  ngZoneFactory: e,
  ignoreChangesOutsideZone: t,
  scheduleInRootZone: n
}) {
  return e ??= () => new z(G(V({}, lv()), {
    scheduleInRootZone: n
  })), [{
    provide: z,
    useFactory: e
  }, {
    provide: Nt,
    multi: !0,
    useFactory: () => {
      let r = y(YT, {
        optional: !0
      });
      return () => r.initialize()
    }
  }, {
    provide: Nt,
    multi: !0,
    useFactory: () => {
      let r = y(QT);
      return () => {
        r.initialize()
      }
    }
  }, t === !0 ? {
    provide: Ou,
    useValue: !0
  } : [], {
    provide: Fu,
    useValue: n ?? bm
  }, {
    provide: Be,
    useFactory: () => {
      let r = y(z),
        o = y(ye),
        i;
      return s => {
        r.runOutsideAngular(() => {
          o.destroyed && !i ? setTimeout(() => {
            throw s
          }) : (i ??= o.get(De), i.handleError(s))
        })
      }
    }
  }]
}

function lv(e) {
  return {
    enableLongStackTrace: !1,
    shouldCoalesceEventChangeDetection: e?.eventCoalescing ?? !1,
    shouldCoalesceRunChangeDetection: e?.runCoalescing ?? !1
  }
}

function KT() {
  return typeof $localize < "u" && $localize.locale || So
}
var os, Ng, WE, gs, Ol, Rg, Wh, L, ur, En, qu, oI, jg, Bg, iI, tt, Dn, Et, Es, Pl, Zg, gI, Kh, Ku, ks, vI, Ps, mo, DI, Ls, EI, II, Jg, Xg, em, tm, nm, wI, bI, vt, is, ss, Dt, Xu, el, tl, nl, rl, ol, il, SI, am, cm, um, NI, AI, xI, eg, lm, RI, OI, FI, kI, sl, BI, VI, as, UI, $I, zI, xe, JI, XI, Dm, re, Hs, Ue, Dw, In, Us, Lt, sg, bm, cl, yt, Kl, ws, Ew, z, Iw, Cs, $s, Xl, ed, uo, Mm, Bw, fg, Gw, Hm, iC, aC, cC, kt, nt, BP, IC, wC, Xm, Ys, fl, wo, wn, Co, ey, ps, pl, hl, _s, Pt, Ms, ot, YC, ay, KC, JC, gl, ml, Ss, yl, vl, Cn, yy, Ns, As, ho, cb, bb, _y, Js, vr, To, _o, md, yd, vd, Sy, Mb, Tn, WP, Il, xs, Cl, bl, Tl, Py, Vb, cs, $b, Uu, _n, So, Gb, He, MT, Fs, ZT, YT, QT, dv, No, Nd = h(() => {
  io();
  Wt();
  Ur();
  xc();
  ku();
  os = "__parameters__";
  Ng = Kc(Sg("Optional"), 8), WE = Kc(Sg("SkipSelf"), 4);
  gs = class {
    previousValue;
    currentValue;
    firstChange;
    constructor(t, n, r) {
      this.previousValue = t, this.currentValue = n, this.firstChange = r
    }
    isFirstChange() {
      return this.firstChange
    }
  };
  Ol = (() => {
    let e = () => xg;
    return e.ngInherit = !0, e
  })();
  Rg = "__ngSimpleChanges__";
  Wh = [], L = function(e, t = null, n) {
    for (let r = 0; r < Wh.length; r++) {
      let o = Wh[r];
      o(e, t, n)
    }
  };
  ur = -1, En = class {
    factory;
    name;
    injectImpl;
    resolving = !1;
    canSeeViewProviders;
    multi;
    componentProviders;
    index;
    providerFactory;
    constructor(t, n, r, o) {
      this.factory = t, this.name = o, this.canSeeViewProviders = n, this.injectImpl = r
    }
  };
  qu = !0;
  oI = 256, jg = oI - 1, Bg = 5, iI = 0, tt = {};
  Dn = class {
    _tNode;
    _lView;
    constructor(t, n) {
      this._tNode = t, this._lView = n
    }
    get(t, n, r) {
      return $g(this._tNode, this._lView, t, on(r), n)
    }
  };
  Et = (() => {
    class e {
      nativeElement;
      constructor(n) {
        this.nativeElement = n
      }
      static __NG_ELEMENT_ID__ = pI
    }
    return e
  })();
  Es = class {
    _emitDistinctChangesOnly;
    dirty = !0;
    _onDirty = void 0;
    _results = [];
    _changesDetected = !1;
    _changes = void 0;
    length = 0;
    first = void 0;
    last = void 0;
    get changes() {
      return this._changes ??= new ge
    }
    constructor(t = !1) {
      this._emitDistinctChangesOnly = t
    }
    get(t) {
      return this._results[t]
    }
    map(t) {
      return this._results.map(t)
    }
    filter(t) {
      return this._results.filter(t)
    }
    find(t) {
      return this._results.find(t)
    }
    reduce(t, n) {
      return this._results.reduce(t, n)
    }
    forEach(t) {
      this._results.forEach(t)
    }
    some(t) {
      return this._results.some(t)
    }
    toArray() {
      return this._results.slice()
    }
    toString() {
      return this._results.toString()
    }
    reset(t, n) {
      this.dirty = !1;
      let r = dh(t);
      (this._changesDetected = !lh(this._results, r, n)) && (this._results = r, this.length = r.length, this.last = r[this.length - 1], this.first = r[0])
    }
    notifyOnChanges() {
      this._changes !== void 0 && (this._changesDetected || !this._emitDistinctChangesOnly) && this._changes.next(this)
    }
    onDirty(t) {
      this._onDirty = t
    }
    setDirty() {
      this.dirty = !0, this._onDirty?.()
    }
    destroy() {
      this._changes !== void 0 && (this._changes.complete(), this._changes.unsubscribe())
    } [Symbol.iterator] = hI
  };
  Pl = (function(e) {
    return e[e.OnPush = 0] = "OnPush", e[e.Default = 1] = "Default", e
  })(Pl || {}), Zg = new Map, gI = 0;
  Kh = "__ngContext__";
  ks = new T("", {
    providedIn: "root",
    factory: () => vI
  }), vI = "ng", Ps = new T(""), mo = new T("", {
    providedIn: "platform",
    factory: () => "unknown"
  }), DI = new T(""), Ls = new T("", {
    providedIn: "root",
    factory: () => jl().body?.querySelector("[ngCspNonce]")?.getAttribute("ngCspNonce") || null
  }), EI = "h", II = "b", Jg = "r", Xg = "di", em = !1, tm = new T("", {
    providedIn: "root",
    factory: () => em
  }), nm = new T("");
  wI = (e, t, n, r) => {};
  bI = () => null;
  vt = (function(e) {
    return e[e.Emulated = 0] = "Emulated", e[e.None = 2] = "None", e[e.ShadowDom = 3] = "ShadowDom", e
  })(vt || {});
  Dt = class {
    changingThisBreaksApplicationSecurity;
    constructor(t) {
      this.changingThisBreaksApplicationSecurity = t
    }
    toString() {
      return `SafeValue must use [property]=binding: ${this.changingThisBreaksApplicationSecurity} (see ${ji})`
    }
  }, Xu = class extends Dt {
    getTypeName() {
      return "HTML"
    }
  }, el = class extends Dt {
    getTypeName() {
      return "Style"
    }
  }, tl = class extends Dt {
    getTypeName() {
      return "Script"
    }
  }, nl = class extends Dt {
    getTypeName() {
      return "URL"
    }
  }, rl = class extends Dt {
    getTypeName() {
      return "ResourceURL"
    }
  };
  ol = class {
    inertDocumentHelper;
    constructor(t) {
      this.inertDocumentHelper = t
    }
    getInertBodyElement(t) {
      t = "<body><remove></remove>" + t;
      try {
        let n = new window.DOMParser().parseFromString(Bs(t), "text/html").body;
        return n === null ? this.inertDocumentHelper.getInertBodyElement(t) : (n.firstChild?.remove(), n)
      } catch {
        return null
      }
    }
  }, il = class {
    defaultDoc;
    inertDocument;
    constructor(t) {
      this.defaultDoc = t, this.inertDocument = this.defaultDoc.implementation.createHTMLDocument("sanitization-inert")
    }
    getInertBodyElement(t) {
      let n = this.inertDocument.createElement("template");
      return n.innerHTML = Bs(t), n
    }
  };
  SI = /^(?!javascript:)(?:[a-z0-9+.-]+:|[^&:\/?#]*(?:[\/?#]|$))/i;
  am = It("area,br,col,hr,img,wbr"), cm = It("colgroup,dd,dt,li,p,tbody,td,tfoot,th,thead,tr"), um = It("rp,rt"), NI = vo(um, cm), AI = vo(cm, It("address,article,aside,blockquote,caption,center,del,details,dialog,dir,div,dl,figure,figcaption,footer,h1,h2,h3,h4,h5,h6,header,hgroup,hr,ins,main,map,menu,nav,ol,pre,section,summary,table,ul")), xI = vo(um, It("a,abbr,acronym,audio,b,bdi,bdo,big,br,cite,code,del,dfn,em,font,i,img,ins,kbd,label,map,mark,picture,q,ruby,rp,rt,s,samp,small,source,span,strike,strong,sub,sup,time,track,tt,u,var,video")), eg = vo(am, AI, xI, NI), lm = It("background,cite,href,itemtype,longdesc,poster,src,xlink:href"), RI = It("abbr,accesskey,align,alt,autoplay,axis,bgcolor,border,cellpadding,cellspacing,class,clear,color,cols,colspan,compact,controls,coords,datetime,default,dir,download,face,headers,height,hidden,hreflang,hspace,ismap,itemscope,itemprop,kind,label,lang,language,loop,media,muted,nohref,nowrap,open,preload,rel,rev,role,rows,rowspan,rules,scope,scrolling,shape,size,sizes,span,srclang,srcset,start,summary,tabindex,target,title,translate,type,usemap,valign,value,vspace,width"), OI = It("aria-activedescendant,aria-atomic,aria-autocomplete,aria-busy,aria-checked,aria-colcount,aria-colindex,aria-colspan,aria-controls,aria-current,aria-describedby,aria-details,aria-disabled,aria-dropeffect,aria-errormessage,aria-expanded,aria-flowto,aria-grabbed,aria-haspopup,aria-hidden,aria-invalid,aria-keyshortcuts,aria-label,aria-labelledby,aria-level,aria-live,aria-modal,aria-multiline,aria-multiselectable,aria-orientation,aria-owns,aria-placeholder,aria-posinset,aria-pressed,aria-readonly,aria-relevant,aria-required,aria-roledescription,aria-rowcount,aria-rowindex,aria-rowspan,aria-selected,aria-setsize,aria-sort,aria-valuemax,aria-valuemin,aria-valuenow,aria-valuetext"), FI = vo(lm, RI, OI), kI = It("script,style,template"), sl = class {
    sanitizedSomething = !1;
    buf = [];
    sanitizeChildren(t) {
      let n = t.firstChild,
        r = !0,
        o = [];
      for (; n;) {
        if (n.nodeType === Node.ELEMENT_NODE ? r = this.startElement(n) : n.nodeType === Node.TEXT_NODE ? this.chars(n.nodeValue) : this.sanitizedSomething = !0, r && n.firstChild) {
          o.push(n), n = jI(n);
          continue
        }
        for (; n;) {
          n.nodeType === Node.ELEMENT_NODE && this.endElement(n);
          let i = LI(n);
          if (i) {
            n = i;
            break
          }
          n = o.pop()
        }
      }
      return this.buf.join("")
    }
    startElement(t) {
      let n = tg(t).toLowerCase();
      if (!eg.hasOwnProperty(n)) return this.sanitizedSomething = !0, !kI.hasOwnProperty(n);
      this.buf.push("<"), this.buf.push(n);
      let r = t.attributes;
      for (let o = 0; o < r.length; o++) {
        let i = r.item(o),
          s = i.name,
          a = s.toLowerCase();
        if (!FI.hasOwnProperty(a)) {
          this.sanitizedSomething = !0;
          continue
        }
        let c = i.value;
        lm[a] && (c = yo(c)), this.buf.push(" ", s, '="', ng(c), '"')
      }
      return this.buf.push(">"), !0
    }
    endElement(t) {
      let n = tg(t).toLowerCase();
      eg.hasOwnProperty(n) && !am.hasOwnProperty(n) && (this.buf.push("</"), this.buf.push(n), this.buf.push(">"))
    }
    chars(t) {
      this.buf.push(ng(t))
    }
  };
  BI = /[\uD800-\uDBFF][\uDC00-\uDFFF]/g, VI = /([^\#-~ |!])/g;
  UI = /^>|^->|<!--|-->|--!>|<!-$/g, $I = /(<|>)/g, zI = "​$1​";
  xe = (function(e) {
    return e[e.NONE = 0] = "NONE", e[e.HTML = 1] = "HTML", e[e.STYLE = 2] = "STYLE", e[e.SCRIPT = 3] = "SCRIPT", e[e.URL = 4] = "URL", e[e.RESOURCE_URL = 5] = "RESOURCE_URL", e
  })(xe || {});
  JI = new Set(["embed", "frame", "iframe", "media", "script"]), XI = new Set(["base", "link", "script"]);
  Dm = "ng-template";
  re = {};
  Hs = (function(e) {
    return e[e.None = 0] = "None", e[e.SignalBased = 1] = "SignalBased", e[e.HasDecoratorInputTransform = 2] = "HasDecoratorInputTransform", e
  })(Hs || {});
  Ue = (function(e) {
    return e[e.Important = 1] = "Important", e[e.DashCase = 2] = "DashCase", e
  })(Ue || {});
  In = new Set, Us = (function(e) {
    return e[e.CHANGE_DETECTION = 0] = "CHANGE_DETECTION", e[e.AFTER_NEXT_RENDER = 1] = "AFTER_NEXT_RENDER", e
  })(Us || {}), Lt = new T(""), sg = new Set;
  bm = !1, cl = class extends ge {
    __isAsync;
    destroyRef = void 0;
    pendingTasks = void 0;
    constructor(t = !1) {
      super(), this.__isAsync = t, iu() && (this.destroyRef = y(Ae, {
        optional: !0
      }) ?? void 0, this.pendingTasks = y(Ft, {
        optional: !0
      }) ?? void 0)
    }
    emit(t) {
      let n = M(null);
      try {
        super.next(t)
      } finally {
        M(n)
      }
    }
    subscribe(t, n, r) {
      let o = t,
        i = n || (() => null),
        s = r;
      if (t && typeof t == "object") {
        let c = t;
        o = c.next?.bind(c), i = c.error?.bind(c), s = c.complete?.bind(c)
      }
      this.__isAsync && (i = this.wrapInTimeout(i), o && (o = this.wrapInTimeout(o)), s && (s = this.wrapInTimeout(s)));
      let a = super.subscribe({
        next: o,
        error: i,
        complete: s
      });
      return t instanceof W && t.add(a), a
    }
    wrapInTimeout(t) {
      return n => {
        let r = this.pendingTasks?.add();
        setTimeout(() => {
          try {
            t(n)
          } finally {
            r !== void 0 && this.pendingTasks?.remove(r)
          }
        })
      }
    }
  }, yt = cl;
  Kl = "isAngularZone", ws = Kl + "_ID", Ew = 0, z = class e {
    hasPendingMacrotasks = !1;
    hasPendingMicrotasks = !1;
    isStable = !0;
    onUnstable = new yt(!1);
    onMicrotaskEmpty = new yt(!1);
    onStable = new yt(!1);
    onError = new yt(!1);
    constructor(t) {
      let {
        enableLongStackTrace: n = !1,
        shouldCoalesceEventChangeDetection: r = !1,
        shouldCoalesceRunChangeDetection: o = !1,
        scheduleInRootZone: i = bm
      } = t;
      if (typeof Zone > "u") throw new v(908, !1);
      Zone.assertZonePatched();
      let s = this;
      s._nesting = 0, s._outer = s._inner = Zone.current, Zone.TaskTrackingZoneSpec && (s._inner = s._inner.fork(new Zone.TaskTrackingZoneSpec)), n && Zone.longStackTraceZoneSpec && (s._inner = s._inner.fork(Zone.longStackTraceZoneSpec)), s.shouldCoalesceEventChangeDetection = !o && r, s.shouldCoalesceRunChangeDetection = o, s.callbackScheduled = !1, s.scheduleInRootZone = i, Cw(s)
    }
    static isInAngularZone() {
      return typeof Zone < "u" && Zone.current.get(Kl) === !0
    }
    static assertInAngularZone() {
      if (!e.isInAngularZone()) throw new v(909, !1)
    }
    static assertNotInAngularZone() {
      if (e.isInAngularZone()) throw new v(909, !1)
    }
    run(t, n, r) {
      return this._inner.run(t, n, r)
    }
    runTask(t, n, r, o) {
      let i = this._inner,
        s = i.scheduleEventTask("NgZoneEvent: " + o, t, Iw, vn, vn);
      try {
        return i.runTask(s, n, r)
      } finally {
        i.cancelTask(s)
      }
    }
    runGuarded(t, n, r) {
      return this._inner.runGuarded(t, n, r)
    }
    runOutsideAngular(t) {
      return this._outer.run(t)
    }
  }, Iw = {};
  Cs = class {
    hasPendingMicrotasks = !1;
    hasPendingMacrotasks = !1;
    isStable = !0;
    onUnstable = new yt;
    onMicrotaskEmpty = new yt;
    onStable = new yt;
    onError = new yt;
    run(t, n, r) {
      return t.apply(n, r)
    }
    runGuarded(t, n, r) {
      return t.apply(n, r)
    }
    runOutsideAngular(t) {
      return t()
    }
    runTask(t, n, r, o) {
      return t.apply(n, r)
    }
  };
  $s = (() => {
    class e {
      impl = null;
      execute() {
        this.impl?.execute()
      }
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: () => new e
      })
    }
    return e
  })(), Xl = [0, 1, 2, 3], ed = (() => {
    class e {
      ngZone = y(z);
      scheduler = y(Te);
      errorHandler = y(De, {
        optional: !0
      });
      sequences = new Set;
      deferredRegistrations = new Set;
      executing = !1;
      constructor() {
        y(Lt, {
          optional: !0
        })
      }
      execute() {
        let n = this.sequences.size > 0;
        n && L(16), this.executing = !0;
        for (let r of Xl)
          for (let o of this.sequences)
            if (!(o.erroredOrDestroyed || !o.hooks[r])) try {
              o.pipelinedValue = this.ngZone.runOutsideAngular(() => this.maybeTrace(() => {
                let i = o.hooks[r];
                return i(o.pipelinedValue)
              }, o.snapshot))
            } catch (i) {
              o.erroredOrDestroyed = !0, this.errorHandler?.handleError(i)
            }
        this.executing = !1;
        for (let r of this.sequences) r.afterRun(), r.once && (this.sequences.delete(r), r.destroy());
        for (let r of this.deferredRegistrations) this.sequences.add(r);
        this.deferredRegistrations.size > 0 && this.scheduler.notify(7), this.deferredRegistrations.clear(), n && L(17)
      }
      register(n) {
        let {
          view: r
        } = n;
        r !== void 0 ? ((r[fn] ??= []).push(n), Rt(r), r[A] |= 8192) : this.executing ? this.deferredRegistrations.add(n) : this.addSequence(n)
      }
      addSequence(n) {
        this.sequences.add(n), this.scheduler.notify(7)
      }
      unregister(n) {
        this.executing && this.sequences.has(n) ? (n.erroredOrDestroyed = !0, n.pipelinedValue = void 0, n.once = !0) : (this.sequences.delete(n), this.deferredRegistrations.delete(n))
      }
      maybeTrace(n, r) {
        return r ? r.run(Us.AFTER_NEXT_RENDER, n) : n()
      }
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: () => new e
      })
    }
    return e
  })(), uo = class {
    impl;
    hooks;
    view;
    once;
    snapshot;
    erroredOrDestroyed = !1;
    pipelinedValue = void 0;
    unregisterOnDestroy;
    constructor(t, n, r, o, i, s = null) {
      this.impl = t, this.hooks = n, this.view = r, this.once = o, this.snapshot = s, this.unregisterOnDestroy = i?.onDestroy(() => this.destroy())
    }
    afterRun() {
      this.erroredOrDestroyed = !1, this.pipelinedValue = void 0, this.snapshot?.dispose(), this.snapshot = null
    }
    destroy() {
      this.impl.unregister(this), this.unregisterOnDestroy?.();
      let t = this.view?.[fn];
      t && (this.view[fn] = t.filter(n => n !== this))
    }
  };
  Mm = new T("", {
    providedIn: "root",
    factory: () => ({
      queue: new Set,
      isScheduled: !1,
      scheduler: null
    })
  });
  Bw = jw;
  Gw = () => null;
  Hm = [];
  iC = G(V({}, Ut), {
    consumerIsAlwaysLive: !0,
    kind: "template",
    consumerMarkedDirty: e => {
      Rt(e.lView)
    },
    consumerOnSignalRead() {
      this.lView[Ie] = this
    }
  });
  aC = G(V({}, Ut), {
    consumerIsAlwaysLive: !0,
    kind: "template",
    consumerMarkedDirty: e => {
      let t = St(e.lView);
      for (; t && !Um(t[w]);) t = St(t);
      t && hu(t)
    },
    consumerOnSignalRead() {
      this.lView[Ie] = this
    }
  });
  cC = 100;
  kt = class {
    _lView;
    _cdRefInjectingView;
    _appRef = null;
    _attachedToViewContainer = !1;
    exhaustive;
    get rootNodes() {
      let t = this._lView,
        n = t[w];
      return lo(n, t, n.firstChild, [])
    }
    constructor(t, n) {
      this._lView = t, this._cdRefInjectingView = n
    }
    get context() {
      return this._lView[q]
    }
    set context(t) {
      this._lView[q] = t
    }
    get destroyed() {
      return gn(this._lView)
    }
    destroy() {
      if (this._appRef) this._appRef.detachView(this);
      else if (this._attachedToViewContainer) {
        let t = this._lView[te];
        if (Pe(t)) {
          let n = t[Kr],
            r = n ? n.indexOf(this) : -1;
          r > -1 && (fo(t, r), Zr(n, r))
        }
        this._attachedToViewContainer = !1
      }
      zs(this._lView[w], this._lView)
    }
    onDestroy(t) {
      gu(this._lView, t)
    }
    markForCheck() {
      cd(this._cdRefInjectingView || this._lView, 4)
    }
    detach() {
      this._lView[A] &= -129
    }
    reattach() {
      Qi(this._lView), this._lView[A] |= 128
    }
    detectChanges() {
      this._lView[A] |= 1024, zm(this._lView)
    }
    checkNoChanges() {}
    attachToViewContainerRef() {
      if (this._appRef) throw new v(902, !1);
      this._attachedToViewContainer = !0
    }
    detachFromAppRef() {
      this._appRef = null;
      let t = rr(this._lView),
        n = this._lView[At];
      n !== null && !t && td(n, this._lView), Nm(this._lView[w], this._lView)
    }
    attachToAppRef(t) {
      if (this._attachedToViewContainer) throw new v(902, !1);
      this._appRef = t;
      let n = rr(this._lView),
        r = this._lView[At];
      r !== null && !n && Km(r, this._lView), Qi(this._lView)
    }
  }, nt = (() => {
    class e {
      _declarationLView;
      _declarationTContainer;
      elementRef;
      static __NG_ELEMENT_ID__ = gC;
      constructor(n, r, o) {
        this._declarationLView = n, this._declarationTContainer = r, this.elementRef = o
      }
      get ssrId() {
        return this._declarationTContainer.tView?.ssrId || null
      }
      createEmbeddedView(n, r) {
        return this.createEmbeddedViewImpl(n, r)
      }
      createEmbeddedViewImpl(n, r, o) {
        let i = Eo(this._declarationLView, this._declarationTContainer, n, {
          embeddedViewInjector: r,
          dehydratedView: o
        });
        return new kt(i)
      }
    }
    return e
  })();
  BP = new RegExp(`^(\\d+)*(${II}|${EI})*(.*)`);
  IC = () => null, wC = () => null;
  Xm = class {}, Ys = class {}, fl = class {
    resolveComponentFactory(t) {
      throw new v(917, !1)
    }
  }, wo = class {
    static NULL = new fl
  }, wn = class {}, Co = (() => {
    class e {
      destroyNode = null;
      static __NG_ELEMENT_ID__ = () => CC()
    }
    return e
  })();
  ey = (() => {
    class e {
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: () => null
      })
    }
    return e
  })(), ps = {}, pl = class {
    injector;
    parentInjector;
    constructor(t, n) {
      this.injector = t, this.parentInjector = n
    }
    get(t, n, r) {
      let o = this.injector.get(t, ps, r);
      return o !== ps || n === ps ? o : this.parentInjector.get(t, n, r)
    }
  };
  hl = Symbol("BINDING"), _s = class extends wo {
    ngModule;
    constructor(t) {
      super(), this.ngModule = t
    }
    resolveComponentFactory(t) {
      let n = Qe(t);
      return new Pt(n, this.ngModule)
    }
  };
  Pt = class extends Ys {
    componentDef;
    ngModule;
    selector;
    componentType;
    ngContentSelectors;
    isBoundToModule;
    cachedInputs = null;
    cachedOutputs = null;
    get inputs() {
      return this.cachedInputs ??= VC(this.componentDef.inputs), this.cachedInputs
    }
    get outputs() {
      return this.cachedOutputs ??= HC(this.componentDef.outputs), this.cachedOutputs
    }
    constructor(t, n) {
      super(), this.componentDef = t, this.ngModule = n, this.componentType = t.type, this.selector = pw(t.selectors), this.ngContentSelectors = t.ngContentSelectors ?? [], this.isBoundToModule = !!n
    }
    create(t, n, r, o, i, s) {
      L(22);
      let a = M(null);
      try {
        let c = this.componentDef,
          u = GC(r, c, s, i),
          l = UC(c, o || this.ngModule, t),
          d = $C(l),
          p = d.rendererFactory.createRenderer(null, c),
          f = r ? $w(p, r, c.encapsulation, l) : zC(c, p),
          g = s?.some(vg) || i?.some(m => typeof m != "function" && m.bindings.some(vg)),
          I = Zl(null, u, null, 512 | Im(c), null, null, d, p, l, null, rm(f, l, !0));
        I[H] = f, es(I);
        let D = null;
        try {
          let m = ud(H, I, 2, "#host", () => u.directiveRegistry, !0, 0);
          gm(p, f, m), dr(f, I), Ws(u, I, m), Bl(u, m, I), ld(u, m), n !== void 0 && qC(m, this.ngContentSelectors, n), D = Ne(m.index, I), I[q] = D[q], ad(u, I, null)
        } catch (m) {
          throw D !== null && Qu(D), Qu(I), m
        } finally {
          L(23), ts()
        }
        return new Ms(this.componentType, I, !!g)
      } finally {
        M(a)
      }
    }
  };
  Ms = class extends Xm {
    _rootLView;
    _hasInputBindings;
    instance;
    hostView;
    changeDetectorRef;
    componentType;
    location;
    previousInputValues = null;
    _tNode;
    constructor(t, n, r) {
      super(), this._rootLView = n, this._hasInputBindings = r, this._tNode = Jr(n[w], H), this.location = mr(this._tNode, n), this.instance = Ne(this._tNode.index, n)[q], this.hostView = this.changeDetectorRef = new kt(n, void 0), this.componentType = t
    }
    setInput(t, n) {
      this._hasInputBindings;
      let r = this._tNode;
      if (this.previousInputValues ??= new Map, this.previousInputValues.has(t) && Object.is(this.previousInputValues.get(t), n)) return;
      let o = this._rootLView,
        i = qs(r, o[w], o, t, n);
      this.previousInputValues.set(t, n);
      let s = Ne(r.index, o);
      cd(s, 1)
    }
    get injector() {
      return new Dn(this._tNode, this._rootLView)
    }
    destroy() {
      this.hostView.destroy()
    }
    onDestroy(t) {
      this.hostView.onDestroy(t)
    }
  };
  ot = (() => {
    class e {
      static __NG_ELEMENT_ID__ = ZC
    }
    return e
  })();
  YC = ot, ay = class extends YC {
    _lContainer;
    _hostTNode;
    _hostLView;
    constructor(t, n, r) {
      super(), this._lContainer = t, this._hostTNode = n, this._hostLView = r
    }
    get element() {
      return mr(this._hostTNode, this._hostLView)
    }
    get injector() {
      return new Dn(this._hostTNode, this._hostLView)
    }
    get parentInjector() {
      let t = Fl(this._hostTNode, this._hostLView);
      if (Lg(t)) {
        let n = ys(t, this._hostLView),
          r = ms(t),
          o = n[w].data[r + 8];
        return new Dn(o, n)
      } else return new Dn(null, this._hostLView)
    }
    clear() {
      for (; this.length > 0;) this.remove(this.length - 1)
    }
    get(t) {
      let n = Dg(this._lContainer);
      return n !== null && n[t] || null
    }
    get length() {
      return this._lContainer.length - Z
    }
    createEmbeddedView(t, n, r) {
      let o, i;
      typeof r == "number" ? o = r : r != null && (o = r.index, i = r.injector);
      let s = bs(this._lContainer, t.ssrId),
        a = t.createEmbeddedViewImpl(n || {}, i, s);
      return this.insertImpl(a, o, fr(this._hostTNode, s)), a
    }
    createComponent(t, n, r, o, i, s, a) {
      let c = t && !qE(t),
        u;
      if (c) u = n;
      else {
        let D = n || {};
        u = D.index, r = D.injector, o = D.projectableNodes, i = D.environmentInjector || D.ngModuleRef, s = D.directives, a = D.bindings
      }
      let l = c ? t : new Pt(Qe(t)),
        d = r || this.parentInjector;
      if (!i && l.ngModule == null) {
        let m = (c ? d : this.parentInjector).get(ye, null);
        m && (i = m)
      }
      let p = Qe(l.componentType ?? {}),
        f = bs(this._lContainer, p?.id ?? null),
        g = f?.firstChild ?? null,
        I = l.create(d, o, g, i, s, a);
      return this.insertImpl(I.hostView, u, fr(this._hostTNode, f)), I
    }
    insert(t, n) {
      return this.insertImpl(t, n, !0)
    }
    insertImpl(t, n, r) {
      let o = t._lView;
      if (wh(o)) {
        let a = this.indexOf(t);
        if (a !== -1) this.detach(a);
        else {
          let c = o[te],
            u = new ay(c, c[fe], c[te]);
          u.detach(u.indexOf(t))
        }
      }
      let i = this._adjustIndex(n),
        s = this._lContainer;
      return Io(s, o, i, r), t.attachToViewContainerRef(), Jc(Bu(s), i, t), t
    }
    move(t, n) {
      return this.insert(t, n)
    }
    indexOf(t) {
      let n = Dg(this._lContainer);
      return n !== null ? n.indexOf(t) : -1
    }
    remove(t) {
      let n = this._adjustIndex(t, -1),
        r = fo(this._lContainer, n);
      r && (Zr(Bu(this._lContainer), n), zs(r[w], r))
    }
    detach(t) {
      let n = this._adjustIndex(t, -1),
        r = fo(this._lContainer, n);
      return r && Zr(Bu(this._lContainer), n) != null ? new kt(r) : null
    }
    _adjustIndex(t, n = 0) {
      return t ?? this.length + n
    }
  };
  KC = eb, JC = () => !1;
  gl = class e {
    queryList;
    matches = null;
    constructor(t) {
      this.queryList = t
    }
    clone() {
      return new e(this.queryList)
    }
    setDirty() {
      this.queryList.setDirty()
    }
  }, ml = class e {
    queries;
    constructor(t = []) {
      this.queries = t
    }
    createEmbeddedView(t) {
      let n = t.queries;
      if (n !== null) {
        let r = t.contentQueries !== null ? t.contentQueries[0] : n.length,
          o = [];
        for (let i = 0; i < r; i++) {
          let s = n.getByIndex(i),
            a = this.queries[s.indexInDeclarationView];
          o.push(a.clone())
        }
        return new e(o)
      }
      return null
    }
    insertView(t) {
      this.dirtyQueriesWithMatches(t)
    }
    detachView(t) {
      this.dirtyQueriesWithMatches(t)
    }
    finishViewCreation(t) {
      this.dirtyQueriesWithMatches(t)
    }
    dirtyQueriesWithMatches(t) {
      for (let n = 0; n < this.queries.length; n++) pd(t, n).matches !== null && this.queries[n].setDirty()
    }
  }, Ss = class {
    flags;
    read;
    predicate;
    constructor(t, n, r = null) {
      this.flags = n, this.read = r, typeof t == "string" ? this.predicate = ib(t) : this.predicate = t
    }
  }, yl = class e {
    queries;
    constructor(t = []) {
      this.queries = t
    }
    elementStart(t, n) {
      for (let r = 0; r < this.queries.length; r++) this.queries[r].elementStart(t, n)
    }
    elementEnd(t) {
      for (let n = 0; n < this.queries.length; n++) this.queries[n].elementEnd(t)
    }
    embeddedTView(t) {
      let n = null;
      for (let r = 0; r < this.length; r++) {
        let o = n !== null ? n.length : 0,
          i = this.getByIndex(r).embeddedTView(t, o);
        i && (i.indexInDeclarationView = r, n !== null ? n.push(i) : n = [i])
      }
      return n !== null ? new e(n) : null
    }
    template(t, n) {
      for (let r = 0; r < this.queries.length; r++) this.queries[r].template(t, n)
    }
    getByIndex(t) {
      return this.queries[t]
    }
    get length() {
      return this.queries.length
    }
    track(t) {
      this.queries.push(t)
    }
  }, vl = class e {
    metadata;
    matches = null;
    indexInDeclarationView = -1;
    crossesNgTemplate = !1;
    _declarationNodeIndex;
    _appliesToNextNode = !0;
    constructor(t, n = -1) {
      this.metadata = t, this._declarationNodeIndex = n
    }
    elementStart(t, n) {
      this.isApplyingToNode(n) && this.matchTNode(t, n)
    }
    elementEnd(t) {
      this._declarationNodeIndex === t.index && (this._appliesToNextNode = !1)
    }
    template(t, n) {
      this.elementStart(t, n)
    }
    embeddedTView(t, n) {
      return this.isApplyingToNode(t) ? (this.crossesNgTemplate = !0, this.addMatch(-t.index, n), new e(this.metadata)) : null
    }
    isApplyingToNode(t) {
      if (this._appliesToNextNode && (this.metadata.flags & 1) !== 1) {
        let n = this._declarationNodeIndex,
          r = t.parent;
        for (; r !== null && r.type & 8 && r.index !== n;) r = r.parent;
        return n === (r !== null ? r.index : -1)
      }
      return this._appliesToNextNode
    }
    matchTNode(t, n) {
      let r = this.metadata.predicate;
      if (Array.isArray(r))
        for (let o = 0; o < r.length; o++) {
          let i = r[o];
          this.matchTNodeWithReadOption(t, n, tb(n, i)), this.matchTNodeWithReadOption(t, n, fs(n, t, i, !1, !1))
        } else r === nt ? n.type & 4 && this.matchTNodeWithReadOption(t, n, -1) : this.matchTNodeWithReadOption(t, n, fs(n, t, r, !1, !1))
    }
    matchTNodeWithReadOption(t, n, r) {
      if (r !== null) {
        let o = this.metadata.read;
        if (o !== null)
          if (o === Et || o === ot || o === nt && n.type & 4) this.addMatch(n.index, -2);
          else {
            let i = fs(n, t, o, !1, !1);
            i !== null && this.addMatch(n.index, i)
          }
        else this.addMatch(n.index, r)
      }
    }
    addMatch(t, n) {
      this.matches === null ? this.matches = [t, n] : this.matches.push(t, n)
    }
  };
  Cn = class {}, yy = class {}, Ns = class extends Cn {
    ngModuleType;
    _parent;
    _bootstrapComponents = [];
    _r3Injector;
    instance;
    destroyCbs = [];
    componentFactoryResolver = new _s(this);
    constructor(t, n, r, o = !0) {
      super(), this.ngModuleType = t, this._parent = n;
      let i = tu(t);
      this._bootstrapComponents = vm(i.bootstrap), this._r3Injector = Nu(t, n, [{
        provide: Cn,
        useValue: this
      }, {
        provide: wo,
        useValue: this.componentFactoryResolver
      }, ...r], ft(t), new Set(["environment"])), o && this.resolveInjectorInitializers()
    }
    resolveInjectorInitializers() {
      this._r3Injector.resolveInjectorInitializers(), this.instance = this._r3Injector.get(this.ngModuleType)
    }
    get injector() {
      return this._r3Injector
    }
    destroy() {
      let t = this._r3Injector;
      !t.destroyed && t.destroy(), this.destroyCbs.forEach(n => n()), this.destroyCbs = null
    }
    onDestroy(t) {
      this.destroyCbs.push(t)
    }
  }, As = class extends yy {
    moduleType;
    constructor(t) {
      super(), this.moduleType = t
    }
    create(t) {
      return new Ns(this.moduleType, t, [])
    }
  }, ho = class extends Cn {
    injector;
    componentFactoryResolver = new _s(this);
    instance = null;
    constructor(t) {
      super();
      let n = new an([...t.providers, {
        provide: Cn,
        useValue: this
      }, {
        provide: wo,
        useValue: this.componentFactoryResolver
      }], t.parent || Jn(), t.debugName, new Set(["environment"]));
      this.injector = n, t.runEnvironmentInitializers && n.resolveInjectorInitializers()
    }
    destroy() {
      this.injector.destroy()
    }
    onDestroy(t) {
      this.injector.onDestroy(t)
    }
  };
  cb = (() => {
    class e {
      _injector;
      cachedInjectors = new Map;
      constructor(n) {
        this._injector = n
      }
      getOrCreateStandaloneInjector(n) {
        if (!n.standalone) return null;
        if (!this.cachedInjectors.has(n)) {
          let r = nu(!1, n.type),
            o = r.length > 0 ? vy([r], this._injector, `Standalone[${n.type.name}]`) : null;
          this.cachedInjectors.set(n, o)
        }
        return this.cachedInjectors.get(n)
      }
      ngOnDestroy() {
        try {
          for (let n of this.cachedInjectors.values()) n !== null && n.destroy()
        } finally {
          this.cachedInjectors.clear()
        }
      }
      static \u0275prov = N({
        token: e,
        providedIn: "environment",
        factory: () => new e(C(ye))
      })
    }
    return e
  })();
  bb = Tb;
  _y = (() => {
    class e {
      log(n) {
        console.log(n)
      }
      warn(n) {
        console.warn(n)
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "platform"
      })
    }
    return e
  })();
  Js = new T(""), vr = new T(""), To = (() => {
    class e {
      _ngZone;
      registry;
      _isZoneStable = !0;
      _callbacks = [];
      _taskTrackingZone = null;
      _destroyRef;
      constructor(n, r, o) {
        this._ngZone = n, this.registry = r, iu() && (this._destroyRef = y(Ae, {
          optional: !0
        }) ?? void 0), md || (My(o), o.addToWindow(r)), this._watchAngularEvents(), n.run(() => {
          this._taskTrackingZone = typeof Zone > "u" ? null : Zone.current.get("TaskTrackingZone")
        })
      }
      _watchAngularEvents() {
        let n = this._ngZone.onUnstable.subscribe({
            next: () => {
              this._isZoneStable = !1
            }
          }),
          r = this._ngZone.runOutsideAngular(() => this._ngZone.onStable.subscribe({
            next: () => {
              z.assertNotInAngularZone(), queueMicrotask(() => {
                this._isZoneStable = !0, this._runCallbacksIfReady()
              })
            }
          }));
        this._destroyRef?.onDestroy(() => {
          n.unsubscribe(), r.unsubscribe()
        })
      }
      isStable() {
        return this._isZoneStable && !this._ngZone.hasPendingMacrotasks
      }
      _runCallbacksIfReady() {
        if (this.isStable()) queueMicrotask(() => {
          for (; this._callbacks.length !== 0;) {
            let n = this._callbacks.pop();
            clearTimeout(n.timeoutId), n.doneCb()
          }
        });
        else {
          let n = this.getPendingTasks();
          this._callbacks = this._callbacks.filter(r => r.updateCb && r.updateCb(n) ? (clearTimeout(r.timeoutId), !1) : !0)
        }
      }
      getPendingTasks() {
        return this._taskTrackingZone ? this._taskTrackingZone.macroTasks.map(n => ({
          source: n.source,
          creationLocation: n.creationLocation,
          data: n.data
        })) : []
      }
      addCallback(n, r, o) {
        let i = -1;
        r && r > 0 && (i = setTimeout(() => {
          this._callbacks = this._callbacks.filter(s => s.timeoutId !== i), n()
        }, r)), this._callbacks.push({
          doneCb: n,
          timeoutId: i,
          updateCb: o
        })
      }
      whenStable(n, r, o) {
        if (o && !this._taskTrackingZone) throw new Error('Task tracking zone is required when passing an update callback to whenStable(). Is "zone.js/plugins/task-tracking" loaded?');
        this.addCallback(n, r, o), this._runCallbacksIfReady()
      }
      registerApplication(n) {
        this.registry.registerApplication(n, this)
      }
      unregisterApplication(n) {
        this.registry.unregisterApplication(n)
      }
      findProviders(n, r, o) {
        return []
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(z), C(_o), C(vr))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), _o = (() => {
    class e {
      _applications = new Map;
      registerApplication(n, r) {
        this._applications.set(n, r)
      }
      unregisterApplication(n) {
        this._applications.delete(n)
      }
      unregisterAllApplications() {
        this._applications.clear()
      }
      getTestability(n) {
        return this._applications.get(n) || null
      }
      getAllTestabilities() {
        return Array.from(this._applications.values())
      }
      getAllRootElements() {
        return Array.from(this._applications.keys())
      }
      findTestabilityInTree(n, r = !0) {
        return md?.findTestabilityInTree(this, n, r) ?? null
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "platform"
      })
    }
    return e
  })();
  yd = new T("");
  vd = (() => {
    class e {
      resolve;
      reject;
      initialized = !1;
      done = !1;
      donePromise = new Promise((n, r) => {
        this.resolve = n, this.reject = r
      });
      appInits = y(yd, {
        optional: !0
      }) ?? [];
      injector = y(ve);
      constructor() {}
      runInitializers() {
        if (this.initialized) return;
        let n = [];
        for (let o of this.appInits) {
          let i = Xn(this.injector, o);
          if (Mo(i)) n.push(i);
          else if (Xs(i)) {
            let s = new Promise((a, c) => {
              i.subscribe({
                complete: a,
                error: c
              })
            });
            n.push(s)
          }
        }
        let r = () => {
          this.done = !0, this.resolve()
        };
        Promise.all(n).then(() => {
          r()
        }).catch(o => {
          this.reject(o)
        }), n.length === 0 && r(), this.initialized = !0
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })(), Sy = new T("");
  Mb = 10, Tn = (() => {
    class e {
      _runningTick = !1;
      _destroyed = !1;
      _destroyListeners = [];
      _views = [];
      internalErrorHandler = y(Be);
      afterRenderManager = y($s);
      zonelessEnabled = y(ro);
      rootEffectScheduler = y(oo);
      dirtyFlags = 0;
      tracingSnapshot = null;
      allTestViews = new Set;
      autoDetectTestViews = new Set;
      includeAllTestViews = !1;
      afterTick = new ge;
      get allViews() {
        return [...(this.includeAllTestViews ? this.allTestViews : this.autoDetectTestViews).keys(), ...this._views]
      }
      get destroyed() {
        return this._destroyed
      }
      componentTypes = [];
      components = [];
      internalPendingTask = y(Ft);
      get isStable() {
        return this.internalPendingTask.hasPendingTasksObservable.pipe(le(n => !n))
      }
      constructor() {
        y(Lt, {
          optional: !0
        })
      }
      whenStable() {
        let n;
        return new Promise(r => {
          n = this.isStable.subscribe({
            next: o => {
              o && r()
            }
          })
        }).finally(() => {
          n.unsubscribe()
        })
      }
      _injector = y(ye);
      _rendererFactory = null;
      get injector() {
        return this._injector
      }
      bootstrap(n, r) {
        return this.bootstrapImpl(n, r)
      }
      bootstrapImpl(n, r, o = ve.NULL) {
        return this._injector.get(z).run(() => {
          L(10);
          let s = n instanceof Ys;
          if (!this._injector.get(vd).done) {
            let g = "";
            throw new v(405, g)
          }
          let c;
          s ? c = n : c = this._injector.get(wo).resolveComponentFactory(n), this.componentTypes.push(c.componentType);
          let u = Ay(c) ? void 0 : this._injector.get(Cn),
            l = r || c.selector,
            d = c.create(o, [], l, u),
            p = d.location.nativeElement,
            f = d.injector.get(Js, null);
          return f?.registerApplication(p), d.onDestroy(() => {
            this.detachView(d.hostView), ao(this.components, d), f?.unregisterApplication(p)
          }), this._loadComponent(d), L(11, d), d
        })
      }
      tick() {
        this.zonelessEnabled || (this.dirtyFlags |= 1), this._tick()
      }
      _tick() {
        L(12), this.tracingSnapshot !== null ? this.tracingSnapshot.run(Us.CHANGE_DETECTION, this.tickImpl) : this.tickImpl()
      }
      tickImpl = () => {
        if (this._runningTick) throw new v(101, !1);
        let n = M(null);
        try {
          this._runningTick = !0, this.synchronize()
        } finally {
          this._runningTick = !1, this.tracingSnapshot?.dispose(), this.tracingSnapshot = null, M(n), this.afterTick.next(), L(13)
        }
      };
      synchronize() {
        this._rendererFactory === null && !this._injector.destroyed && (this._rendererFactory = this._injector.get(wn, null, {
          optional: !0
        }));
        let n = 0;
        for (; this.dirtyFlags !== 0 && n++ < Mb;) L(14), this.synchronizeOnce(), L(15)
      }
      synchronizeOnce() {
        this.dirtyFlags & 16 && (this.dirtyFlags &= -17, this.rootEffectScheduler.flush());
        let n = !1;
        if (this.dirtyFlags & 7) {
          let r = !!(this.dirtyFlags & 1);
          this.dirtyFlags &= -8, this.dirtyFlags |= 8;
          for (let {
              _lView: o
            }
            of this.allViews) {
            if (!r && !Xr(o)) continue;
            let i = r && !this.zonelessEnabled ? 0 : 1;
            zm(o, i), n = !0
          }
          if (this.dirtyFlags &= -5, this.syncDirtyFlagsWithViews(), this.dirtyFlags & 23) return
        }
        n || (this._rendererFactory?.begin?.(), this._rendererFactory?.end?.()), this.dirtyFlags & 8 && (this.dirtyFlags &= -9, this.afterRenderManager.execute()), this.syncDirtyFlagsWithViews()
      }
      syncDirtyFlagsWithViews() {
        if (this.allViews.some(({
            _lView: n
          }) => Xr(n))) {
          this.dirtyFlags |= 2;
          return
        } else this.dirtyFlags &= -8
      }
      attachView(n) {
        let r = n;
        this._views.push(r), r.attachToAppRef(this)
      }
      detachView(n) {
        let r = n;
        ao(this._views, r), r.detachFromAppRef()
      }
      _loadComponent(n) {
        this.attachView(n.hostView);
        try {
          this.tick()
        } catch (o) {
          this.internalErrorHandler(o)
        }
        this.components.push(n), this._injector.get(Sy, []).forEach(o => o(n))
      }
      ngOnDestroy() {
        if (!this._destroyed) try {
          this._destroyListeners.forEach(n => n()), this._views.slice().forEach(n => n.destroy())
        } finally {
          this._destroyed = !0, this._views = [], this._destroyListeners = []
        }
      }
      onDestroy(n) {
        return this._destroyListeners.push(n), () => ao(this._destroyListeners, n)
      }
      destroy() {
        if (this._destroyed) throw new v(406, !1);
        let n = this._injector;
        n.destroy && !n.destroyed && n.destroy()
      }
      get viewCount() {
        return this._views.length
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })();
  WP = typeof document < "u" && typeof document?.documentElement?.getAnimations == "function";
  Il = class {
    destroy(t) {}
    updateValue(t, n) {}
    swap(t, n) {
      let r = Math.min(t, n),
        o = Math.max(t, n),
        i = this.detach(o);
      if (o - r > 1) {
        let s = this.detach(r);
        this.attach(r, i), this.attach(o, s)
      } else this.attach(r, i)
    }
    move(t, n) {
      this.attach(n, this.detach(t))
    }
  };
  xs = class {
    kvMap = new Map;
    _vMap = void 0;
    has(t) {
      return this.kvMap.has(t)
    }
    delete(t) {
      if (!this.has(t)) return !1;
      let n = this.kvMap.get(t);
      return this._vMap !== void 0 && this._vMap.has(n) ? (this.kvMap.set(t, this._vMap.get(n)), this._vMap.delete(n)) : this.kvMap.delete(t), !0
    }
    get(t) {
      return this.kvMap.get(t)
    }
    set(t, n) {
      if (this.kvMap.has(t)) {
        let r = this.kvMap.get(t);
        this._vMap === void 0 && (this._vMap = new Map);
        let o = this._vMap;
        for (; o.has(r);) r = o.get(r);
        o.set(r, n)
      } else this.kvMap.set(t, n)
    }
    forEach(t) {
      for (let [n, r] of this.kvMap)
        if (t(r, n), this._vMap !== void 0) {
          let o = this._vMap;
          for (; o.has(r);) r = o.get(r), t(r, n)
        }
    }
  };
  Cl = class {
    lContainer;
    $implicit;
    $index;
    constructor(t, n, r) {
      this.lContainer = t, this.$implicit = n, this.$index = r
    }
    get $count() {
      return this.lContainer.length - Z
    }
  };
  bl = class {
    hasEmptyBlock;
    trackByFn;
    liveCollection;
    constructor(t, n, r) {
      this.hasEmptyBlock = t, this.trackByFn = n, this.liveCollection = r
    }
  };
  Tl = class extends Il {
    lContainer;
    hostLView;
    templateTNode;
    operationsCounter = void 0;
    needsIndexUpdate = !1;
    constructor(t, n, r) {
      super(), this.lContainer = t, this.hostLView = n, this.templateTNode = r
    }
    get length() {
      return this.lContainer.length - Z
    }
    at(t) {
      return this.getLView(t)[q].$implicit
    }
    attach(t, n) {
      let r = n[un];
      this.needsIndexUpdate ||= t !== this.length, Io(this.lContainer, n, t, fr(this.templateTNode, r)), Pb(this.lContainer, t)
    }
    detach(t) {
      return this.needsIndexUpdate ||= t !== this.length - 1, Lb(this.lContainer, t), jb(this.lContainer, t)
    }
    create(t, n) {
      let r = bs(this.lContainer, this.templateTNode.tView.ssrId),
        o = Eo(this.hostLView, this.templateTNode, new Cl(this.lContainer, n, t), {
          dehydratedView: r
        });
      return this.operationsCounter?.recordCreate(), o
    }
    destroy(t) {
      zs(t[w], t), this.operationsCounter?.recordDestroy()
    }
    updateValue(t, n) {
      this.getLView(t)[q].$implicit = n
    }
    reset() {
      this.needsIndexUpdate = !1, this.operationsCounter?.reset()
    }
    updateIndexes() {
      if (this.needsIndexUpdate)
        for (let t = 0; t < this.length; t++) this.getLView(t)[q].$index = t
    }
    getLView(t) {
      return Bb(this.lContainer, t)
    }
  };
  Py = (e, t, n, r, o) => (no(!0), fm(t[P], r, $h()));
  Vb = (e, t, n, r, o) => (no(!0), ZI(t[P], ""));
  cs = void 0;
  $b = ["en", [
      ["a", "p"],
      ["AM", "PM"]
    ],
    [
      ["AM", "PM"]
    ],
    [
      ["S", "M", "T", "W", "T", "F", "S"],
      ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
      ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"],
      ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"]
    ], cs, [
      ["J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"],
      ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
      ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    ], cs, [
      ["B", "A"],
      ["BC", "AD"],
      ["Before Christ", "Anno Domini"]
    ], 0, [6, 0],
    ["M/d/yy", "MMM d, y", "MMMM d, y", "EEEE, MMMM d, y"],
    ["h:mm a", "h:mm:ss a", "h:mm:ss a z", "h:mm:ss a zzzz"],
    ["{1}, {0}", cs, "{1} 'at' {0}", cs],
    [".", ",", ";", "%", "+", "-", "E", "\xD7", "‰", "∞", "NaN", ":"],
    ["#,##0.###", "#,##0%", "\xA4#,##0.00", "#E0"], "USD", "$", "US Dollar", {}, "ltr", Ub
  ], Uu = {};
  _n = (function(e) {
    return e[e.LocaleId = 0] = "LocaleId", e[e.DayPeriodsFormat = 1] = "DayPeriodsFormat", e[e.DayPeriodsStandalone = 2] = "DayPeriodsStandalone", e[e.DaysFormat = 3] = "DaysFormat", e[e.DaysStandalone = 4] = "DaysStandalone", e[e.MonthsFormat = 5] = "MonthsFormat", e[e.MonthsStandalone = 6] = "MonthsStandalone", e[e.Eras = 7] = "Eras", e[e.FirstDayOfWeek = 8] = "FirstDayOfWeek", e[e.WeekendRange = 9] = "WeekendRange", e[e.DateFormat = 10] = "DateFormat", e[e.TimeFormat = 11] = "TimeFormat", e[e.DateTimeFormat = 12] = "DateTimeFormat", e[e.NumberSymbols = 13] = "NumberSymbols", e[e.NumberFormats = 14] = "NumberFormats", e[e.CurrencyCode = 15] = "CurrencyCode", e[e.CurrencySymbol = 16] = "CurrencySymbol", e[e.CurrencyName = 17] = "CurrencyName", e[e.Currencies = 18] = "Currencies", e[e.Directionality = 19] = "Directionality", e[e.PluralCase = 20] = "PluralCase", e[e.ExtraData = 21] = "ExtraData", e
  })(_n || {});
  So = "en-US", Gb = So;
  He = {
    textEnd: 0,
    key: 0,
    keyEnd: 0,
    value: 0,
    valueEnd: 0
  };
  MT = (e, t, n, r, o) => (no(!0), WI(t[P], r));
  Fs = class {
    ngModuleFactory;
    componentFactories;
    constructor(t, n) {
      this.ngModuleFactory = t, this.componentFactories = n
    }
  }, ZT = (() => {
    class e {
      compileModuleSync(n) {
        return new As(n)
      }
      compileModuleAsync(n) {
        return Promise.resolve(this.compileModuleSync(n))
      }
      compileModuleAndAllComponentsSync(n) {
        let r = this.compileModuleSync(n),
          o = tu(n),
          i = vm(o.declarations).reduce((s, a) => {
            let c = Qe(a);
            return c && s.push(new Pt(c)), s
          }, []);
        return new Fs(r, i)
      }
      compileModuleAndAllComponentsAsync(n) {
        return Promise.resolve(this.compileModuleAndAllComponentsSync(n))
      }
      clearCache() {}
      clearCacheFor(n) {}
      getModuleId(n) {}
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })(), YT = (() => {
    class e {
      zone = y(z);
      changeDetectionScheduler = y(Te);
      applicationRef = y(Tn);
      applicationErrorHandler = y(Be);
      _onMicrotaskEmptySubscription;
      initialize() {
        this._onMicrotaskEmptySubscription || (this._onMicrotaskEmptySubscription = this.zone.onMicrotaskEmpty.subscribe({
          next: () => {
            this.changeDetectionScheduler.runningTick || this.zone.run(() => {
              try {
                this.applicationRef.dirtyFlags |= 1, this.applicationRef._tick()
              } catch (n) {
                this.applicationErrorHandler(n)
              }
            })
          }
        }))
      }
      ngOnDestroy() {
        this._onMicrotaskEmptySubscription?.unsubscribe()
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })();
  QT = (() => {
    class e {
      subscription = new W;
      initialized = !1;
      zone = y(z);
      pendingTasks = y(Ft);
      initialize() {
        if (this.initialized) return;
        this.initialized = !0;
        let n = null;
        !this.zone.isStable && !this.zone.hasPendingMacrotasks && !this.zone.hasPendingMicrotasks && (n = this.pendingTasks.add()), this.zone.runOutsideAngular(() => {
          this.subscription.add(this.zone.onStable.subscribe(() => {
            z.assertNotInAngularZone(), queueMicrotask(() => {
              n !== null && !this.zone.hasPendingMacrotasks && !this.zone.hasPendingMicrotasks && (this.pendingTasks.remove(n), n = null)
            })
          }))
        }), this.subscription.add(this.zone.onUnstable.subscribe(() => {
          z.assertInAngularZone(), n ??= this.pendingTasks.add()
        }))
      }
      ngOnDestroy() {
        this.subscription.unsubscribe()
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })(), dv = (() => {
    class e {
      applicationErrorHandler = y(Be);
      appRef = y(Tn);
      taskService = y(Ft);
      ngZone = y(z);
      zonelessEnabled = y(ro);
      tracing = y(Lt, {
        optional: !0
      });
      disableScheduling = y(Ou, {
        optional: !0
      }) ?? !1;
      zoneIsDefined = typeof Zone < "u" && !!Zone.root.run;
      schedulerTickApplyArgs = [{
        data: {
          __scheduler_tick__: !0
        }
      }];
      subscriptions = new W;
      angularZoneId = this.zoneIsDefined ? this.ngZone._inner?.get(ws) : null;
      scheduleInRootZone = !this.zonelessEnabled && this.zoneIsDefined && (y(Fu, {
        optional: !0
      }) ?? !1);
      cancelScheduledCallback = null;
      useMicrotaskScheduler = !1;
      runningTick = !1;
      pendingRenderTaskId = null;
      constructor() {
        this.subscriptions.add(this.appRef.afterTick.subscribe(() => {
          this.runningTick || this.cleanup()
        })), this.subscriptions.add(this.ngZone.onUnstable.subscribe(() => {
          this.runningTick || this.cleanup()
        })), this.disableScheduling ||= !this.zonelessEnabled && (this.ngZone instanceof Cs || !this.zoneIsDefined)
      }
      notify(n) {
        if (!this.zonelessEnabled && n === 5) return;
        let r = !1;
        switch (n) {
          case 0: {
            this.appRef.dirtyFlags |= 2;
            break
          }
          case 3:
          case 2:
          case 4:
          case 5:
          case 1: {
            this.appRef.dirtyFlags |= 4;
            break
          }
          case 6: {
            this.appRef.dirtyFlags |= 2, r = !0;
            break
          }
          case 12: {
            this.appRef.dirtyFlags |= 16, r = !0;
            break
          }
          case 13: {
            this.appRef.dirtyFlags |= 2, r = !0;
            break
          }
          case 11: {
            r = !0;
            break
          }
          case 9:
          case 8:
          case 7:
          case 10:
          default:
            this.appRef.dirtyFlags |= 8
        }
        if (this.appRef.tracingSnapshot = this.tracing?.snapshot(this.appRef.tracingSnapshot) ?? null, !this.shouldScheduleTick(r)) return;
        let o = this.useMicrotaskScheduler ? ag : Tm;
        this.pendingRenderTaskId = this.taskService.add(), this.scheduleInRootZone ? this.cancelScheduledCallback = Zone.root.run(() => o(() => this.tick())) : this.cancelScheduledCallback = this.ngZone.runOutsideAngular(() => o(() => this.tick()))
      }
      shouldScheduleTick(n) {
        return !(this.disableScheduling && !n || this.appRef.destroyed || this.pendingRenderTaskId !== null || this.runningTick || this.appRef._runningTick || !this.zonelessEnabled && this.zoneIsDefined && Zone.current.get(ws + this.angularZoneId))
      }
      tick() {
        if (this.runningTick || this.appRef.destroyed) return;
        if (this.appRef.dirtyFlags === 0) {
          this.cleanup();
          return
        }!this.zonelessEnabled && this.appRef.dirtyFlags & 7 && (this.appRef.dirtyFlags |= 1);
        let n = this.taskService.add();
        try {
          this.ngZone.run(() => {
            this.runningTick = !0, this.appRef._tick()
          }, void 0, this.schedulerTickApplyArgs)
        } catch (r) {
          this.taskService.remove(n), this.applicationErrorHandler(r)
        } finally {
          this.cleanup()
        }
        this.useMicrotaskScheduler = !0, ag(() => {
          this.useMicrotaskScheduler = !1, this.taskService.remove(n)
        })
      }
      ngOnDestroy() {
        this.subscriptions.unsubscribe(), this.cleanup()
      }
      cleanup() {
        if (this.runningTick = !1, this.cancelScheduledCallback?.(), this.cancelScheduledCallback = null, this.pendingRenderTaskId !== null) {
          let n = this.pendingRenderTaskId;
          this.pendingRenderTaskId = null, this.taskService.remove(n)
        }
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })();
  No = new T("", {
    providedIn: "root",
    factory: () => y(No, {
      optional: !0,
      skipSelf: !0
    }) || KT()
  })
});

function na(e) {
  return Jp(e)
}

function JT(e, t) {
  return Mr(e, t?.equal)
}

function XT(e, t) {
  let n = t?.injector ?? y(ve),
    r = t?.manualCleanup !== !0 ? n.get(Ae) : null,
    o, i = n.get(yn, null, {
      optional: !0
    }),
    s = n.get(Te);
  return i !== null ? (o = n_(i.view, s, e), r instanceof Wr && r._lView === i.view && (r = null)) : o = r_(e, n.get(oo), s), o.injector = n, r !== null && (o.onDestroyFn = r.onDestroy(() => o.destroy())), new Ad(o)
}

function n_(e, t, n) {
  let r = Object.create(t_);
  return r.view = e, r.zone = typeof Zone < "u" ? Zone.current : null, r.notifier = t, r.fn = pv(r, n), e[gt] ??= new Set, e[gt].add(r), r.consumerMarkedDirty(r), r
}

function r_(e, t, n) {
  let r = Object.create(e_);
  return r.fn = pv(r, e), r.scheduler = t, r.notifier = n, r.zone = typeof Zone < "u" ? Zone.current : null, r.scheduler.add(r), r.notifier.notify(12), r
}

function pv(e, t) {
  return () => {
    t(n => (e.cleanupFns ??= []).push(n))
  }
}
var ta, Ad, fv, e_, t_, xd = h(() => {
  io();
  Wt();
  th();
  ta = class {
    destroyed = !1;
    listeners = null;
    errorHandler = y(De, {
      optional: !0
    });
    destroyRef = y(Ae);
    constructor() {
      this.destroyRef.onDestroy(() => {
        this.destroyed = !0, this.listeners = null
      })
    }
    subscribe(t) {
      if (this.destroyed) throw new v(953, !1);
      return (this.listeners ??= []).push(t), {
        unsubscribe: () => {
          let n = this.listeners?.indexOf(t);
          n !== void 0 && n !== -1 && this.listeners?.splice(n, 1)
        }
      }
    }
    emit(t) {
      if (this.destroyed) {
        console.warn(Ye(953, !1));
        return
      }
      if (this.listeners === null) return;
      let n = M(null);
      try {
        for (let r of this.listeners) try {
          r(t)
        } catch (o) {
          this.errorHandler?.handleError(o)
        }
      } finally {
        M(n)
      }
    }
  };
  Ad = class {
    [X];
    constructor(t) {
      this[X] = t
    }
    destroy() {
      this[X].destroy()
    }
  };
  fv = G(V({}, Xp), {
    cleanupFns: void 0,
    zone: null,
    onDestroyFn: vn,
    run() {
      let e = ir(!1);
      try {
        eh(this)
      } finally {
        ir(e)
      }
    },
    cleanup() {
      if (!this.cleanupFns?.length) return;
      let e = M(null);
      try {
        for (; this.cleanupFns.length;) this.cleanupFns.pop()()
      } finally {
        this.cleanupFns = [], M(e)
      }
    }
  }), e_ = G(V({}, fv), {
    consumerMarkedDirty() {
      this.scheduler.schedule(this), this.notifier.notify(12)
    },
    destroy() {
      bt(this), this.onDestroyFn(), this.cleanup(), this.scheduler.remove(this)
    }
  }), t_ = G(V({}, fv), {
    consumerMarkedDirty() {
      this.view[A] |= 8192, Rt(this.view), this.notifier.notify(13)
    },
    destroy() {
      bt(this), this.onDestroyFn(), this.cleanup(), this.view[gt]?.delete(this)
    }
  })
});

function bv(e, t) {
  let n = Object.create(d_);
  n.value = e, n.transformFn = t?.transform;

  function r() {
    if ($t(n), n.value === Cv) {
      let o = null;
      throw new v(-950, o)
    }
    return n.value
  }
  return r[X] = n, r
}

function M2(e) {
  return new ta
}

function gv(e, t) {
  return bv(e, t)
}

function p_(e) {
  return bv(Cv, e)
}

function mv(e, t) {
  return hd(t)
}

function h_(e, t) {
  return gd(t)
}

function yv(e, t) {
  return hd(t)
}

function g_(e, t) {
  return gd(t)
}

function Ao(e) {
  return !e.moduleRef
}

function y_(e) {
  let t = Ao(e) ? e.r3Injector : e.moduleRef.injector,
    n = t.get(z);
  return n.run(() => {
    Ao(e) ? e.r3Injector.resolveInjectorInitializers() : e.moduleRef.resolveInjectorInitializers();
    let r = t.get(Be),
      o;
    if (n.runOutsideAngular(() => {
        o = n.onError.subscribe({
          next: r
        })
      }), Ao(e)) {
      let i = () => t.destroy(),
        s = e.platformInjector.get(Od);
      s.add(i), t.onDestroy(() => {
        o.unsubscribe(), s.delete(i)
      })
    } else {
      let i = () => e.moduleRef.destroy(),
        s = e.platformInjector.get(Od);
      s.add(i), e.moduleRef.onDestroy(() => {
        ao(e.allPlatformModules, e.moduleRef), o.unsubscribe(), s.delete(i)
      })
    }
    return D_(r, n, () => {
      let i = t.get(Ft),
        s = i.add(),
        a = t.get(vd);
      return a.runInitializers(), a.donePromise.then(() => {
        let c = t.get(No, So);
        if (By(c || So), !t.get(m_, !0)) return Ao(e) ? t.get(Tn) : (e.allPlatformModules.push(e.moduleRef), e.moduleRef);
        if (Ao(e)) {
          let l = t.get(Tn);
          return e.rootComponent !== void 0 && l.bootstrap(e.rootComponent), l
        } else return v_?.(e.moduleRef, e.allPlatformModules), e.moduleRef
      }).finally(() => void i.remove(s))
    })
  })
}

function D_(e, t, n) {
  try {
    let r = n();
    return Mo(r) ? r.catch(o => {
      throw t.runOutsideAngular(() => e(o)), o
    }) : r
  } catch (r) {
    throw t.runOutsideAngular(() => e(r)), r
  }
}

function E_(e = [], t) {
  return ve.create({
    name: t,
    providers: [{
      provide: Yr,
      useValue: "platform"
    }, {
      provide: Od,
      useValue: new Set([() => ra = null])
    }, ...e]
  })
}

function I_(e = []) {
  if (ra) return ra;
  let t = E_(e);
  return ra = t, Ny(), w_(t), t
}

function w_(e) {
  let t = e.get(Ps, null);
  Xn(e, () => {
    t?.forEach(n => n())
  })
}

function x2() {
  return !1
}

function C_(e) {
  return b_(J(), E(), (e & 16) === 16)
}

function b_(e, t, n) {
  if (mt(e) && !n) {
    let r = Ne(e.index, t);
    return new kt(r, r)
  } else if (e.type & 175) {
    let r = t[ce];
    return new kt(r, t)
  }
  return null
}

function vv(e, t, n) {
  let r = e.previousIndex;
  if (r === null) return r;
  let o = 0;
  return n && r < n.length && (o = n[r]), r + t + o
}

function Dv() {
  return new $d([new Fd])
}

function Ev() {
  return new zd([new jd])
}

function _v(e) {
  let {
    rootComponent: t,
    appProviders: n,
    platformProviders: r,
    platformRef: o
  } = e;
  L(8);
  try {
    let i = o?.injector ?? I_(r),
      s = [uv({}), {
        provide: Te,
        useExisting: dv
      }, Gh, ...n || []],
      a = new ho({
        providers: s,
        parent: i,
        debugName: "",
        runEnvironmentInitializers: !1
      });
    return y_({
      r3Injector: a.injector,
      platformInjector: i,
      rootComponent: t
    })
  } catch (i) {
    return Promise.reject(i)
  } finally {
    L(9)
  }
}

function __(e) {
  return typeof e == "boolean" ? e : e != null && e !== "false"
}

function M_(e, t = NaN) {
  return !isNaN(parseFloat(e)) && !isNaN(Number(e)) ? Number(e) : t
}

function R2(e, t) {
  let n = t?.injector ?? y(ve),
    r = n.get(Te),
    o = n.get($s),
    i = n.get(Lt, null, {
      optional: !0
    });
  o.impl ??= n.get(ed);
  let s = e;
  typeof s == "function" && (s = {
    mixedReadWrite: e
  });
  let a = n.get(yn, null, {
      optional: !0
    }),
    c = new Hd(o.impl, [s.earlyRead, s.write, s.mixedReadWrite, s.read], a?.view, r, n, i?.snapshot(null));
  return o.impl.register(c), c
}

function O2(e, t) {
  let n = Qe(e),
    r = t.elementInjector || Jn();
  return new Pt(n).create(r, t.projectableNodes, t.hostElement, t.environmentInjector, t.directives, t.bindings)
}

function F2(e) {
  let t = Qe(e);
  if (!t) return null;
  let n = new Pt(t);
  return {
    get selector() {
      return n.selector
    },
    get type() {
      return n.componentType
    },
    get inputs() {
      return n.inputs
    },
    get outputs() {
      return n.outputs
    },
    get ngContentSelectors() {
      return n.ngContentSelectors
    },
    get isStandalone() {
      return t.standalone
    },
    get isSignal() {
      return t.signals
    }
  }
}
var Cv, d_, hv, f_, S2, N2, A2, Od, m_, v_, ra, Ud, Fd, T_, kd, Pd, Ld, oa, jd, Bd, Vd, $d, zd, Tv, Rd, Mv, S_, Hd, he = h(() => {
  io();
  io();
  Wt();
  Nd();
  Nd();
  xd();
  xd();
  Cv = Symbol("InputSignalNode#UNSET"), d_ = G(V({}, Sr), {
    transformFn: void 0,
    applyValueToInputSignal(e, t) {
      xn(e, t)
    }
  });
  hv = class {
    attributeName;
    constructor(t) {
      this.attributeName = t
    }
    __NG_ELEMENT_ID__ = () => kl(this.attributeName);
    toString() {
      return `HostAttributeToken ${this.attributeName}`
    }
  }, f_ = new T("");
  f_.__NG_ELEMENT_ID__ = e => {
    let t = J();
    if (t === null) throw new v(204, !1);
    if (t.type & 2) return t.value;
    if (e & 8) return null;
    throw new v(204, !1)
  };
  S2 = (gv.required = p_, gv);
  N2 = (mv.required = h_, mv);
  A2 = (yv.required = g_, yv), Od = new T(""), m_ = new T("");
  ra = null;
  Ud = (() => {
    class e {
      static __NG_ELEMENT_ID__ = C_
    }
    return e
  })();
  Fd = class {
    constructor() {}
    supports(t) {
      return dd(t)
    }
    create(t) {
      return new kd(t)
    }
  }, T_ = (e, t) => t, kd = class {
    length = 0;
    collection;
    _linkedRecords = null;
    _unlinkedRecords = null;
    _previousItHead = null;
    _itHead = null;
    _itTail = null;
    _additionsHead = null;
    _additionsTail = null;
    _movesHead = null;
    _movesTail = null;
    _removalsHead = null;
    _removalsTail = null;
    _identityChangesHead = null;
    _identityChangesTail = null;
    _trackByFn;
    constructor(t) {
      this._trackByFn = t || T_
    }
    forEachItem(t) {
      let n;
      for (n = this._itHead; n !== null; n = n._next) t(n)
    }
    forEachOperation(t) {
      let n = this._itHead,
        r = this._removalsHead,
        o = 0,
        i = null;
      for (; n || r;) {
        let s = !r || n && n.currentIndex < vv(r, o, i) ? n : r,
          a = vv(s, o, i),
          c = s.currentIndex;
        if (s === r) o--, r = r._nextRemoved;
        else if (n = n._next, s.previousIndex == null) o++;
        else {
          i || (i = []);
          let u = a - o,
            l = c - o;
          if (u != l) {
            for (let p = 0; p < u; p++) {
              let f = p < i.length ? i[p] : i[p] = 0,
                g = f + p;
              l <= g && g < u && (i[p] = f + 1)
            }
            let d = s.previousIndex;
            i[d] = l - u
          }
        }
        a !== c && t(s, a, c)
      }
    }
    forEachPreviousItem(t) {
      let n;
      for (n = this._previousItHead; n !== null; n = n._nextPrevious) t(n)
    }
    forEachAddedItem(t) {
      let n;
      for (n = this._additionsHead; n !== null; n = n._nextAdded) t(n)
    }
    forEachMovedItem(t) {
      let n;
      for (n = this._movesHead; n !== null; n = n._nextMoved) t(n)
    }
    forEachRemovedItem(t) {
      let n;
      for (n = this._removalsHead; n !== null; n = n._nextRemoved) t(n)
    }
    forEachIdentityChange(t) {
      let n;
      for (n = this._identityChangesHead; n !== null; n = n._nextIdentityChange) t(n)
    }
    diff(t) {
      if (t == null && (t = []), !dd(t)) throw new v(900, !1);
      return this.check(t) ? this : null
    }
    onDestroy() {}
    check(t) {
      this._reset();
      let n = this._itHead,
        r = !1,
        o, i, s;
      if (Array.isArray(t)) {
        this.length = t.length;
        for (let a = 0; a < this.length; a++) i = t[a], s = this._trackByFn(a, i), n === null || !Object.is(n.trackById, s) ? (n = this._mismatch(n, i, s, a), r = !0) : (r && (n = this._verifyReinsertion(n, i, s, a)), Object.is(n.item, i) || this._addIdentityChange(n, i)), n = n._next
      } else o = 0, ry(t, a => {
        s = this._trackByFn(o, a), n === null || !Object.is(n.trackById, s) ? (n = this._mismatch(n, a, s, o), r = !0) : (r && (n = this._verifyReinsertion(n, a, s, o)), Object.is(n.item, a) || this._addIdentityChange(n, a)), n = n._next, o++
      }), this.length = o;
      return this._truncate(n), this.collection = t, this.isDirty
    }
    get isDirty() {
      return this._additionsHead !== null || this._movesHead !== null || this._removalsHead !== null || this._identityChangesHead !== null
    }
    _reset() {
      if (this.isDirty) {
        let t;
        for (t = this._previousItHead = this._itHead; t !== null; t = t._next) t._nextPrevious = t._next;
        for (t = this._additionsHead; t !== null; t = t._nextAdded) t.previousIndex = t.currentIndex;
        for (this._additionsHead = this._additionsTail = null, t = this._movesHead; t !== null; t = t._nextMoved) t.previousIndex = t.currentIndex;
        this._movesHead = this._movesTail = null, this._removalsHead = this._removalsTail = null, this._identityChangesHead = this._identityChangesTail = null
      }
    }
    _mismatch(t, n, r, o) {
      let i;
      return t === null ? i = this._itTail : (i = t._prev, this._remove(t)), t = this._unlinkedRecords === null ? null : this._unlinkedRecords.get(r, null), t !== null ? (Object.is(t.item, n) || this._addIdentityChange(t, n), this._reinsertAfter(t, i, o)) : (t = this._linkedRecords === null ? null : this._linkedRecords.get(r, o), t !== null ? (Object.is(t.item, n) || this._addIdentityChange(t, n), this._moveAfter(t, i, o)) : t = this._addAfter(new Pd(n, r), i, o)), t
    }
    _verifyReinsertion(t, n, r, o) {
      let i = this._unlinkedRecords === null ? null : this._unlinkedRecords.get(r, null);
      return i !== null ? t = this._reinsertAfter(i, t._prev, o) : t.currentIndex != o && (t.currentIndex = o, this._addToMoves(t, o)), t
    }
    _truncate(t) {
      for (; t !== null;) {
        let n = t._next;
        this._addToRemovals(this._unlink(t)), t = n
      }
      this._unlinkedRecords !== null && this._unlinkedRecords.clear(), this._additionsTail !== null && (this._additionsTail._nextAdded = null), this._movesTail !== null && (this._movesTail._nextMoved = null), this._itTail !== null && (this._itTail._next = null), this._removalsTail !== null && (this._removalsTail._nextRemoved = null), this._identityChangesTail !== null && (this._identityChangesTail._nextIdentityChange = null)
    }
    _reinsertAfter(t, n, r) {
      this._unlinkedRecords !== null && this._unlinkedRecords.remove(t);
      let o = t._prevRemoved,
        i = t._nextRemoved;
      return o === null ? this._removalsHead = i : o._nextRemoved = i, i === null ? this._removalsTail = o : i._prevRemoved = o, this._insertAfter(t, n, r), this._addToMoves(t, r), t
    }
    _moveAfter(t, n, r) {
      return this._unlink(t), this._insertAfter(t, n, r), this._addToMoves(t, r), t
    }
    _addAfter(t, n, r) {
      return this._insertAfter(t, n, r), this._additionsTail === null ? this._additionsTail = this._additionsHead = t : this._additionsTail = this._additionsTail._nextAdded = t, t
    }
    _insertAfter(t, n, r) {
      let o = n === null ? this._itHead : n._next;
      return t._next = o, t._prev = n, o === null ? this._itTail = t : o._prev = t, n === null ? this._itHead = t : n._next = t, this._linkedRecords === null && (this._linkedRecords = new oa), this._linkedRecords.put(t), t.currentIndex = r, t
    }
    _remove(t) {
      return this._addToRemovals(this._unlink(t))
    }
    _unlink(t) {
      this._linkedRecords !== null && this._linkedRecords.remove(t);
      let n = t._prev,
        r = t._next;
      return n === null ? this._itHead = r : n._next = r, r === null ? this._itTail = n : r._prev = n, t
    }
    _addToMoves(t, n) {
      return t.previousIndex === n || (this._movesTail === null ? this._movesTail = this._movesHead = t : this._movesTail = this._movesTail._nextMoved = t), t
    }
    _addToRemovals(t) {
      return this._unlinkedRecords === null && (this._unlinkedRecords = new oa), this._unlinkedRecords.put(t), t.currentIndex = null, t._nextRemoved = null, this._removalsTail === null ? (this._removalsTail = this._removalsHead = t, t._prevRemoved = null) : (t._prevRemoved = this._removalsTail, this._removalsTail = this._removalsTail._nextRemoved = t), t
    }
    _addIdentityChange(t, n) {
      return t.item = n, this._identityChangesTail === null ? this._identityChangesTail = this._identityChangesHead = t : this._identityChangesTail = this._identityChangesTail._nextIdentityChange = t, t
    }
  }, Pd = class {
    item;
    trackById;
    currentIndex = null;
    previousIndex = null;
    _nextPrevious = null;
    _prev = null;
    _next = null;
    _prevDup = null;
    _nextDup = null;
    _prevRemoved = null;
    _nextRemoved = null;
    _nextAdded = null;
    _nextMoved = null;
    _nextIdentityChange = null;
    constructor(t, n) {
      this.item = t, this.trackById = n
    }
  }, Ld = class {
    _head = null;
    _tail = null;
    add(t) {
      this._head === null ? (this._head = this._tail = t, t._nextDup = null, t._prevDup = null) : (this._tail._nextDup = t, t._prevDup = this._tail, t._nextDup = null, this._tail = t)
    }
    get(t, n) {
      let r;
      for (r = this._head; r !== null; r = r._nextDup)
        if ((n === null || n <= r.currentIndex) && Object.is(r.trackById, t)) return r;
      return null
    }
    remove(t) {
      let n = t._prevDup,
        r = t._nextDup;
      return n === null ? this._head = r : n._nextDup = r, r === null ? this._tail = n : r._prevDup = n, this._head === null
    }
  }, oa = class {
    map = new Map;
    put(t) {
      let n = t.trackById,
        r = this.map.get(n);
      r || (r = new Ld, this.map.set(n, r)), r.add(t)
    }
    get(t, n) {
      let r = t,
        o = this.map.get(r);
      return o ? o.get(t, n) : null
    }
    remove(t) {
      let n = t.trackById;
      return this.map.get(n).remove(t) && this.map.delete(n), t
    }
    get isEmpty() {
      return this.map.size === 0
    }
    clear() {
      this.map.clear()
    }
  };
  jd = class {
    constructor() {}
    supports(t) {
      return t instanceof Map || Qs(t)
    }
    create() {
      return new Bd
    }
  }, Bd = class {
    _records = new Map;
    _mapHead = null;
    _appendAfter = null;
    _previousMapHead = null;
    _changesHead = null;
    _changesTail = null;
    _additionsHead = null;
    _additionsTail = null;
    _removalsHead = null;
    _removalsTail = null;
    get isDirty() {
      return this._additionsHead !== null || this._changesHead !== null || this._removalsHead !== null
    }
    forEachItem(t) {
      let n;
      for (n = this._mapHead; n !== null; n = n._next) t(n)
    }
    forEachPreviousItem(t) {
      let n;
      for (n = this._previousMapHead; n !== null; n = n._nextPrevious) t(n)
    }
    forEachChangedItem(t) {
      let n;
      for (n = this._changesHead; n !== null; n = n._nextChanged) t(n)
    }
    forEachAddedItem(t) {
      let n;
      for (n = this._additionsHead; n !== null; n = n._nextAdded) t(n)
    }
    forEachRemovedItem(t) {
      let n;
      for (n = this._removalsHead; n !== null; n = n._nextRemoved) t(n)
    }
    diff(t) {
      if (!t) t = new Map;
      else if (!(t instanceof Map || Qs(t))) throw new v(900, !1);
      return this.check(t) ? this : null
    }
    onDestroy() {}
    check(t) {
      this._reset();
      let n = this._mapHead;
      if (this._appendAfter = null, this._forEach(t, (r, o) => {
          if (n && n.key === o) this._maybeAddToChanges(n, r), this._appendAfter = n, n = n._next;
          else {
            let i = this._getOrCreateRecordForKey(o, r);
            n = this._insertBeforeOrAppend(n, i)
          }
        }), n) {
        n._prev && (n._prev._next = null), this._removalsHead = n;
        for (let r = n; r !== null; r = r._nextRemoved) r === this._mapHead && (this._mapHead = null), this._records.delete(r.key), r._nextRemoved = r._next, r.previousValue = r.currentValue, r.currentValue = null, r._prev = null, r._next = null
      }
      return this._changesTail && (this._changesTail._nextChanged = null), this._additionsTail && (this._additionsTail._nextAdded = null), this.isDirty
    }
    _insertBeforeOrAppend(t, n) {
      if (t) {
        let r = t._prev;
        return n._next = t, n._prev = r, t._prev = n, r && (r._next = n), t === this._mapHead && (this._mapHead = n), this._appendAfter = t, t
      }
      return this._appendAfter ? (this._appendAfter._next = n, n._prev = this._appendAfter) : this._mapHead = n, this._appendAfter = n, null
    }
    _getOrCreateRecordForKey(t, n) {
      if (this._records.has(t)) {
        let o = this._records.get(t);
        this._maybeAddToChanges(o, n);
        let i = o._prev,
          s = o._next;
        return i && (i._next = s), s && (s._prev = i), o._next = null, o._prev = null, o
      }
      let r = new Vd(t);
      return this._records.set(t, r), r.currentValue = n, this._addToAdditions(r), r
    }
    _reset() {
      if (this.isDirty) {
        let t;
        for (this._previousMapHead = this._mapHead, t = this._previousMapHead; t !== null; t = t._next) t._nextPrevious = t._next;
        for (t = this._changesHead; t !== null; t = t._nextChanged) t.previousValue = t.currentValue;
        for (t = this._additionsHead; t != null; t = t._nextAdded) t.previousValue = t.currentValue;
        this._changesHead = this._changesTail = null, this._additionsHead = this._additionsTail = null, this._removalsHead = null
      }
    }
    _maybeAddToChanges(t, n) {
      Object.is(n, t.currentValue) || (t.previousValue = t.currentValue, t.currentValue = n, this._addToChanges(t))
    }
    _addToAdditions(t) {
      this._additionsHead === null ? this._additionsHead = this._additionsTail = t : (this._additionsTail._nextAdded = t, this._additionsTail = t)
    }
    _addToChanges(t) {
      this._changesHead === null ? this._changesHead = this._changesTail = t : (this._changesTail._nextChanged = t, this._changesTail = t)
    }
    _forEach(t, n) {
      t instanceof Map ? t.forEach(n) : Object.keys(t).forEach(r => n(t[r], r))
    }
  }, Vd = class {
    key;
    previousValue = null;
    currentValue = null;
    _nextPrevious = null;
    _next = null;
    _prev = null;
    _nextAdded = null;
    _nextRemoved = null;
    _nextChanged = null;
    constructor(t) {
      this.key = t
    }
  };
  $d = (() => {
    class e {
      factories;
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: Dv
      });
      constructor(n) {
        this.factories = n
      }
      static create(n, r) {
        if (r != null) {
          let o = r.factories.slice();
          n = n.concat(o)
        }
        return new e(n)
      }
      static extend(n) {
        return {
          provide: e,
          useFactory: () => {
            let r = y(e, {
              optional: !0,
              skipSelf: !0
            });
            return e.create(n, r || Dv())
          }
        }
      }
      find(n) {
        let r = this.factories.find(o => o.supports(n));
        if (r != null) return r;
        throw new v(901, !1)
      }
    }
    return e
  })();
  zd = (() => {
    class e {
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: Ev
      });
      factories;
      constructor(n) {
        this.factories = n
      }
      static create(n, r) {
        if (r) {
          let o = r.factories.slice();
          n = n.concat(o)
        }
        return new e(n)
      }
      static extend(n) {
        return {
          provide: e,
          useFactory: () => {
            let r = y(e, {
              optional: !0,
              skipSelf: !0
            });
            return e.create(n, r || Ev())
          }
        }
      }
      find(n) {
        let r = this.factories.find(o => o.supports(n));
        if (r) return r;
        throw new v(901, !1)
      }
    }
    return e
  })(), Tv = (() => {
    class e {
      constructor(n) {}
      static \u0275fac = function(r) {
        return new(r || e)(C(Tn))
      };
      static \u0275mod = Bt({
        type: e
      });
      static \u0275inj = pt({})
    }
    return e
  })();
  Rd = Symbol("NOT_SET"), Mv = new Set, S_ = G(V({}, Sr), {
    consumerIsAlwaysLive: !0,
    consumerAllowSignalWrites: !0,
    value: Rd,
    cleanup: null,
    consumerMarkedDirty() {
      if (this.sequence.impl.executing) {
        if (this.sequence.lastPhase === null || this.sequence.lastPhase < this.phase) return;
        this.sequence.erroredOrDestroyed = !0
      }
      this.sequence.scheduler.notify(7)
    },
    phaseFn(e) {
      if (this.sequence.lastPhase = this.phase, !this.dirty) return this.signal;
      if (this.dirty = !1, this.value !== Rd && !Gt(this)) return this.signal;
      try {
        for (let o of this.cleanup ?? Mv) o()
      } finally {
        this.cleanup?.clear()
      }
      let t = [];
      e !== void 0 && t.push(e), t.push(this.registerCleanupFn);
      let n = Ct(this),
        r;
      try {
        r = this.userFn.apply(null, t)
      } finally {
        zt(this, n)
      }
      return (this.value === Rd || !this.equal(this.value, r)) && (this.value = r, this.version++), this.signal
    }
  }), Hd = class extends uo {
    scheduler;
    lastPhase = null;
    nodes = [void 0, void 0, void 0, void 0];
    constructor(t, n, r, o, i, s = null) {
      super(t, [void 0, void 0, void 0, void 0], r, !1, i.get(Ae), s), this.scheduler = o;
      for (let a of Xl) {
        let c = n[a];
        if (c === void 0) continue;
        let u = Object.create(S_);
        u.sequence = this, u.phase = a, u.userFn = c, u.dirty = !0, u.signal = () => ($t(u), u.value), u.signal[X] = u, u.registerCleanupFn = l => (u.cleanup ??= new Set).add(l), this.nodes[a] = u, this.hooks[a] = l => u.phaseFn(l)
      }
    }
    afterRun() {
      super.afterRun(), this.lastPhase = null
    }
    destroy() {
      super.destroy();
      for (let t of this.nodes)
        if (t) try {
          for (let n of t.cleanup ?? Mv) n()
        } finally {
          bt(t)
        }
    }
  }
});

function st() {
  return Av
}

function Gd(e) {
  Av ??= e
}

function ia(e, t) {
  return e ? t ? e.endsWith("/") ? t.startsWith("/") ? e + t.slice(1) : e + t : t.startsWith("/") ? e + t : `${e}/${t}` : e : t
}

function Sv(e) {
  let t = e.search(/#|\?|$/);
  return e[t - 1] === "/" ? e.slice(0, t - 1) + e.slice(t) : e
}

function $e(e) {
  return e && e[0] !== "?" ? `?${e}` : e
}

function A_() {
  return new Ov(C(Er))
}

function x_(e, t) {
  if (!e || !t.startsWith(e)) return t;
  let n = t.substring(e.length);
  return n === "" || ["/", ";", "?", "#"].includes(n[0]) ? n : t
}

function Nv(e) {
  return e.replace(/\/index.html$/, "")
}

function R_(e) {
  if (new RegExp("^(https?:)?//").test(e)) {
    let [, n] = e.split(/\/\/[^\/]+/);
    return n
  }
  return e
}
var Av, xo, Ro, N_, xv, Er, sa, Rv, Ov, Wd = h(() => {
  he();
  he();
  Ur();
  Av = null;
  xo = class {}, Ro = (() => {
    class e {
      historyGo(n) {
        throw new Error("")
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: () => y(xv),
        providedIn: "platform"
      })
    }
    return e
  })(), N_ = new T(""), xv = (() => {
    class e extends Ro {
      _location;
      _history;
      _doc = y(Y);
      constructor() {
        super(), this._location = window.location, this._history = window.history
      }
      getBaseHrefFromDOM() {
        return st().getBaseHref(this._doc)
      }
      onPopState(n) {
        let r = st().getGlobalEventTarget(this._doc, "window");
        return r.addEventListener("popstate", n, !1), () => r.removeEventListener("popstate", n)
      }
      onHashChange(n) {
        let r = st().getGlobalEventTarget(this._doc, "window");
        return r.addEventListener("hashchange", n, !1), () => r.removeEventListener("hashchange", n)
      }
      get href() {
        return this._location.href
      }
      get protocol() {
        return this._location.protocol
      }
      get hostname() {
        return this._location.hostname
      }
      get port() {
        return this._location.port
      }
      get pathname() {
        return this._location.pathname
      }
      get search() {
        return this._location.search
      }
      get hash() {
        return this._location.hash
      }
      set pathname(n) {
        this._location.pathname = n
      }
      pushState(n, r, o) {
        this._history.pushState(n, r, o)
      }
      replaceState(n, r, o) {
        this._history.replaceState(n, r, o)
      }
      forward() {
        this._history.forward()
      }
      back() {
        this._history.back()
      }
      historyGo(n = 0) {
        this._history.go(n)
      }
      getState() {
        return this._history.state
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: () => new e,
        providedIn: "platform"
      })
    }
    return e
  })();
  Er = (() => {
    class e {
      historyGo(n) {
        throw new Error("")
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: () => y(Rv),
        providedIn: "root"
      })
    }
    return e
  })(), sa = new T(""), Rv = (() => {
    class e extends Er {
      _platformLocation;
      _baseHref;
      _removeListenerFns = [];
      constructor(n, r) {
        super(), this._platformLocation = n, this._baseHref = r ?? this._platformLocation.getBaseHrefFromDOM() ?? y(Y).location?.origin ?? ""
      }
      ngOnDestroy() {
        for (; this._removeListenerFns.length;) this._removeListenerFns.pop()()
      }
      onPopState(n) {
        this._removeListenerFns.push(this._platformLocation.onPopState(n), this._platformLocation.onHashChange(n))
      }
      getBaseHref() {
        return this._baseHref
      }
      prepareExternalUrl(n) {
        return ia(this._baseHref, n)
      }
      path(n = !1) {
        let r = this._platformLocation.pathname + $e(this._platformLocation.search),
          o = this._platformLocation.hash;
        return o && n ? `${r}${o}` : r
      }
      pushState(n, r, o, i) {
        let s = this.prepareExternalUrl(o + $e(i));
        this._platformLocation.pushState(n, r, s)
      }
      replaceState(n, r, o, i) {
        let s = this.prepareExternalUrl(o + $e(i));
        this._platformLocation.replaceState(n, r, s)
      }
      forward() {
        this._platformLocation.forward()
      }
      back() {
        this._platformLocation.back()
      }
      getState() {
        return this._platformLocation.getState()
      }
      historyGo(n = 0) {
        this._platformLocation.historyGo?.(n)
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Ro), C(sa, 8))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })(), Ov = (() => {
    class e {
      _subject = new ge;
      _basePath;
      _locationStrategy;
      _urlChangeListeners = [];
      _urlChangeSubscription = null;
      constructor(n) {
        this._locationStrategy = n;
        let r = this._locationStrategy.getBaseHref();
        this._basePath = R_(Sv(Nv(r))), this._locationStrategy.onPopState(o => {
          this._subject.next({
            url: this.path(!0),
            pop: !0,
            state: o.state,
            type: o.type
          })
        })
      }
      ngOnDestroy() {
        this._urlChangeSubscription?.unsubscribe(), this._urlChangeListeners = []
      }
      path(n = !1) {
        return this.normalize(this._locationStrategy.path(n))
      }
      getState() {
        return this._locationStrategy.getState()
      }
      isCurrentPathEqualTo(n, r = "") {
        return this.path() == this.normalize(n + $e(r))
      }
      normalize(n) {
        return e.stripTrailingSlash(x_(this._basePath, Nv(n)))
      }
      prepareExternalUrl(n) {
        return n && n[0] !== "/" && (n = "/" + n), this._locationStrategy.prepareExternalUrl(n)
      }
      go(n, r = "", o = null) {
        this._locationStrategy.pushState(o, "", n, r), this._notifyUrlChangeListeners(this.prepareExternalUrl(n + $e(r)), o)
      }
      replaceState(n, r = "", o = null) {
        this._locationStrategy.replaceState(o, "", n, r), this._notifyUrlChangeListeners(this.prepareExternalUrl(n + $e(r)), o)
      }
      forward() {
        this._locationStrategy.forward()
      }
      back() {
        this._locationStrategy.back()
      }
      historyGo(n = 0) {
        this._locationStrategy.historyGo?.(n)
      }
      onUrlChange(n) {
        return this._urlChangeListeners.push(n), this._urlChangeSubscription ??= this.subscribe(r => {
          this._notifyUrlChangeListeners(r.url, r.state)
        }), () => {
          let r = this._urlChangeListeners.indexOf(n);
          this._urlChangeListeners.splice(r, 1), this._urlChangeListeners.length === 0 && (this._urlChangeSubscription?.unsubscribe(), this._urlChangeSubscription = null)
        }
      }
      _notifyUrlChangeListeners(n = "", r) {
        this._urlChangeListeners.forEach(o => o(n, r))
      }
      subscribe(n, r, o) {
        return this._subject.subscribe({
          next: n,
          error: r ?? void 0,
          complete: o ?? void 0
        })
      }
      static normalizeQueryParams = $e;
      static joinWithSlash = ia;
      static stripTrailingSlash = Sv;
      static \u0275fac = function(r) {
        return new(r || e)(C(Er))
      };
      static \u0275prov = N({
        token: e,
        factory: () => A_(),
        providedIn: "root"
      })
    }
    return e
  })()
});

function Ir(e, t) {
  let n = ea(e),
    r = n[_n.NumberSymbols][t];
  if (typeof r > "u") {
    if (t === at.CurrencyDecimal) return n[_n.NumberSymbols][at.Decimal];
    if (t === at.CurrencyGroup) return n[_n.NumberSymbols][at.Group]
  }
  return r
}

function jv(e, t) {
  return ea(e)[_n.NumberFormats][t]
}

function L_(e, t, n, r, o, i, s = !1) {
  let a = "",
    c = !1;
  if (!isFinite(e)) a = Ir(n, at.Infinity);
  else {
    let u = V_(e);
    s && (u = B_(u));
    let l = t.minInt,
      d = t.minFrac,
      p = t.maxFrac;
    if (i) {
      let F = i.match(F_);
      if (F === null) throw new v(2306, !1);
      let ct = F[1],
        Q = F[3],
        ze = F[5];
      ct != null && (l = Zd(ct)), Q != null && (d = Zd(Q)), ze != null ? p = Zd(ze) : Q != null && d > p && (p = d)
    }
    H_(u, d, p);
    let f = u.digits,
      g = u.integerLen,
      I = u.exponent,
      D = [];
    for (c = f.every(F => !F); g < l; g++) f.unshift(0);
    for (; g < 0; g++) f.unshift(0);
    g > 0 ? D = f.splice(g, f.length) : (D = f, f = [0]);
    let m = [];
    for (f.length >= t.lgSize && m.unshift(f.splice(-t.lgSize, f.length).join("")); f.length > t.gSize;) m.unshift(f.splice(-t.gSize, f.length).join(""));
    f.length && m.unshift(f.join("")), a = m.join(Ir(n, r)), D.length && (a += Ir(n, o) + D.join("")), I && (a += Ir(n, at.Exponential) + "+" + I)
  }
  return e < 0 && !c ? a = t.negPre + a + t.negSuf : a = t.posPre + a + t.posSuf, a
}

function Bv(e, t, n) {
  let r = jv(t, Jd.Decimal),
    o = j_(r, Ir(t, at.MinusSign));
  return L_(e, o, t, at.Group, at.Decimal, n)
}

function j_(e, t = "-") {
  let n = {
      minInt: 1,
      minFrac: 0,
      maxFrac: 0,
      posPre: "",
      posSuf: "",
      negPre: "",
      negSuf: "",
      gSize: 0,
      lgSize: 0
    },
    r = e.split(k_),
    o = r[0],
    i = r[1],
    s = o.indexOf(aa) !== -1 ? o.split(aa) : [o.substring(0, o.lastIndexOf(Oo) + 1), o.substring(o.lastIndexOf(Oo) + 1)],
    a = s[0],
    c = s[1] || "";
  n.posPre = a.substring(0, a.indexOf(qd));
  for (let l = 0; l < c.length; l++) {
    let d = c.charAt(l);
    d === Oo ? n.minFrac = n.maxFrac = l + 1 : d === qd ? n.maxFrac = l + 1 : n.posSuf += d
  }
  let u = a.split(P_);
  if (n.gSize = u[1] ? u[1].length : 0, n.lgSize = u[2] || u[1] ? (u[2] || u[1]).length : 0, i) {
    let l = o.length - n.posPre.length - n.posSuf.length,
      d = i.indexOf(qd);
    n.negPre = i.substring(0, d).replace(/'/g, ""), n.negSuf = i.slice(d + l).replace(/'/g, "")
  } else n.negPre = t + n.posPre, n.negSuf = n.posSuf;
  return n
}

function B_(e) {
  if (e.digits[0] === 0) return e;
  let t = e.digits.length - e.integerLen;
  return e.exponent ? e.exponent += 2 : (t === 0 ? e.digits.push(0, 0) : t === 1 && e.digits.push(0), e.integerLen += 2), e
}

function V_(e) {
  let t = Math.abs(e) + "",
    n = 0,
    r, o, i, s, a;
  for ((o = t.indexOf(aa)) > -1 && (t = t.replace(aa, "")), (i = t.search(/e/i)) > 0 ? (o < 0 && (o = i), o += +t.slice(i + 1), t = t.substring(0, i)) : o < 0 && (o = t.length), i = 0; t.charAt(i) === Oo; i++);
  if (i === (a = t.length)) r = [0], o = 1;
  else {
    for (a--; t.charAt(a) === Oo;) a--;
    for (o -= i, r = [], s = 0; i <= a; i++, s++) r[s] = Number(t.charAt(i))
  }
  return o > Fv && (r = r.splice(0, Fv - 1), n = o - 1, o = 1), {
    digits: r,
    exponent: n,
    integerLen: o
  }
}

function H_(e, t, n) {
  if (t > n) throw new v(2307, !1);
  let r = e.digits,
    o = r.length - e.integerLen,
    i = Math.min(Math.max(t, o), n),
    s = i + e.integerLen,
    a = r[s];
  if (s > 0) {
    r.splice(Math.max(e.integerLen, s));
    for (let d = s; d < r.length; d++) r[d] = 0
  } else {
    o = Math.max(0, o), e.integerLen = 1, r.length = Math.max(1, s = i + 1), r[0] = 0;
    for (let d = 1; d < s; d++) r[d] = 0
  }
  if (a >= 5)
    if (s - 1 < 0) {
      for (let d = 0; d > s; d--) r.unshift(0), e.integerLen++;
      r.unshift(1), e.integerLen++
    } else r[s - 1]++;
  for (; o < Math.max(0, i); o++) r.push(0);
  let c = i !== 0,
    u = t + e.integerLen,
    l = r.reduceRight(function(d, p, f, g) {
      return p = p + d, g[f] = p < 10 ? p : p - 10, c && (g[f] === 0 && f >= u ? g.pop() : c = !1), p >= 10 ? 1 : 0
    }, 0);
  l && (r.unshift(l), e.integerLen++)
}

function Zd(e) {
  let t = parseInt(e);
  if (isNaN(t)) throw new v(2305, !1);
  return t
}

function Pv(e, t) {
  e.context.$implicit = t.item
}

function Lv(e, t) {
  if (e && !e.createEmbeddedView) throw new v(2020, !1)
}

function ef(e, t) {
  return new v(2100, !1)
}

function X_(e) {
  return !(e == null || e === "" || e !== e)
}

function eM(e) {
  if (typeof e == "string" && !isNaN(Number(e) - parseFloat(e))) return Number(e);
  if (typeof e != "number") throw new v(2309, !1);
  return e
}
var O_, Jd, at, F_, Fv, aa, Oo, k_, P_, qd, Yd, kv, U_, ca, Vv, $_, ua, la, Xd, z_, G_, W_, q_, Qd, Kd, Z_, Y_, Q_, K_, J_, tf, Hv = h(() => {
  he();
  he();
  Wd();
  O_ = (() => {
    class e extends Er {
      _platformLocation;
      _baseHref = "";
      _removeListenerFns = [];
      constructor(n, r) {
        super(), this._platformLocation = n, r != null && (this._baseHref = r)
      }
      ngOnDestroy() {
        for (; this._removeListenerFns.length;) this._removeListenerFns.pop()()
      }
      onPopState(n) {
        this._removeListenerFns.push(this._platformLocation.onPopState(n), this._platformLocation.onHashChange(n))
      }
      getBaseHref() {
        return this._baseHref
      }
      path(n = !1) {
        let r = this._platformLocation.hash ?? "#";
        return r.length > 0 ? r.substring(1) : r
      }
      prepareExternalUrl(n) {
        let r = ia(this._baseHref, n);
        return r.length > 0 ? "#" + r : r
      }
      pushState(n, r, o, i) {
        let s = this.prepareExternalUrl(o + $e(i)) || this._platformLocation.pathname;
        this._platformLocation.pushState(n, r, s)
      }
      replaceState(n, r, o, i) {
        let s = this.prepareExternalUrl(o + $e(i)) || this._platformLocation.pathname;
        this._platformLocation.replaceState(n, r, s)
      }
      forward() {
        this._platformLocation.forward()
      }
      back() {
        this._platformLocation.back()
      }
      getState() {
        return this._platformLocation.getState()
      }
      historyGo(n = 0) {
        this._platformLocation.historyGo?.(n)
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Ro), C(sa, 8))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), Jd = (function(e) {
    return e[e.Decimal = 0] = "Decimal", e[e.Percent = 1] = "Percent", e[e.Currency = 2] = "Currency", e[e.Scientific = 3] = "Scientific", e
  })(Jd || {}), at = {
    Decimal: 0,
    Group: 1,
    List: 2,
    PercentSign: 3,
    PlusSign: 4,
    MinusSign: 5,
    Exponential: 6,
    SuperscriptingExponent: 7,
    PerMille: 8,
    Infinity: 9,
    NaN: 10,
    TimeSeparator: 11,
    CurrencyDecimal: 12,
    CurrencyGroup: 13
  };
  F_ = /^(\d+)?\.((\d+)(-(\d+))?)?$/, Fv = 22, aa = ".", Oo = "0", k_ = ";", P_ = ",", qd = "#";
  Yd = /\s+/, kv = [], U_ = (() => {
    class e {
      _ngEl;
      _renderer;
      initialClasses = kv;
      rawClass;
      stateMap = new Map;
      constructor(n, r) {
        this._ngEl = n, this._renderer = r
      }
      set klass(n) {
        this.initialClasses = n != null ? n.trim().split(Yd) : kv
      }
      set ngClass(n) {
        this.rawClass = typeof n == "string" ? n.trim().split(Yd) : n
      }
      ngDoCheck() {
        for (let r of this.initialClasses) this._updateState(r, !0);
        let n = this.rawClass;
        if (Array.isArray(n) || n instanceof Set)
          for (let r of n) this._updateState(r, !0);
        else if (n != null)
          for (let r of Object.keys(n)) this._updateState(r, !!n[r]);
        this._applyStateDiff()
      }
      _updateState(n, r) {
        let o = this.stateMap.get(n);
        o !== void 0 ? (o.enabled !== r && (o.changed = !0, o.enabled = r), o.touched = !0) : this.stateMap.set(n, {
          enabled: r,
          changed: !0,
          touched: !0
        })
      }
      _applyStateDiff() {
        for (let n of this.stateMap) {
          let r = n[0],
            o = n[1];
          o.changed ? (this._toggleClass(r, o.enabled), o.changed = !1) : o.touched || (o.enabled && this._toggleClass(r, !1), this.stateMap.delete(r)), o.touched = !1
        }
      }
      _toggleClass(n, r) {
        n = n.trim(), n.length > 0 && n.split(Yd).forEach(o => {
          r ? this._renderer.addClass(this._ngEl.nativeElement, o) : this._renderer.removeClass(this._ngEl.nativeElement, o)
        })
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(Et), U(Co))
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngClass", ""]
        ],
        inputs: {
          klass: [0, "class", "klass"],
          ngClass: "ngClass"
        }
      })
    }
    return e
  })(), ca = class {
    $implicit;
    ngForOf;
    index;
    count;
    constructor(t, n, r, o) {
      this.$implicit = t, this.ngForOf = n, this.index = r, this.count = o
    }
    get first() {
      return this.index === 0
    }
    get last() {
      return this.index === this.count - 1
    }
    get even() {
      return this.index % 2 === 0
    }
    get odd() {
      return !this.even
    }
  }, Vv = (() => {
    class e {
      _viewContainer;
      _template;
      _differs;
      set ngForOf(n) {
        this._ngForOf = n, this._ngForOfDirty = !0
      }
      set ngForTrackBy(n) {
        this._trackByFn = n
      }
      get ngForTrackBy() {
        return this._trackByFn
      }
      _ngForOf = null;
      _ngForOfDirty = !0;
      _differ = null;
      _trackByFn;
      constructor(n, r, o) {
        this._viewContainer = n, this._template = r, this._differs = o
      }
      set ngForTemplate(n) {
        n && (this._template = n)
      }
      ngDoCheck() {
        if (this._ngForOfDirty) {
          this._ngForOfDirty = !1;
          let n = this._ngForOf;
          !this._differ && n && (this._differ = this._differs.find(n).create(this.ngForTrackBy))
        }
        if (this._differ) {
          let n = this._differ.diff(this._ngForOf);
          n && this._applyChanges(n)
        }
      }
      _applyChanges(n) {
        let r = this._viewContainer;
        n.forEachOperation((o, i, s) => {
          if (o.previousIndex == null) r.createEmbeddedView(this._template, new ca(o.item, this._ngForOf, -1, -1), s === null ? void 0 : s);
          else if (s == null) r.remove(i === null ? void 0 : i);
          else if (i !== null) {
            let a = r.get(i);
            r.move(a, s), Pv(a, o)
          }
        });
        for (let o = 0, i = r.length; o < i; o++) {
          let a = r.get(o).context;
          a.index = o, a.count = i, a.ngForOf = this._ngForOf
        }
        n.forEachIdentityChange(o => {
          let i = r.get(o.currentIndex);
          Pv(i, o)
        })
      }
      static ngTemplateContextGuard(n, r) {
        return !0
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(ot), U(nt), U($d))
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngFor", "", "ngForOf", ""]
        ],
        inputs: {
          ngForOf: "ngForOf",
          ngForTrackBy: "ngForTrackBy",
          ngForTemplate: "ngForTemplate"
        }
      })
    }
    return e
  })();
  $_ = (() => {
    class e {
      _viewContainer;
      _context = new ua;
      _thenTemplateRef = null;
      _elseTemplateRef = null;
      _thenViewRef = null;
      _elseViewRef = null;
      constructor(n, r) {
        this._viewContainer = n, this._thenTemplateRef = r
      }
      set ngIf(n) {
        this._context.$implicit = this._context.ngIf = n, this._updateView()
      }
      set ngIfThen(n) {
        Lv(n, !1), this._thenTemplateRef = n, this._thenViewRef = null, this._updateView()
      }
      set ngIfElse(n) {
        Lv(n, !1), this._elseTemplateRef = n, this._elseViewRef = null, this._updateView()
      }
      _updateView() {
        this._context.$implicit ? this._thenViewRef || (this._viewContainer.clear(), this._elseViewRef = null, this._thenTemplateRef && (this._thenViewRef = this._viewContainer.createEmbeddedView(this._thenTemplateRef, this._context))) : this._elseViewRef || (this._viewContainer.clear(), this._thenViewRef = null, this._elseTemplateRef && (this._elseViewRef = this._viewContainer.createEmbeddedView(this._elseTemplateRef, this._context)))
      }
      static ngIfUseIfTypeGuard;
      static ngTemplateGuard_ngIf;
      static ngTemplateContextGuard(n, r) {
        return !0
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(ot), U(nt))
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngIf", ""]
        ],
        inputs: {
          ngIf: "ngIf",
          ngIfThen: "ngIfThen",
          ngIfElse: "ngIfElse"
        }
      })
    }
    return e
  })(), ua = class {
    $implicit = null;
    ngIf = null
  };
  la = class {
    _viewContainerRef;
    _templateRef;
    _created = !1;
    constructor(t, n) {
      this._viewContainerRef = t, this._templateRef = n
    }
    create() {
      this._created = !0, this._viewContainerRef.createEmbeddedView(this._templateRef)
    }
    destroy() {
      this._created = !1, this._viewContainerRef.clear()
    }
    enforceState(t) {
      t && !this._created ? this.create() : !t && this._created && this.destroy()
    }
  }, Xd = (() => {
    class e {
      _defaultViews = [];
      _defaultUsed = !1;
      _caseCount = 0;
      _lastCaseCheckIndex = 0;
      _lastCasesMatched = !1;
      _ngSwitch;
      set ngSwitch(n) {
        this._ngSwitch = n, this._caseCount === 0 && this._updateDefaultCases(!0)
      }
      _addCase() {
        return this._caseCount++
      }
      _addDefault(n) {
        this._defaultViews.push(n)
      }
      _matchCase(n) {
        let r = n === this._ngSwitch;
        return this._lastCasesMatched ||= r, this._lastCaseCheckIndex++, this._lastCaseCheckIndex === this._caseCount && (this._updateDefaultCases(!this._lastCasesMatched), this._lastCaseCheckIndex = 0, this._lastCasesMatched = !1), r
      }
      _updateDefaultCases(n) {
        if (this._defaultViews.length > 0 && n !== this._defaultUsed) {
          this._defaultUsed = n;
          for (let r of this._defaultViews) r.enforceState(n)
        }
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngSwitch", ""]
        ],
        inputs: {
          ngSwitch: "ngSwitch"
        }
      })
    }
    return e
  })(), z_ = (() => {
    class e {
      ngSwitch;
      _view;
      ngSwitchCase;
      constructor(n, r, o) {
        this.ngSwitch = o, o._addCase(), this._view = new la(n, r)
      }
      ngDoCheck() {
        this._view.enforceState(this.ngSwitch._matchCase(this.ngSwitchCase))
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(ot), U(nt), U(Xd, 9))
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngSwitchCase", ""]
        ],
        inputs: {
          ngSwitchCase: "ngSwitchCase"
        }
      })
    }
    return e
  })(), G_ = (() => {
    class e {
      constructor(n, r, o) {
        o._addDefault(new la(n, r))
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(ot), U(nt), U(Xd, 9))
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngSwitchDefault", ""]
        ]
      })
    }
    return e
  })(), W_ = (() => {
    class e {
      _ngEl;
      _differs;
      _renderer;
      _ngStyle = null;
      _differ = null;
      constructor(n, r, o) {
        this._ngEl = n, this._differs = r, this._renderer = o
      }
      set ngStyle(n) {
        this._ngStyle = n, !this._differ && n && (this._differ = this._differs.find(n).create())
      }
      ngDoCheck() {
        if (this._differ) {
          let n = this._differ.diff(this._ngStyle);
          n && this._applyChanges(n)
        }
      }
      _setStyle(n, r) {
        let [o, i] = n.split("."), s = o.indexOf("-") === -1 ? void 0 : Ue.DashCase;
        r != null ? this._renderer.setStyle(this._ngEl.nativeElement, o, i ? `${r}${i}` : r, s) : this._renderer.removeStyle(this._ngEl.nativeElement, o, s)
      }
      _applyChanges(n) {
        n.forEachRemovedItem(r => this._setStyle(r.key, null)), n.forEachAddedItem(r => this._setStyle(r.key, r.currentValue)), n.forEachChangedItem(r => this._setStyle(r.key, r.currentValue))
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(Et), U(zd), U(Co))
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngStyle", ""]
        ],
        inputs: {
          ngStyle: "ngStyle"
        }
      })
    }
    return e
  })(), q_ = (() => {
    class e {
      _viewContainerRef;
      _viewRef = null;
      ngTemplateOutletContext = null;
      ngTemplateOutlet = null;
      ngTemplateOutletInjector = null;
      constructor(n) {
        this._viewContainerRef = n
      }
      ngOnChanges(n) {
        if (this._shouldRecreateView(n)) {
          let r = this._viewContainerRef;
          if (this._viewRef && r.remove(r.indexOf(this._viewRef)), !this.ngTemplateOutlet) {
            this._viewRef = null;
            return
          }
          let o = this._createContextForwardProxy();
          this._viewRef = r.createEmbeddedView(this.ngTemplateOutlet, o, {
            injector: this.ngTemplateOutletInjector ?? void 0
          })
        }
      }
      _shouldRecreateView(n) {
        return !!n.ngTemplateOutlet || !!n.ngTemplateOutletInjector
      }
      _createContextForwardProxy() {
        return new Proxy({}, {
          set: (n, r, o) => this.ngTemplateOutletContext ? Reflect.set(this.ngTemplateOutletContext, r, o) : !1,
          get: (n, r, o) => {
            if (this.ngTemplateOutletContext) return Reflect.get(this.ngTemplateOutletContext, r, o)
          }
        })
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(ot))
      };
      static \u0275dir = it({
        type: e,
        selectors: [
          ["", "ngTemplateOutlet", ""]
        ],
        inputs: {
          ngTemplateOutletContext: "ngTemplateOutletContext",
          ngTemplateOutlet: "ngTemplateOutlet",
          ngTemplateOutletInjector: "ngTemplateOutletInjector"
        },
        features: [Ol]
      })
    }
    return e
  })();
  Qd = class {
    createSubscription(t, n, r) {
      return na(() => t.subscribe({
        next: n,
        error: r
      }))
    }
    dispose(t) {
      na(() => t.unsubscribe())
    }
  }, Kd = class {
    createSubscription(t, n, r) {
      return t.then(o => n?.(o), o => r?.(o)), {
        unsubscribe: () => {
          n = null, r = null
        }
      }
    }
    dispose(t) {
      t.unsubscribe()
    }
  }, Z_ = new Kd, Y_ = new Qd, Q_ = (() => {
    class e {
      _ref;
      _latestValue = null;
      markForCheckOnValueUpdate = !0;
      _subscription = null;
      _obj = null;
      _strategy = null;
      applicationErrorHandler = y(Be);
      constructor(n) {
        this._ref = n
      }
      ngOnDestroy() {
        this._subscription && this._dispose(), this._ref = null
      }
      transform(n) {
        if (!this._obj) {
          if (n) try {
            this.markForCheckOnValueUpdate = !1, this._subscribe(n)
          } finally {
            this.markForCheckOnValueUpdate = !0
          }
          return this._latestValue
        }
        return n !== this._obj ? (this._dispose(), this.transform(n)) : this._latestValue
      }
      _subscribe(n) {
        this._obj = n, this._strategy = this._selectStrategy(n), this._subscription = this._strategy.createSubscription(n, r => this._updateLatestValue(n, r), r => this.applicationErrorHandler(r))
      }
      _selectStrategy(n) {
        if (Mo(n)) return Z_;
        if (Xs(n)) return Y_;
        throw ef(e, n)
      }
      _dispose() {
        this._strategy.dispose(this._subscription), this._latestValue = null, this._subscription = null, this._obj = null
      }
      _updateLatestValue(n, r) {
        n === this._obj && (this._latestValue = r, this.markForCheckOnValueUpdate && this._ref?.markForCheck())
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(Ud, 16))
      };
      static \u0275pipe = bo({
        name: "async",
        type: e,
        pure: !1
      })
    }
    return e
  })(), K_ = (() => {
    class e {
      transform(n) {
        if (n == null) return null;
        if (typeof n != "string") throw ef(e, n);
        return n.toLowerCase()
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275pipe = bo({
        name: "lowercase",
        type: e,
        pure: !0
      })
    }
    return e
  })(), J_ = (() => {
    class e {
      _locale;
      constructor(n) {
        this._locale = n
      }
      transform(n, r, o) {
        if (!X_(n)) return null;
        o ||= this._locale;
        try {
          let i = eM(n);
          return Bv(i, o, r)
        } catch (i) {
          throw ef(e, i.message)
        }
      }
      static \u0275fac = function(r) {
        return new(r || e)(U(No, 16))
      };
      static \u0275pipe = bo({
        name: "number",
        type: e,
        pure: !0
      })
    }
    return e
  })();
  tf = (() => {
    class e {
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275mod = Bt({
        type: e
      });
      static \u0275inj = pt({})
    }
    return e
  })()
});

function Fo(e, t) {
  t = encodeURIComponent(t);
  for (let n of e.split(";")) {
    let r = n.indexOf("="),
      [o, i] = r == -1 ? [n, ""] : [n.slice(0, r), n.slice(r + 1)];
    if (o.trim() === t) return decodeURIComponent(i)
  }
  return null
}
var Mn, nf = h(() => {
  Mn = class {}
});

function tU(e) {
  return e === of
}

function tM(e, t) {
  let n = e.getElementById(t) || e.getElementsByName(t)[0];
  if (n) return n;
  if (typeof e.createTreeWalker == "function" && e.body && typeof e.body.attachShadow == "function") {
    let r = e.createTreeWalker(e.body, NodeFilter.SHOW_ELEMENT),
      o = r.currentNode;
    for (; o;) {
      let i = o.shadowRoot;
      if (i) {
        let s = i.getElementById(t) || i.querySelector(`[name="${t}"]`);
        if (s) return s
      }
      o = r.nextNode()
    }
  }
  return null
}
var of, nU, rf, da = h(() => {
  Hv();
  he();
  he();
  nf();
  Wd();
  of = "browser";
  nU = (() => {
    class e {
      static \u0275prov = N({
        token: e,
        providedIn: "root",
        factory: () => new rf(y(Y), window)
      })
    }
    return e
  })(), rf = class {
    document;
    window;
    offset = () => [0, 0];
    constructor(t, n) {
      this.document = t, this.window = n
    }
    setOffset(t) {
      Array.isArray(t) ? this.offset = () => t : this.offset = t
    }
    getScrollPosition() {
      return [this.window.scrollX, this.window.scrollY]
    }
    scrollToPosition(t, n) {
      this.window.scrollTo(G(V({}, n), {
        left: t[0],
        top: t[1]
      }))
    }
    scrollToAnchor(t, n) {
      let r = tM(this.document, t);
      r && (this.scrollToElement(r, n), r.focus())
    }
    setHistoryScrollRestoration(t) {
      try {
        this.window.history.scrollRestoration = t
      } catch {
        console.warn(Ye(2400, !1))
      }
    }
    scrollToElement(t, n) {
      let r = t.getBoundingClientRect(),
        o = r.left + this.window.pageXOffset,
        i = r.top + this.window.pageYOffset,
        s = this.offset();
      this.window.scrollTo(G(V({}, n), {
        left: o - s[0],
        top: i - s[1]
      }))
    }
  }
});

function Uv(e) {
  for (let t of e) t.remove()
}

function $v(e, t) {
  let n = t.createElement("style");
  return n.textContent = e, n
}

function nM(e, t, n, r) {
  let o = e.head?.querySelectorAll(`style[${sf}="${t}"],link[${sf}="${t}"]`);
  if (o)
    for (let i of o) i.removeAttribute(sf), i instanceof HTMLLinkElement ? r.set(i.href.slice(i.href.lastIndexOf("/") + 1), {
      usage: 0,
      elements: [i]
    }) : i.textContent && n.set(i.textContent, {
      usage: 0,
      elements: [i]
    })
}

function cf(e, t) {
  let n = t.createElement("link");
  return n.setAttribute("rel", "stylesheet"), n.setAttribute("href", e), n
}

function aM(e) {
  return oM.replace(ff, e)
}

function cM(e) {
  return rM.replace(ff, e)
}

function Wv(e, t) {
  return t.map(n => n.replace(ff, e))
}

function zv(e) {
  return e.tagName === "TEMPLATE" && e.content !== void 0
}
var ko, fa, ha, lf, sf, df, af, ff, Gv, rM, oM, iM, sM, pf, Po, uf, Lo, pa, qv = h(() => {
  da();
  he();
  he();
  ko = class {
    _doc;
    constructor(t) {
      this._doc = t
    }
    manager
  }, fa = (() => {
    class e extends ko {
      constructor(n) {
        super(n)
      }
      supports(n) {
        return !0
      }
      addEventListener(n, r, o, i) {
        return n.addEventListener(r, o, i), () => this.removeEventListener(n, r, o, i)
      }
      removeEventListener(n, r, o, i) {
        return n.removeEventListener(r, o, i)
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Y))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), ha = new T(""), lf = (() => {
    class e {
      _zone;
      _plugins;
      _eventNameToPlugin = new Map;
      constructor(n, r) {
        this._zone = r, n.forEach(s => {
          s.manager = this
        });
        let o = n.filter(s => !(s instanceof fa));
        this._plugins = o.slice().reverse();
        let i = n.find(s => s instanceof fa);
        i && this._plugins.push(i)
      }
      addEventListener(n, r, o, i) {
        return this._findPluginFor(r).addEventListener(n, r, o, i)
      }
      getZone() {
        return this._zone
      }
      _findPluginFor(n) {
        let r = this._eventNameToPlugin.get(n);
        if (r) return r;
        if (r = this._plugins.find(i => i.supports(n)), !r) throw new v(5101, !1);
        return this._eventNameToPlugin.set(n, r), r
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(ha), C(z))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), sf = "ng-app-id";
  df = (() => {
    class e {
      doc;
      appId;
      nonce;
      inline = new Map;
      external = new Map;
      hosts = new Set;
      constructor(n, r, o, i = {}) {
        this.doc = n, this.appId = r, this.nonce = o, nM(n, r, this.inline, this.external), this.hosts.add(n.head)
      }
      addStyles(n, r) {
        for (let o of n) this.addUsage(o, this.inline, $v);
        r?.forEach(o => this.addUsage(o, this.external, cf))
      }
      removeStyles(n, r) {
        for (let o of n) this.removeUsage(o, this.inline);
        r?.forEach(o => this.removeUsage(o, this.external))
      }
      addUsage(n, r, o) {
        let i = r.get(n);
        i ? i.usage++ : r.set(n, {
          usage: 1,
          elements: [...this.hosts].map(s => this.addElement(s, o(n, this.doc)))
        })
      }
      removeUsage(n, r) {
        let o = r.get(n);
        o && (o.usage--, o.usage <= 0 && (Uv(o.elements), r.delete(n)))
      }
      ngOnDestroy() {
        for (let [, {
            elements: n
          }] of [...this.inline, ...this.external]) Uv(n);
        this.hosts.clear()
      }
      addHost(n) {
        this.hosts.add(n);
        for (let [r, {
            elements: o
          }] of this.inline) o.push(this.addElement(n, $v(r, this.doc)));
        for (let [r, {
            elements: o
          }] of this.external) o.push(this.addElement(n, cf(r, this.doc)))
      }
      removeHost(n) {
        this.hosts.delete(n)
      }
      addElement(n, r) {
        return this.nonce && r.setAttribute("nonce", this.nonce), n.appendChild(r)
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Y), C(ks), C(Ls, 8), C(mo))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), af = {
    svg: "http://www.w3.org/2000/svg",
    xhtml: "http://www.w3.org/1999/xhtml",
    xlink: "http://www.w3.org/1999/xlink",
    xml: "http://www.w3.org/XML/1998/namespace",
    xmlns: "http://www.w3.org/2000/xmlns/",
    math: "http://www.w3.org/1998/Math/MathML"
  }, ff = /%COMP%/g, Gv = "%COMP%", rM = `_nghost-${Gv}`, oM = `_ngcontent-${Gv}`, iM = !0, sM = new T("", {
    providedIn: "root",
    factory: () => iM
  });
  pf = (() => {
    class e {
      eventManager;
      sharedStylesHost;
      appId;
      removeStylesOnCompDestroy;
      doc;
      ngZone;
      nonce;
      tracingService;
      rendererByCompId = new Map;
      defaultRenderer;
      platformIsServer;
      constructor(n, r, o, i, s, a, c = null, u = null) {
        this.eventManager = n, this.sharedStylesHost = r, this.appId = o, this.removeStylesOnCompDestroy = i, this.doc = s, this.ngZone = a, this.nonce = c, this.tracingService = u, this.platformIsServer = !1, this.defaultRenderer = new Po(n, s, a, this.platformIsServer, this.tracingService)
      }
      createRenderer(n, r) {
        if (!n || !r) return this.defaultRenderer;
        let o = this.getOrCreateRenderer(n, r);
        return o instanceof pa ? o.applyToHost(n) : o instanceof Lo && o.applyStyles(), o
      }
      getOrCreateRenderer(n, r) {
        let o = this.rendererByCompId,
          i = o.get(r.id);
        if (!i) {
          let s = this.doc,
            a = this.ngZone,
            c = this.eventManager,
            u = this.sharedStylesHost,
            l = this.removeStylesOnCompDestroy,
            d = this.platformIsServer,
            p = this.tracingService;
          switch (r.encapsulation) {
            case vt.Emulated:
              i = new pa(c, u, r, this.appId, l, s, a, d, p);
              break;
            case vt.ShadowDom:
              return new uf(c, u, n, r, s, a, this.nonce, d, p);
            default:
              i = new Lo(c, u, r, l, s, a, d, p);
              break
          }
          o.set(r.id, i)
        }
        return i
      }
      ngOnDestroy() {
        this.rendererByCompId.clear()
      }
      componentReplaced(n) {
        this.rendererByCompId.delete(n)
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(lf), C(df), C(ks), C(sM), C(Y), C(z), C(Ls), C(Lt, 8))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), Po = class {
    eventManager;
    doc;
    ngZone;
    platformIsServer;
    tracingService;
    data = Object.create(null);
    throwOnSyntheticProps = !0;
    constructor(t, n, r, o, i) {
      this.eventManager = t, this.doc = n, this.ngZone = r, this.platformIsServer = o, this.tracingService = i
    }
    destroy() {}
    destroyNode = null;
    createElement(t, n) {
      return n ? this.doc.createElementNS(af[n] || n, t) : this.doc.createElement(t)
    }
    createComment(t) {
      return this.doc.createComment(t)
    }
    createText(t) {
      return this.doc.createTextNode(t)
    }
    appendChild(t, n) {
      (zv(t) ? t.content : t).appendChild(n)
    }
    insertBefore(t, n, r) {
      t && (zv(t) ? t.content : t).insertBefore(n, r)
    }
    removeChild(t, n) {
      n.remove()
    }
    selectRootElement(t, n) {
      let r = typeof t == "string" ? this.doc.querySelector(t) : t;
      if (!r) throw new v(-5104, !1);
      return n || (r.textContent = ""), r
    }
    parentNode(t) {
      return t.parentNode
    }
    nextSibling(t) {
      return t.nextSibling
    }
    setAttribute(t, n, r, o) {
      if (o) {
        n = o + ":" + n;
        let i = af[o];
        i ? t.setAttributeNS(i, n, r) : t.setAttribute(n, r)
      } else t.setAttribute(n, r)
    }
    removeAttribute(t, n, r) {
      if (r) {
        let o = af[r];
        o ? t.removeAttributeNS(o, n) : t.removeAttribute(`${r}:${n}`)
      } else t.removeAttribute(n)
    }
    addClass(t, n) {
      t.classList.add(n)
    }
    removeClass(t, n) {
      t.classList.remove(n)
    }
    setStyle(t, n, r, o) {
      o & (Ue.DashCase | Ue.Important) ? t.style.setProperty(n, r, o & Ue.Important ? "important" : "") : t.style[n] = r
    }
    removeStyle(t, n, r) {
      r & Ue.DashCase ? t.style.removeProperty(n) : t.style[n] = ""
    }
    setProperty(t, n, r) {
      t != null && (t[n] = r)
    }
    setValue(t, n) {
      t.nodeValue = n
    }
    listen(t, n, r, o) {
      if (typeof t == "string" && (t = st().getGlobalEventTarget(this.doc, t), !t)) throw new v(5102, !1);
      let i = this.decoratePreventDefault(r);
      return this.tracingService?.wrapEventListener && (i = this.tracingService.wrapEventListener(t, n, i)), this.eventManager.addEventListener(t, n, i, o)
    }
    decoratePreventDefault(t) {
      return n => {
        if (n === "__ngUnwrap__") return t;
        t(n) === !1 && n.preventDefault()
      }
    }
  };
  uf = class extends Po {
    sharedStylesHost;
    hostEl;
    shadowRoot;
    constructor(t, n, r, o, i, s, a, c, u) {
      super(t, i, s, c, u), this.sharedStylesHost = n, this.hostEl = r, this.shadowRoot = r.attachShadow({
        mode: "open"
      }), this.sharedStylesHost.addHost(this.shadowRoot);
      let l = o.styles;
      l = Wv(o.id, l);
      for (let p of l) {
        let f = document.createElement("style");
        a && f.setAttribute("nonce", a), f.textContent = p, this.shadowRoot.appendChild(f)
      }
      let d = o.getExternalStyles?.();
      if (d)
        for (let p of d) {
          let f = cf(p, i);
          a && f.setAttribute("nonce", a), this.shadowRoot.appendChild(f)
        }
    }
    nodeOrShadowRoot(t) {
      return t === this.hostEl ? this.shadowRoot : t
    }
    appendChild(t, n) {
      return super.appendChild(this.nodeOrShadowRoot(t), n)
    }
    insertBefore(t, n, r) {
      return super.insertBefore(this.nodeOrShadowRoot(t), n, r)
    }
    removeChild(t, n) {
      return super.removeChild(null, n)
    }
    parentNode(t) {
      return this.nodeOrShadowRoot(super.parentNode(this.nodeOrShadowRoot(t)))
    }
    destroy() {
      this.sharedStylesHost.removeHost(this.shadowRoot)
    }
  }, Lo = class extends Po {
    sharedStylesHost;
    removeStylesOnCompDestroy;
    styles;
    styleUrls;
    constructor(t, n, r, o, i, s, a, c, u) {
      super(t, i, s, a, c), this.sharedStylesHost = n, this.removeStylesOnCompDestroy = o;
      let l = r.styles;
      this.styles = u ? Wv(u, l) : l, this.styleUrls = r.getExternalStyles?.(u)
    }
    applyStyles() {
      this.sharedStylesHost.addStyles(this.styles, this.styleUrls)
    }
    destroy() {
      this.removeStylesOnCompDestroy && In.size === 0 && this.sharedStylesHost.removeStyles(this.styles, this.styleUrls)
    }
  }, pa = class extends Lo {
    contentAttr;
    hostAttr;
    constructor(t, n, r, o, i, s, a, c, u) {
      let l = o + "-" + r.id;
      super(t, n, r, i, s, a, c, u, l), this.contentAttr = aM(l), this.hostAttr = cM(l)
    }
    applyToHost(t) {
      this.applyStyles(), this.setAttribute(t, this.hostAttr, "")
    }
    createElement(t, n) {
      let r = super.createElement(t, n);
      return super.setAttribute(r, this.contentAttr, ""), r
    }
  }
});

function uM() {
  return jo = jo || document.head.querySelector("base"), jo ? jo.getAttribute("href") : null
}

function lM(e) {
  return new URL(e, document.baseURI).pathname
}

function hM(e, t, n) {
  let r = V({
    rootComponent: e,
    platformRef: n?.platformRef
  }, gM(t));
  return _v(r)
}

function gM(e) {
  return {
    appProviders: [...Qv, ...e?.providers ?? []],
    platformProviders: DM
  }
}

function mM() {
  ga.makeCurrent()
}

function yM() {
  return new De
}

function vM() {
  return Ll(document), document
}
var ga, jo, ma, dM, Zv, fM, pM, Yv, DM, EM, Qv, IM, Kv = h(() => {
  da();
  he();
  he();
  qv();
  ga = class e extends xo {
    supportsDOMEvents = !0;
    static makeCurrent() {
      Gd(new e)
    }
    onAndCancel(t, n, r, o) {
      return t.addEventListener(n, r, o), () => {
        t.removeEventListener(n, r, o)
      }
    }
    dispatchEvent(t, n) {
      t.dispatchEvent(n)
    }
    remove(t) {
      t.remove()
    }
    createElement(t, n) {
      return n = n || this.getDefaultDocument(), n.createElement(t)
    }
    createHtmlDocument() {
      return document.implementation.createHTMLDocument("fakeTitle")
    }
    getDefaultDocument() {
      return document
    }
    isElementNode(t) {
      return t.nodeType === Node.ELEMENT_NODE
    }
    isShadowRoot(t) {
      return t instanceof DocumentFragment
    }
    getGlobalEventTarget(t, n) {
      return n === "window" ? window : n === "document" ? t : n === "body" ? t.body : null
    }
    getBaseHref(t) {
      let n = uM();
      return n == null ? null : lM(n)
    }
    resetBaseElement() {
      jo = null
    }
    getUserAgent() {
      return window.navigator.userAgent
    }
    getCookie(t) {
      return Fo(document.cookie, t)
    }
  }, jo = null;
  ma = class {
    addToWindow(t) {
      ne.getAngularTestability = (r, o = !0) => {
        let i = t.findTestabilityInTree(r, o);
        if (i == null) throw new v(5103, !1);
        return i
      }, ne.getAllAngularTestabilities = () => t.getAllTestabilities(), ne.getAllAngularRootElements = () => t.getAllRootElements();
      let n = r => {
        let o = ne.getAllAngularTestabilities(),
          i = o.length,
          s = function() {
            i--, i == 0 && r()
          };
        o.forEach(a => {
          a.whenStable(s)
        })
      };
      ne.frameworkStabilizers || (ne.frameworkStabilizers = []), ne.frameworkStabilizers.push(n)
    }
    findTestabilityInTree(t, n, r) {
      if (n == null) return null;
      let o = t.getTestability(n);
      return o ?? (r ? st().isShadowRoot(n) ? this.findTestabilityInTree(t, n.host, !0) : this.findTestabilityInTree(t, n.parentElement, !0) : null)
    }
  }, dM = (() => {
    class e {
      build() {
        return new XMLHttpRequest
      }
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), Zv = ["alt", "control", "meta", "shift"], fM = {
    "\b": "Backspace",
    "	": "Tab",
    "\x7F": "Delete",
    "\x1B": "Escape",
    Del: "Delete",
    Esc: "Escape",
    Left: "ArrowLeft",
    Right: "ArrowRight",
    Up: "ArrowUp",
    Down: "ArrowDown",
    Menu: "ContextMenu",
    Scroll: "ScrollLock",
    Win: "OS"
  }, pM = {
    alt: e => e.altKey,
    control: e => e.ctrlKey,
    meta: e => e.metaKey,
    shift: e => e.shiftKey
  }, Yv = (() => {
    class e extends ko {
      constructor(n) {
        super(n)
      }
      supports(n) {
        return e.parseEventName(n) != null
      }
      addEventListener(n, r, o, i) {
        let s = e.parseEventName(r),
          a = e.eventCallback(s.fullKey, o, this.manager.getZone());
        return this.manager.getZone().runOutsideAngular(() => st().onAndCancel(n, s.domEventName, a, i))
      }
      static parseEventName(n) {
        let r = n.toLowerCase().split("."),
          o = r.shift();
        if (r.length === 0 || !(o === "keydown" || o === "keyup")) return null;
        let i = e._normalizeKey(r.pop()),
          s = "",
          a = r.indexOf("code");
        if (a > -1 && (r.splice(a, 1), s = "code."), Zv.forEach(u => {
            let l = r.indexOf(u);
            l > -1 && (r.splice(l, 1), s += u + ".")
          }), s += i, r.length != 0 || i.length === 0) return null;
        let c = {};
        return c.domEventName = o, c.fullKey = s, c
      }
      static matchEventFullKeyCode(n, r) {
        let o = fM[n.key] || n.key,
          i = "";
        return r.indexOf("code.") > -1 && (o = n.code, i = "code."), o == null || !o ? !1 : (o = o.toLowerCase(), o === " " ? o = "space" : o === "." && (o = "dot"), Zv.forEach(s => {
          if (s !== o) {
            let a = pM[s];
            a(n) && (i += s + ".")
          }
        }), i += o, i === r)
      }
      static eventCallback(n, r, o) {
        return i => {
          e.matchEventFullKeyCode(i, n) && o.runGuarded(() => r(i))
        }
      }
      static _normalizeKey(n) {
        return n === "esc" ? "escape" : n
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Y))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })();
  DM = [{
    provide: mo,
    useValue: of
  }, {
    provide: Ps,
    useValue: mM,
    multi: !0
  }, {
    provide: Y,
    useFactory: vM
  }], EM = [{
    provide: vr,
    useClass: ma
  }, {
    provide: Js,
    useClass: To,
    deps: [z, _o, vr]
  }, {
    provide: To,
    useClass: To,
    deps: [z, _o, vr]
  }], Qv = [{
      provide: Yr,
      useValue: "root"
    }, {
      provide: De,
      useFactory: yM
    }, {
      provide: ha,
      useClass: fa,
      multi: !0,
      deps: [Y]
    }, {
      provide: ha,
      useClass: Yv,
      multi: !0,
      deps: [Y]
    }, pf, df, lf, {
      provide: wn,
      useExisting: pf
    }, {
      provide: Mn,
      useClass: dM
    },
    []
  ], IM = (() => {
    class e {
      constructor() {}
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275mod = Bt({
        type: e
      });
      static \u0275inj = pt({
        providers: [...Qv, ...EM],
        imports: [tf, Tv]
      })
    }
    return e
  })()
});

function wM(e, t) {
  let n = new Map;
  return e.length > 0 && e.replace(/^\?/, "").split("&").forEach(o => {
    let i = o.indexOf("="),
      [s, a] = i == -1 ? [t.decodeKey(o), ""] : [t.decodeKey(o.slice(0, i)), t.decodeValue(o.slice(i + 1))],
      c = n.get(s) || [];
    c.push(a), n.set(s, c)
  }), n
}

function Jv(e) {
  return encodeURIComponent(e).replace(CM, (t, n) => bM[n] ?? t)
}

function ya(e) {
  return `${e}`
}

function TM(e) {
  switch (e) {
    case "DELETE":
    case "GET":
    case "HEAD":
    case "OPTIONS":
    case "JSONP":
      return !1;
    default:
      return !0
  }
}

function Xv(e) {
  return typeof ArrayBuffer < "u" && e instanceof ArrayBuffer
}

function eD(e) {
  return typeof Blob < "u" && e instanceof Blob
}

function tD(e) {
  return typeof FormData < "u" && e instanceof FormData
}

function _M(e) {
  return typeof URLSearchParams < "u" && e instanceof URLSearchParams
}

function hf(e, t) {
  return {
    body: t,
    headers: e.headers,
    context: e.context,
    observe: e.observe,
    params: e.params,
    reportProgress: e.reportProgress,
    responseType: e.responseType,
    withCredentials: e.withCredentials,
    credentials: e.credentials,
    transferCache: e.transferCache,
    timeout: e.timeout,
    keepalive: e.keepalive,
    priority: e.priority,
    cache: e.cache,
    mode: e.mode,
    redirect: e.redirect,
    integrity: e.integrity,
    referrer: e.referrer
  }
}

function uD(e, t) {
  return t(e)
}

function xM(e, t) {
  return (n, r) => t.intercept(n, {
    handle: o => e(o, r)
  })
}

function RM(e, t, n) {
  return (r, o) => Xn(n, () => t(r, i => e(i, o)))
}

function OM() {
  let e = null;
  return (t, n) => {
    e === null && (e = (y(lD, {
      optional: !0
    }) ?? []).reduceRight(xM, uD));
    let r = y(ar);
    if (y(yf)) {
      let i = r.add();
      return e(t, n).pipe(Hr(i))
    } else return e(t, n)
  }
}

function PM(e) {
  return "responseURL" in e && e.responseURL ? e.responseURL : kM.test(e.getAllResponseHeaders()) ? e.getResponseHeader(iD) : null
}

function $M(e, t) {
  if (!y(fD) || e.method === "GET" || e.method === "HEAD" || UM.test(e.url)) return t(e);
  let n = y(Ho).getToken(),
    r = y(VM);
  return n != null && !e.headers.has(r) && (e = e.clone({
    headers: e.headers.set(r, n)
  })), t(e)
}

function zM(e, t) {
  return {
    \u0275kind: e,
    \u0275providers: t
  }
}

function GM(...e) {
  let t = [cD, gf, Ia, {
    provide: br,
    useExisting: Ia
  }, {
    provide: Bo,
    useFactory: () => y(AM, {
      optional: !0
    }) ?? y(gf)
  }, {
    provide: mf,
    useValue: $M,
    multi: !0
  }, {
    provide: fD,
    useValue: !0
  }, {
    provide: Ho,
    useClass: HM
  }];
  for (let n of e) t.push(...n.\u0275providers);
  return Kn(t)
}

function WM() {
  return zM(vf.LegacyInterceptors, [{
    provide: oD,
    useFactory: OM
  }, {
    provide: mf,
    useExisting: oD,
    multi: !0
  }])
}
var br, Bo, Vt, va, CM, bM, wt, Da, nD, rD, iD, sD, aD, MM, wr, Sn, Tr, Ea, Vo, Cr, SM, NM, cD, AM, lD, mf, dD, yf, Ia, FM, kM, gf, fD, LM, jM, BM, VM, Ho, HM, UM, vf, oD, Df = h(() => {
  he();
  he();
  ku();
  Ur();
  nf();
  br = class {}, Bo = class {}, Vt = class e {
    headers;
    normalizedNames = new Map;
    lazyInit;
    lazyUpdate = null;
    constructor(t) {
      t ? typeof t == "string" ? this.lazyInit = () => {
        this.headers = new Map, t.split(`
`).forEach(n => {
          let r = n.indexOf(":");
          if (r > 0) {
            let o = n.slice(0, r),
              i = n.slice(r + 1).trim();
            this.addHeaderEntry(o, i)
          }
        })
      } : typeof Headers < "u" && t instanceof Headers ? (this.headers = new Map, t.forEach((n, r) => {
        this.addHeaderEntry(r, n)
      })) : this.lazyInit = () => {
        this.headers = new Map, Object.entries(t).forEach(([n, r]) => {
          this.setHeaderEntries(n, r)
        })
      } : this.headers = new Map
    }
    has(t) {
      return this.init(), this.headers.has(t.toLowerCase())
    }
    get(t) {
      this.init();
      let n = this.headers.get(t.toLowerCase());
      return n && n.length > 0 ? n[0] : null
    }
    keys() {
      return this.init(), Array.from(this.normalizedNames.values())
    }
    getAll(t) {
      return this.init(), this.headers.get(t.toLowerCase()) || null
    }
    append(t, n) {
      return this.clone({
        name: t,
        value: n,
        op: "a"
      })
    }
    set(t, n) {
      return this.clone({
        name: t,
        value: n,
        op: "s"
      })
    }
    delete(t, n) {
      return this.clone({
        name: t,
        value: n,
        op: "d"
      })
    }
    maybeSetNormalizedName(t, n) {
      this.normalizedNames.has(n) || this.normalizedNames.set(n, t)
    }
    init() {
      this.lazyInit && (this.lazyInit instanceof e ? this.copyFrom(this.lazyInit) : this.lazyInit(), this.lazyInit = null, this.lazyUpdate && (this.lazyUpdate.forEach(t => this.applyUpdate(t)), this.lazyUpdate = null))
    }
    copyFrom(t) {
      t.init(), Array.from(t.headers.keys()).forEach(n => {
        this.headers.set(n, t.headers.get(n)), this.normalizedNames.set(n, t.normalizedNames.get(n))
      })
    }
    clone(t) {
      let n = new e;
      return n.lazyInit = this.lazyInit && this.lazyInit instanceof e ? this.lazyInit : this, n.lazyUpdate = (this.lazyUpdate || []).concat([t]), n
    }
    applyUpdate(t) {
      let n = t.name.toLowerCase();
      switch (t.op) {
        case "a":
        case "s":
          let r = t.value;
          if (typeof r == "string" && (r = [r]), r.length === 0) return;
          this.maybeSetNormalizedName(t.name, n);
          let o = (t.op === "a" ? this.headers.get(n) : void 0) || [];
          o.push(...r), this.headers.set(n, o);
          break;
        case "d":
          let i = t.value;
          if (!i) this.headers.delete(n), this.normalizedNames.delete(n);
          else {
            let s = this.headers.get(n);
            if (!s) return;
            s = s.filter(a => i.indexOf(a) === -1), s.length === 0 ? (this.headers.delete(n), this.normalizedNames.delete(n)) : this.headers.set(n, s)
          }
          break
      }
    }
    addHeaderEntry(t, n) {
      let r = t.toLowerCase();
      this.maybeSetNormalizedName(t, r), this.headers.has(r) ? this.headers.get(r).push(n) : this.headers.set(r, [n])
    }
    setHeaderEntries(t, n) {
      let r = (Array.isArray(n) ? n : [n]).map(i => i.toString()),
        o = t.toLowerCase();
      this.headers.set(o, r), this.maybeSetNormalizedName(t, o)
    }
    forEach(t) {
      this.init(), Array.from(this.normalizedNames.keys()).forEach(n => t(this.normalizedNames.get(n), this.headers.get(n)))
    }
  }, va = class {
    encodeKey(t) {
      return Jv(t)
    }
    encodeValue(t) {
      return Jv(t)
    }
    decodeKey(t) {
      return decodeURIComponent(t)
    }
    decodeValue(t) {
      return decodeURIComponent(t)
    }
  };
  CM = /%(\d[a-f0-9])/gi, bM = {
    40: "@",
    "3A": ":",
    24: "$",
    "2C": ",",
    "3B": ";",
    "3D": "=",
    "3F": "?",
    "2F": "/"
  };
  wt = class e {
    map;
    encoder;
    updates = null;
    cloneFrom = null;
    constructor(t = {}) {
      if (this.encoder = t.encoder || new va, t.fromString) {
        if (t.fromObject) throw new v(2805, !1);
        this.map = wM(t.fromString, this.encoder)
      } else t.fromObject ? (this.map = new Map, Object.keys(t.fromObject).forEach(n => {
        let r = t.fromObject[n],
          o = Array.isArray(r) ? r.map(ya) : [ya(r)];
        this.map.set(n, o)
      })) : this.map = null
    }
    has(t) {
      return this.init(), this.map.has(t)
    }
    get(t) {
      this.init();
      let n = this.map.get(t);
      return n ? n[0] : null
    }
    getAll(t) {
      return this.init(), this.map.get(t) || null
    }
    keys() {
      return this.init(), Array.from(this.map.keys())
    }
    append(t, n) {
      return this.clone({
        param: t,
        value: n,
        op: "a"
      })
    }
    appendAll(t) {
      let n = [];
      return Object.keys(t).forEach(r => {
        let o = t[r];
        Array.isArray(o) ? o.forEach(i => {
          n.push({
            param: r,
            value: i,
            op: "a"
          })
        }) : n.push({
          param: r,
          value: o,
          op: "a"
        })
      }), this.clone(n)
    }
    set(t, n) {
      return this.clone({
        param: t,
        value: n,
        op: "s"
      })
    }
    delete(t, n) {
      return this.clone({
        param: t,
        value: n,
        op: "d"
      })
    }
    toString() {
      return this.init(), this.keys().map(t => {
        let n = this.encoder.encodeKey(t);
        return this.map.get(t).map(r => n + "=" + this.encoder.encodeValue(r)).join("&")
      }).filter(t => t !== "").join("&")
    }
    clone(t) {
      let n = new e({
        encoder: this.encoder
      });
      return n.cloneFrom = this.cloneFrom || this, n.updates = (this.updates || []).concat(t), n
    }
    init() {
      this.map === null && (this.map = new Map), this.cloneFrom !== null && (this.cloneFrom.init(), this.cloneFrom.keys().forEach(t => this.map.set(t, this.cloneFrom.map.get(t))), this.updates.forEach(t => {
        switch (t.op) {
          case "a":
          case "s":
            let n = (t.op === "a" ? this.map.get(t.param) : void 0) || [];
            n.push(ya(t.value)), this.map.set(t.param, n);
            break;
          case "d":
            if (t.value !== void 0) {
              let r = this.map.get(t.param) || [],
                o = r.indexOf(ya(t.value));
              o !== -1 && r.splice(o, 1), r.length > 0 ? this.map.set(t.param, r) : this.map.delete(t.param)
            } else {
              this.map.delete(t.param);
              break
            }
        }
      }), this.cloneFrom = this.updates = null)
    }
  }, Da = class {
    map = new Map;
    set(t, n) {
      return this.map.set(t, n), this
    }
    get(t) {
      return this.map.has(t) || this.map.set(t, t.defaultValue()), this.map.get(t)
    }
    delete(t) {
      return this.map.delete(t), this
    }
    has(t) {
      return this.map.has(t)
    }
    keys() {
      return this.map.keys()
    }
  };
  nD = "Content-Type", rD = "Accept", iD = "X-Request-URL", sD = "text/plain", aD = "application/json", MM = `${aD}, ${sD}, */*`, wr = class e {
    url;
    body = null;
    headers;
    context;
    reportProgress = !1;
    withCredentials = !1;
    credentials;
    keepalive = !1;
    cache;
    priority;
    mode;
    redirect;
    referrer;
    integrity;
    responseType = "json";
    method;
    params;
    urlWithParams;
    transferCache;
    timeout;
    constructor(t, n, r, o) {
      this.url = n, this.method = t.toUpperCase();
      let i;
      if (TM(this.method) || o ? (this.body = r !== void 0 ? r : null, i = o) : i = r, i) {
        if (this.reportProgress = !!i.reportProgress, this.withCredentials = !!i.withCredentials, this.keepalive = !!i.keepalive, i.responseType && (this.responseType = i.responseType), i.headers && (this.headers = i.headers), i.context && (this.context = i.context), i.params && (this.params = i.params), i.priority && (this.priority = i.priority), i.cache && (this.cache = i.cache), i.credentials && (this.credentials = i.credentials), typeof i.timeout == "number") {
          if (i.timeout < 1 || !Number.isInteger(i.timeout)) throw new v(2822, "");
          this.timeout = i.timeout
        }
        i.mode && (this.mode = i.mode), i.redirect && (this.redirect = i.redirect), i.integrity && (this.integrity = i.integrity), i.referrer && (this.referrer = i.referrer), this.transferCache = i.transferCache
      }
      if (this.headers ??= new Vt, this.context ??= new Da, !this.params) this.params = new wt, this.urlWithParams = n;
      else {
        let s = this.params.toString();
        if (s.length === 0) this.urlWithParams = n;
        else {
          let a = n.indexOf("?"),
            c = a === -1 ? "?" : a < n.length - 1 ? "&" : "";
          this.urlWithParams = n + c + s
        }
      }
    }
    serializeBody() {
      return this.body === null ? null : typeof this.body == "string" || Xv(this.body) || eD(this.body) || tD(this.body) || _M(this.body) ? this.body : this.body instanceof wt ? this.body.toString() : typeof this.body == "object" || typeof this.body == "boolean" || Array.isArray(this.body) ? JSON.stringify(this.body) : this.body.toString()
    }
    detectContentTypeHeader() {
      return this.body === null || tD(this.body) ? null : eD(this.body) ? this.body.type || null : Xv(this.body) ? null : typeof this.body == "string" ? sD : this.body instanceof wt ? "application/x-www-form-urlencoded;charset=UTF-8" : typeof this.body == "object" || typeof this.body == "number" || typeof this.body == "boolean" ? aD : null
    }
    clone(t = {}) {
      let n = t.method || this.method,
        r = t.url || this.url,
        o = t.responseType || this.responseType,
        i = t.keepalive ?? this.keepalive,
        s = t.priority || this.priority,
        a = t.cache || this.cache,
        c = t.mode || this.mode,
        u = t.redirect || this.redirect,
        l = t.credentials || this.credentials,
        d = t.referrer || this.referrer,
        p = t.integrity || this.integrity,
        f = t.transferCache ?? this.transferCache,
        g = t.timeout ?? this.timeout,
        I = t.body !== void 0 ? t.body : this.body,
        D = t.withCredentials ?? this.withCredentials,
        m = t.reportProgress ?? this.reportProgress,
        F = t.headers || this.headers,
        ct = t.params || this.params,
        Q = t.context ?? this.context;
      return t.setHeaders !== void 0 && (F = Object.keys(t.setHeaders).reduce((ze, Ht) => ze.set(Ht, t.setHeaders[Ht]), F)), t.setParams && (ct = Object.keys(t.setParams).reduce((ze, Ht) => ze.set(Ht, t.setParams[Ht]), ct)), new e(n, r, I, {
        params: ct,
        headers: F,
        context: Q,
        reportProgress: m,
        responseType: o,
        withCredentials: D,
        transferCache: f,
        keepalive: i,
        cache: a,
        priority: s,
        timeout: g,
        mode: c,
        redirect: u,
        credentials: l,
        referrer: d,
        integrity: p
      })
    }
  }, Sn = (function(e) {
    return e[e.Sent = 0] = "Sent", e[e.UploadProgress = 1] = "UploadProgress", e[e.ResponseHeader = 2] = "ResponseHeader", e[e.DownloadProgress = 3] = "DownloadProgress", e[e.Response = 4] = "Response", e[e.User = 5] = "User", e
  })(Sn || {}), Tr = class {
    headers;
    status;
    statusText;
    url;
    ok;
    type;
    redirected;
    constructor(t, n = 200, r = "OK") {
      this.headers = t.headers || new Vt, this.status = t.status !== void 0 ? t.status : n, this.statusText = t.statusText || r, this.url = t.url || null, this.redirected = t.redirected, this.ok = this.status >= 200 && this.status < 300
    }
  }, Ea = class e extends Tr {
    constructor(t = {}) {
      super(t)
    }
    type = Sn.ResponseHeader;
    clone(t = {}) {
      return new e({
        headers: t.headers || this.headers,
        status: t.status !== void 0 ? t.status : this.status,
        statusText: t.statusText || this.statusText,
        url: t.url || this.url || void 0
      })
    }
  }, Vo = class e extends Tr {
    body;
    constructor(t = {}) {
      super(t), this.body = t.body !== void 0 ? t.body : null
    }
    type = Sn.Response;
    clone(t = {}) {
      return new e({
        body: t.body !== void 0 ? t.body : this.body,
        headers: t.headers || this.headers,
        status: t.status !== void 0 ? t.status : this.status,
        statusText: t.statusText || this.statusText,
        url: t.url || this.url || void 0,
        redirected: t.redirected ?? this.redirected
      })
    }
  }, Cr = class extends Tr {
    name = "HttpErrorResponse";
    message;
    error;
    ok = !1;
    constructor(t) {
      super(t, 0, "Unknown Error"), this.status >= 200 && this.status < 300 ? this.message = `Http failure during parsing for ${t.url||"(unknown url)"}` : this.message = `Http failure response for ${t.url||"(unknown url)"}: ${t.status} ${t.statusText}`, this.error = t.error || null
    }
  }, SM = 200, NM = 204;
  cD = (() => {
    class e {
      handler;
      constructor(n) {
        this.handler = n
      }
      request(n, r, o = {}) {
        let i;
        if (n instanceof wr) i = n;
        else {
          let c;
          o.headers instanceof Vt ? c = o.headers : c = new Vt(o.headers);
          let u;
          o.params && (o.params instanceof wt ? u = o.params : u = new wt({
            fromObject: o.params
          })), i = new wr(n, r, o.body !== void 0 ? o.body : null, {
            headers: c,
            context: o.context,
            params: u,
            reportProgress: o.reportProgress,
            responseType: o.responseType || "json",
            withCredentials: o.withCredentials,
            transferCache: o.transferCache,
            keepalive: o.keepalive,
            priority: o.priority,
            cache: o.cache,
            mode: o.mode,
            redirect: o.redirect,
            credentials: o.credentials,
            referrer: o.referrer,
            integrity: o.integrity,
            timeout: o.timeout
          })
        }
        let s = Ti(i).pipe(pc(c => this.handler.handle(c)));
        if (n instanceof wr || o.observe === "events") return s;
        let a = s.pipe(Ze(c => c instanceof Vo));
        switch (o.observe || "body") {
          case "body":
            switch (i.responseType) {
              case "arraybuffer":
                return a.pipe(le(c => {
                  if (c.body !== null && !(c.body instanceof ArrayBuffer)) throw new v(2806, !1);
                  return c.body
                }));
              case "blob":
                return a.pipe(le(c => {
                  if (c.body !== null && !(c.body instanceof Blob)) throw new v(2807, !1);
                  return c.body
                }));
              case "text":
                return a.pipe(le(c => {
                  if (c.body !== null && typeof c.body != "string") throw new v(2808, !1);
                  return c.body
                }));
              case "json":
              default:
                return a.pipe(le(c => c.body))
            }
          case "response":
            return a;
          default:
            throw new v(2809, !1)
        }
      }
      delete(n, r = {}) {
        return this.request("DELETE", n, r)
      }
      get(n, r = {}) {
        return this.request("GET", n, r)
      }
      head(n, r = {}) {
        return this.request("HEAD", n, r)
      }
      jsonp(n, r) {
        return this.request("JSONP", n, {
          params: new wt().append(r, "JSONP_CALLBACK"),
          observe: "body",
          responseType: "json"
        })
      }
      options(n, r = {}) {
        return this.request("OPTIONS", n, r)
      }
      patch(n, r, o = {}) {
        return this.request("PATCH", n, hf(o, r))
      }
      post(n, r, o = {}) {
        return this.request("POST", n, hf(o, r))
      }
      put(n, r, o = {}) {
        return this.request("PUT", n, hf(o, r))
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(br))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), AM = new T("");
  lD = new T(""), mf = new T(""), dD = new T(""), yf = new T("", {
    providedIn: "root",
    factory: () => !0
  });
  Ia = (() => {
    class e extends br {
      backend;
      injector;
      chain = null;
      pendingTasks = y(ar);
      contributeToStability = y(yf);
      constructor(n, r) {
        super(), this.backend = n, this.injector = r
      }
      handle(n) {
        if (this.chain === null) {
          let r = Array.from(new Set([...this.injector.get(mf), ...this.injector.get(dD, [])]));
          this.chain = r.reduceRight((o, i) => RM(o, i, this.injector), uD)
        }
        if (this.contributeToStability) {
          let r = this.pendingTasks.add();
          return this.chain(n, o => this.backend.handle(o)).pipe(Hr(r))
        } else return this.chain(n, r => this.backend.handle(r))
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Bo), C(ye))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), FM = /^\)\]\}',?\n/, kM = RegExp(`^${iD}:`, "m");
  gf = (() => {
    class e {
      xhrFactory;
      constructor(n) {
        this.xhrFactory = n
      }
      handle(n) {
        if (n.method === "JSONP") throw new v(-2800, !1);
        let r = this.xhrFactory;
        return Ti(null).pipe(Fi(() => new R(i => {
          let s = r.build();
          if (s.open(n.method, n.urlWithParams), n.withCredentials && (s.withCredentials = !0), n.headers.forEach((D, m) => s.setRequestHeader(D, m.join(","))), n.headers.has(rD) || s.setRequestHeader(rD, MM), !n.headers.has(nD)) {
            let D = n.detectContentTypeHeader();
            D !== null && s.setRequestHeader(nD, D)
          }
          if (n.timeout && (s.timeout = n.timeout), n.responseType) {
            let D = n.responseType.toLowerCase();
            s.responseType = D !== "json" ? D : "text"
          }
          let a = n.serializeBody(),
            c = null,
            u = () => {
              if (c !== null) return c;
              let D = s.statusText || "OK",
                m = new Vt(s.getAllResponseHeaders()),
                F = PM(s) || n.url;
              return c = new Ea({
                headers: m,
                status: s.status,
                statusText: D,
                url: F
              }), c
            },
            l = () => {
              let {
                headers: D,
                status: m,
                statusText: F,
                url: ct
              } = u(), Q = null;
              m !== NM && (Q = typeof s.response > "u" ? s.responseText : s.response), m === 0 && (m = Q ? SM : 0);
              let ze = m >= 200 && m < 300;
              if (n.responseType === "json" && typeof Q == "string") {
                let Ht = Q;
                Q = Q.replace(FM, "");
                try {
                  Q = Q !== "" ? JSON.parse(Q) : null
                } catch (pD) {
                  Q = Ht, ze && (ze = !1, Q = {
                    error: pD,
                    text: Q
                  })
                }
              }
              ze ? (i.next(new Vo({
                body: Q,
                headers: D,
                status: m,
                statusText: F,
                url: ct || void 0
              })), i.complete()) : i.error(new Cr({
                error: Q,
                headers: D,
                status: m,
                statusText: F,
                url: ct || void 0
              }))
            },
            d = D => {
              let {
                url: m
              } = u(), F = new Cr({
                error: D,
                status: s.status || 0,
                statusText: s.statusText || "Unknown Error",
                url: m || void 0
              });
              i.error(F)
            },
            p = d;
          n.timeout && (p = D => {
            let {
              url: m
            } = u(), F = new Cr({
              error: new DOMException("Request timed out", "TimeoutError"),
              status: s.status || 0,
              statusText: s.statusText || "Request timeout",
              url: m || void 0
            });
            i.error(F)
          });
          let f = !1,
            g = D => {
              f || (i.next(u()), f = !0);
              let m = {
                type: Sn.DownloadProgress,
                loaded: D.loaded
              };
              D.lengthComputable && (m.total = D.total), n.responseType === "text" && s.responseText && (m.partialText = s.responseText), i.next(m)
            },
            I = D => {
              let m = {
                type: Sn.UploadProgress,
                loaded: D.loaded
              };
              D.lengthComputable && (m.total = D.total), i.next(m)
            };
          return s.addEventListener("load", l), s.addEventListener("error", d), s.addEventListener("timeout", p), s.addEventListener("abort", d), n.reportProgress && (s.addEventListener("progress", g), a !== null && s.upload && s.upload.addEventListener("progress", I)), s.send(a), i.next({
            type: Sn.Sent
          }), () => {
            s.removeEventListener("error", d), s.removeEventListener("abort", d), s.removeEventListener("load", l), s.removeEventListener("timeout", p), n.reportProgress && (s.removeEventListener("progress", g), a !== null && s.upload && s.upload.removeEventListener("progress", I)), s.readyState !== s.DONE && s.abort()
          }
        })))
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Mn))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), fD = new T(""), LM = "XSRF-TOKEN", jM = new T("", {
    providedIn: "root",
    factory: () => LM
  }), BM = "X-XSRF-TOKEN", VM = new T("", {
    providedIn: "root",
    factory: () => BM
  }), Ho = class {}, HM = (() => {
    class e {
      doc;
      cookieName;
      lastCookieString = "";
      lastToken = null;
      parseCount = 0;
      constructor(n, r) {
        this.doc = n, this.cookieName = r
      }
      getToken() {
        let n = this.doc.cookie || "";
        return n !== this.lastCookieString && (this.parseCount++, this.lastToken = Fo(n, this.cookieName), this.lastCookieString = n), this.lastToken
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Y), C(jM))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac
      })
    }
    return e
  })(), UM = /^(?:https?:)?\/\//i;
  vf = (function(e) {
    return e[e.Interceptors = 0] = "Interceptors", e[e.LegacyInterceptors = 1] = "LegacyInterceptors", e[e.CustomXsrfConfiguration = 2] = "CustomXsrfConfiguration", e[e.NoXsrfProtection = 3] = "NoXsrfProtection", e[e.JsonpSupport = 4] = "JsonpSupport", e[e.RequestsMadeViaParent = 5] = "RequestsMadeViaParent", e[e.Fetch = 6] = "Fetch", e
  })(vf || {});
  oD = new T("")
});
var qM = h(() => {
  Df();
  Df();
});
var v$, ZM, YM, QM = h(() => {
  Kv();
  da();
  he();
  he();
  v$ = (() => {
    class e {
      _doc;
      constructor(n) {
        this._doc = n
      }
      getTitle() {
        return this._doc.title
      }
      setTitle(n) {
        this._doc.title = n || ""
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Y))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })(), ZM = (() => {
    class e {
      static \u0275fac = function(r) {
        return new(r || e)
      };
      static \u0275prov = N({
        token: e,
        factory: function(r) {
          let o = null;
          return r ? o = new(r || e) : o = C(YM), o
        },
        providedIn: "root"
      })
    }
    return e
  })(), YM = (() => {
    class e extends ZM {
      _doc;
      constructor(n) {
        super(), this._doc = n
      }
      sanitize(n, r) {
        if (r == null) return null;
        switch (n) {
          case xe.NONE:
            return r;
          case xe.HTML:
            return rt(r, "HTML") ? Ce(r) : Vs(this._doc, String(r)).toString();
          case xe.STYLE:
            return rt(r, "Style") ? Ce(r) : r;
          case xe.SCRIPT:
            if (rt(r, "Script")) return Ce(r);
            throw new v(5200, !1);
          case xe.URL:
            return rt(r, "URL") ? Ce(r) : yo(String(r));
          case xe.RESOURCE_URL:
            if (rt(r, "ResourceURL")) return Ce(r);
            throw new v(5201, !1);
          default:
            throw new v(5202, !1)
        }
      }
      bypassSecurityTrustHtml(n) {
        return Vl(n)
      }
      bypassSecurityTrustStyle(n) {
        return Hl(n)
      }
      bypassSecurityTrustScript(n) {
        return Ul(n)
      }
      bypassSecurityTrustUrl(n) {
        return $l(n)
      }
      bypassSecurityTrustResourceUrl(n) {
        return zl(n)
      }
      static \u0275fac = function(r) {
        return new(r || e)(C(Y))
      };
      static \u0275prov = N({
        token: e,
        factory: e.\u0275fac,
        providedIn: "root"
      })
    }
    return e
  })()
});
export {
  W as a, bD as b, R as c, Ua as d, za as e, ge as f, Rr as g, Fr as h, MD as i, Kt as j, qe as k, Ti as l, kD as m, PD as n, lt as o, LD as p, le as q, GD as r, be as s, Lr as t, qn as u, qD as v, ZD as w, lc as x, tn as y, tE as z, nE as A, Ze as B, rE as C, dc as D, pc as E, kp as F, Br as G, nn as H, gc as I, oE as J, Vp as K, aE as L, Hr as M, cE as N, Ic as O, uE as P, lE as Q, dE as R, bc as S, fE as T, pE as U, Zp as V, Fi as W, Yp as X, Qp as Y, Kp as Z, Ur as _, v as $, Ye as aa, Vi as ba, N as ca, pt as da, mE as ea, T as fa, C as ga, y as ha, gh as ia, ye as ja, Xn as ka, Sh as la, Nh as ma, Hh as na, Uh as oa, ve as pa, Y as qa, Ae as ra, De as sa, Be as ta, Au as ua, rs as va, Ft as wa, ku as xa, Ng as ya, WE as za, Ol as Aa, dI as Ba, kl as Ca, Et as Da, Es as Ea, ks as Fa, mo as Ga, DI as Ha, Ls as Ia, nm as Ja, xe as Ka, KI as La, mm as Ma, ym as Na, tw as Oa, nw as Pa, vw as Qa, jt as Ra, yt as Sa, z as Ta, _w as Ua, nt as Va, wn as Wa, Co as Xa, U as Ya, bC as Za, ot as _a, Cn as $a, yy as ab, vy as bb, ub as cb, Bt as db, it as eb, bo as fb, Iy as gb, Eb as hb, by as ib, Ty as jb, _y as kb, Mo as lb, _b as mb, Sy as nb, Tn as ob, xy as pb, Ry as qb, Sb as rb, Ab as sb, Dd as tb, xb as ub, Rb as vb, Ob as wb, Fb as xb, kb as yb, Oy as zb, Ed as Ab, Id as Bb, Fy as Cb, wd as Db, Cd as Eb, ky as Fb, bd as Gb, Td as Hb, Ly as Ib, Hb as Jb, jy as Kb, Vy as Lb, Hy as Mb, Wb as Nb, Zb as Ob, Yb as Pb, Kb as Qb, Jb as Rb, Xb as Sb, eT as Tb, tT as Ub, nT as Vb, rT as Wb, oT as Xb, Gy as Yb, Wy as Zb, gT as _b, _T as $b, ev as ac, _d as bc, tv as cc, nv as dc, rv as ec, NT as fc, ov as gc, AT as hc, xT as ic, RT as jc, LT as kc, jT as lc, BT as mc, VT as nc, HT as oc, $T as pc, GT as qc, WT as rc, qT as sc, ZT as tc, No as uc, na as vc, JT as wc, XT as xc, hv as yc, M2 as zc, S2 as Ac, N2 as Bc, A2 as Cc, x2 as Dc, Ud as Ec, $d as Fc, zd as Gc, __ as Hc, M_ as Ic, R2 as Jc, O2 as Kc, F2 as Lc, he as Mc, st as Nc, N_ as Oc, Er as Pc, sa as Qc, Rv as Rc, Ov as Sc, O_ as Tc, U_ as Uc, Vv as Vc, $_ as Wc, Xd as Xc, z_ as Yc, G_ as Zc, W_ as _c, q_ as $c, Q_ as ad, K_ as bd, J_ as cd, tf as dd, tU as ed, nU as fd, da as gd, pf as hd, qv as id, hM as jd, IM as kd, cD as ld, lD as md, GM as nd, WM as od, qM as pd, v$ as qd, ZM as rd, QM as sd
};