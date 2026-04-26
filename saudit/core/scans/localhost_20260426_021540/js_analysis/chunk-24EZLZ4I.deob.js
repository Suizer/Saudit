import {
  f as i
} from "./chunk-TWZW5B45.js";
var p = i((k, l) => {
  var v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  function c(r) {
    this.message = r
  }
  c.prototype = new Error;
  c.prototype.name = "InvalidCharacterError";

  function f(r) {
    var e = String(r).replace(/=+$/, "");
    if (e.length % 4 == 1) throw new c("'atob' failed: The string to be decoded is not correctly encoded.");
    for (var o = 0, t, n, u = 0, s = ""; n = e.charAt(u++); ~n && (t = o % 4 ? t * 64 + n : n, o++ % 4) ? s += String.fromCharCode(255 & t >> (-2 * o & 6)) : 0) n = v.indexOf(n);
    return s
  }
  l.exports = typeof window < "u" && window.atob && window.atob.bind(window) || f
});
var g = i((C, w) => {
  var h = p();

  function y(r) {
    return decodeURIComponent(h(r).replace(/(.)/g, function(e, o) {
      var t = o.charCodeAt(0).toString(16).toUpperCase();
      return t.length < 2 && (t = "0" + t), "%" + t
    }))
  }
  w.exports = function(r) {
    var e = r.replace(/-/g, "+").replace(/_/g, "/");
    switch (e.length % 4) {
      case 0:
        break;
      case 2:
        e += "==";
        break;
      case 3:
        e += "=";
        break;
      default:
        throw "Illegal base64url string!"
    }
    try {
      return y(e)
    } catch {
      return h(e)
    }
  }
});
var m = i((E, d) => {
  "use strict";
  var I = g();

  function a(r) {
    this.message = r
  }
  a.prototype = new Error;
  a.prototype.name = "InvalidTokenError";
  d.exports = function(r, e) {
    if (typeof r != "string") throw new a("Invalid token specified");
    e = e || {};
    var o = e.header === !0 ? 0 : 1;
    try {
      return JSON.parse(I(r.split(".")[o]))
    } catch (t) {
      throw new a("Invalid token specified: " + t.message)
    }
  };
  d.exports.InvalidTokenError = a
});
export {
  m as a
};