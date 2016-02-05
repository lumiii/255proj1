"use strict";

var rng_counter = 0;
var rng_seed = "";

/* From:
 * http://stackoverflow.com/questions/11889329/word-array-to-string */
function wordToByteArray(wordArray) {
    var byteArray = new Uint8Array(wordArray.sigBytes);
    var word, i, j, k = 0;
    for (i = 0; i < wordArray.words.length; ++i) {
        word = wordArray.words[i];
        for (j = 3; j >= 0; --j) {
            byteArray[k] = ((word >> 8 * j) & 0xFF);
            k++;
        }
    }
    return byteArray;
}

/* From:
 * https://jsperf.com/hex-conversion */
function byteArrayToHex(arr) {
  if (arr.length === "undefined") 
    console.log ("Type error.");

  var s = '';
  for (var i = 0; i < arr.length; i++) {
    s += arr[i].toString(16);
  }
  return s;
}


/*
CryptoJS v3.1.2
code.google.com/p/to-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/to-js/wiki/License
*/
var CryptoJS=CryptoJS||function(v,p){var d={},u=d.lib={},r=function(){},f=u.Base={extend:function(a){r.prototype=this;var b=new r;a&&b.mixIn(a);b.hasOwnProperty("init")||(b.init=function(){b.$super.init.apply(this,arguments)});b.init.prototype=b;b.$super=this;return b},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var b in a)a.hasOwnProperty(b)&&(this[b]=a[b]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
s=u.WordArray=f.extend({init:function(a,b){a=this.words=a||[];this.sigBytes=b!=p?b:4*a.length},toString:function(a){return(a||y).stringify(this)},concat:function(a){var b=this.words,c=a.words,j=this.sigBytes;a=a.sigBytes;this.clamp();if(j%4)for(var n=0;n<a;n++)b[j+n>>>2]|=(c[n>>>2]>>>24-8*(n%4)&255)<<24-8*((j+n)%4);else if(65535<c.length)for(n=0;n<a;n+=4)b[j+n>>>2]=c[n>>>2];else b.push.apply(b,c);this.sigBytes+=a;return this},clamp:function(){var a=this.words,b=this.sigBytes;a[b>>>2]&=4294967295<<
32-8*(b%4);a.length=v.ceil(b/4)},clone:function(){var a=f.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var b=[],c=0;c<a;c+=4)b.push(4294967296*v.random()|0);return new s.init(b,a)}}),x=d.enc={},y=x.Hex={stringify:function(a){var b=a.words;a=a.sigBytes;for(var c=[],j=0;j<a;j++){var n=b[j>>>2]>>>24-8*(j%4)&255;c.push((n>>>4).toString(16));c.push((n&15).toString(16))}return c.join("")},parse:function(a){for(var b=a.length,c=[],j=0;j<b;j+=2)c[j>>>3]|=parseInt(a.substr(j,
2),16)<<24-4*(j%8);return new s.init(c,b/2)}},e=x.Latin1={stringify:function(a){var b=a.words;a=a.sigBytes;for(var c=[],j=0;j<a;j++)c.push(String.fromCharCode(b[j>>>2]>>>24-8*(j%4)&255));return c.join("")},parse:function(a){for(var b=a.length,c=[],j=0;j<b;j++)c[j>>>2]|=(a.charCodeAt(j)&255)<<24-8*(j%4);return new s.init(c,b)}},q=x.Utf8={stringify:function(a){try{return decodeURIComponent(escape(e.stringify(a)))}catch(b){throw Error("Malformed UTF-8 data");}},parse:function(a){return e.parse(unescape(encodeURIComponent(a)))}},
t=u.BufferedBlockAlgorithm=f.extend({reset:function(){this._data=new s.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=q.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var b=this._data,c=b.words,j=b.sigBytes,n=this.blockSize,e=j/(4*n),e=a?v.ceil(e):v.max((e|0)-this._minBufferSize,0);a=e*n;j=v.min(4*a,j);if(a){for(var f=0;f<a;f+=n)this._doProcessBlock(c,f);f=c.splice(0,a);b.sigBytes-=j}return new s.init(f,j)},clone:function(){var a=f.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});u.Hasher=t.extend({cfg:f.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){t.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,c){return(new a.init(c)).finalize(b)}},_createHmacHelper:function(a){return function(b,c){return(new w.HMAC.init(a,
c)).finalize(b)}}});var w=d.algo={};return d}(Math);
(function(v){var p=CryptoJS,d=p.lib,u=d.Base,r=d.WordArray,p=p.x64={};p.Word=u.extend({init:function(f,s){this.high=f;this.low=s}});p.WordArray=u.extend({init:function(f,s){f=this.words=f||[];this.sigBytes=s!=v?s:8*f.length},toX32:function(){for(var f=this.words,s=f.length,d=[],p=0;p<s;p++){var e=f[p];d.push(e.high);d.push(e.low)}return r.create(d,this.sigBytes)},clone:function(){for(var f=u.clone.call(this),d=f.words=this.words.slice(0),p=d.length,r=0;r<p;r++)d[r]=d[r].clone();return f}})})();
(function(v){for(var p=CryptoJS,d=p.lib,u=d.WordArray,r=d.Hasher,f=p.x64.Word,d=p.algo,s=[],x=[],y=[],e=1,q=0,t=0;24>t;t++){s[e+5*q]=(t+1)*(t+2)/2%64;var w=(2*e+3*q)%5,e=q%5,q=w}for(e=0;5>e;e++)for(q=0;5>q;q++)x[e+5*q]=q+5*((2*e+3*q)%5);e=1;for(q=0;24>q;q++){for(var a=w=t=0;7>a;a++){if(e&1){var b=(1<<a)-1;32>b?w^=1<<b:t^=1<<b-32}e=e&128?e<<1^113:e<<1}y[q]=f.create(t,w)}for(var c=[],e=0;25>e;e++)c[e]=f.create();d=d.SHA3=r.extend({cfg:r.cfg.extend({outputLength:512}),_doReset:function(){for(var a=this._state=
[],b=0;25>b;b++)a[b]=new f.init;this.blockSize=(1600-2*this.cfg.outputLength)/32},_doProcessBlock:function(a,b){for(var e=this._state,f=this.blockSize/2,h=0;h<f;h++){var l=a[b+2*h],m=a[b+2*h+1],l=(l<<8|l>>>24)&16711935|(l<<24|l>>>8)&4278255360,m=(m<<8|m>>>24)&16711935|(m<<24|m>>>8)&4278255360,g=e[h];g.high^=m;g.low^=l}for(f=0;24>f;f++){for(h=0;5>h;h++){for(var d=l=0,k=0;5>k;k++)g=e[h+5*k],l^=g.high,d^=g.low;g=c[h];g.high=l;g.low=d}for(h=0;5>h;h++){g=c[(h+4)%5];l=c[(h+1)%5];m=l.high;k=l.low;l=g.high^
(m<<1|k>>>31);d=g.low^(k<<1|m>>>31);for(k=0;5>k;k++)g=e[h+5*k],g.high^=l,g.low^=d}for(m=1;25>m;m++)g=e[m],h=g.high,g=g.low,k=s[m],32>k?(l=h<<k|g>>>32-k,d=g<<k|h>>>32-k):(l=g<<k-32|h>>>64-k,d=h<<k-32|g>>>64-k),g=c[x[m]],g.high=l,g.low=d;g=c[0];h=e[0];g.high=h.high;g.low=h.low;for(h=0;5>h;h++)for(k=0;5>k;k++)m=h+5*k,g=e[m],l=c[m],m=c[(h+1)%5+5*k],d=c[(h+2)%5+5*k],g.high=l.high^~m.high&d.high,g.low=l.low^~m.low&d.low;g=e[0];h=y[f];g.high^=h.high;g.low^=h.low}},_doFinalize:function(){var a=this._data,
b=a.words,c=8*a.sigBytes,e=32*this.blockSize;b[c>>>5]|=1<<24-c%32;b[(v.ceil((c+1)/e)*e>>>5)-1]|=128;a.sigBytes=4*b.length;this._process();for(var a=this._state,b=this.cfg.outputLength/8,c=b/8,e=[],h=0;h<c;h++){var d=a[h],f=d.high,d=d.low,f=(f<<8|f>>>24)&16711935|(f<<24|f>>>8)&4278255360,d=(d<<8|d>>>24)&16711935|(d<<24|d>>>8)&4278255360;e.push(d);e.push(f)}return new u.init(e,b)},clone:function(){for(var a=r.clone.call(this),b=a._state=this._state.slice(0),c=0;25>c;c++)b[c]=b[c].clone();return a}});
p.SHA3=r._createHelper(d);p.HmacSHA3=r._createHmacHelper(d)})(Math);

/*
Invoke the above code as...
    var hash = CryptoJS.SHA3("Message", { outputLength: 512 });
*/

/* Wrapper around the SHA3 function. */
function createSha512() {
  return {
    buffer: "",
    update: function (data) {
      if (typeof(data) == "object")
        this.buffer += "|" + byteArrayToHex(data);
      else
        this.buffer += "|" + data.toString();
    },
    digest: function () {
      //console.log(this.buffer);
      var out = CryptoJS.SHA3(this.buffer, { outputLength: 512 });
      return wordToByteArray(out);
    }
  };
}


/**************************************************
 * Balloon Hashing
 * Henry Corrigan-Gibbs
 * 16 January 2016
 *
 * Please DO NOT use this code in production. THIS IS TOTALLY
 * UNSAFE AND PROBABLY COMPLETELY BROKEN CODE.
 *
 * See https://crypto.stanford.edu/balloon/
 */

/**
 * This module exports a single function that takes the following arguments:
 *    balloon (password, salt, space_cost, time_cost);
 * where
 *    password    = the secret password used in the KDF
 *    salt        = a public salt
 *    space_cost  = the number of bytes to use in computing the KDF
 *                  (the actual number of bytes used might be slightly
 *                  larger or smaller depending on rounding)
 *    time_cost   = the number of iterations to perform
 *
 * The function returns a 64-byte value derived from the password and salt. 
 *
 * The larger the value of space_cost and time_cost are, the longer
 * the algorithm will take to run. You should set space_cost to the 
 * largest amount of space you can tolerate using and you should set
 * time_cost to an integer greater than 5.
 *
 * For example, you can invoke the Balloon hash like this:
 *    var balloon = require ("./balloon.js"); 
 *    var buf = balloon ("password", "salt", 4*1024*1024, 5);
 * This will use 4 MiB of space and 5 iterations of the function.
 */

const BLOCK_SIZE = 512/8;         /* Number of bytes in a SHA-512 hash. */
const DELTA = 10;                 /* A security parameter. */
const MIN_SPACE_COST = 16*1024;   /* Sanity checks. */
const MIN_TIME_COST = 3;

/* A pseudo-random number generator. This is _supposed_ to 
 * give deterministic outputs. */
function rand_four_bytes ()
{
  rng_counter += 1;
  var sha512 = createSha512 ();
  sha512.update (rng_seed);
  sha512.update (rng_counter);
  return sha512.digest().slice(0, 4);
}

/* Return a random integer in [0, max). */
function random_int (max)
{
  const n_bits = max.toString(2).length; 
  if (n_bits >= 32) {
    console.log ("Cannot handle integers this large!");
    return -1;
  }
  while (true) {
    var buf = rand_four_bytes();
    var ret = new Uint32Array(buf)[0];
    ret %= 1 << n_bits;
    if (ret < max) return ret;
  }

  return 0;
}

/* Sanity-check the arguments. */
function balloon_valid_args (password, salt, space_cost, time_cost)
{
  if (typeof password === 'undefined') {
    console.log ("No password passed in");
    return undefined;
  }

  if (typeof salt === 'undefined') {
    console.log ("No salt passed in");
    return undefined;
  }

  if (typeof space_cost === 'undefined') {
    console.log ("No space_cost passed in");
    return undefined;
  }

  if (space_cost < MIN_SPACE_COST) {
    console.log ("space_cost too small (must be >= " + MIN_SPACE_COST + ")");
    return undefined;
  }

  if (typeof time_cost === 'undefined') {
    console.log ("No time_cost passed in");
    return undefined;
  }

  if (time_cost < MIN_TIME_COST) {
    console.log ("time_cost too small (must be >= " + MIN_TIME_COST + ")");
    return undefined;
  }

  return true;
}

/* Return the block located at index idx. */
function block (buf, idx)
{
  return buf.slice (idx * BLOCK_SIZE, (idx * BLOCK_SIZE) + BLOCK_SIZE);
}

/* Run the single-buffer Balloon mixing algorithm. */
function buffer_mix (buf, round)
{
  const r = String (round);
  const n_blocks = buf.byteLength / BLOCK_SIZE; 
  for (var i = 0; i < n_blocks; i++) {
    if (i % 128 == 0)
      console.log ("\tHashing block " + i + " of " + n_blocks);

    var sha512 = createSha512 ();
    var prev_idx = (i > 0) ? (i - 1) : (n_blocks - 1);
    sha512.update (r);
    sha512.update (String(i));
    sha512.update (block (buf, i));
    sha512.update (block (buf, prev_idx));

    for (var j = 0; j < DELTA; j++) {
      var rand_idx = random_int (n_blocks);
      sha512.update (block (buf, rand_idx));
    }
 
    var tmp = sha512.digest();
    buf.set(tmp, i*BLOCK_SIZE);
  }
}

/* Fill the buffer with pseudo-random bytes derived
 * from the password, salt, and public parameters. */
function buffer_init (buf, params) 
{
  const n_blocks = buf.byteLength / BLOCK_SIZE; 
  for (var i = 0; i < n_blocks; i++) {
    var sha512 = createSha512 ();
    sha512.update (params + "|" + String (i));
    if (i > 0) 
      sha512.update (block(buf, i-1));
    var tmp = sha512.digest();
    buf.set (tmp, i*BLOCK_SIZE);
  }
}

/* The main routine for the single-buffer Balloon hash. */
function Balloon (password, salt, space_cost, time_cost)
{
  console.log ("WARNING: This code is NOT safe for production use.");
  console.log ("");
  console.log ("=== Balloon Hashing Invoked ===");
  console.log ("password  : [hidden for privacy]");
  console.log ("salt      : " + salt);
  console.log ("time_cost : " + time_cost);
  console.log ("space_cost: " + space_cost);
  if (!balloon_valid_args (password, salt, space_cost, time_cost))
    return undefined;

  const n_blocks = Math.round (space_cost/ BLOCK_SIZE); 
  const buf_len = BLOCK_SIZE * n_blocks;
  var buf = new Uint8Array (buf_len);

  const s_space_cost = String (space_cost);
  const s_time_cost = String (time_cost);

  var sha512 = createSha512 ();
  sha512.update (password);
  sha512.update (salt);
  sha512.update (s_space_cost);
  sha512.update (s_time_cost);

  var params = byteArrayToHex(sha512.digest());
  rng_seed = params;

  console.log ("Initializing..."); 
  buffer_init (buf, params);
  console.log ("Starting to mix...");
  for (var t = 0; t < time_cost; t++) {
    console.log ("Mixing round " + (t + 1) + " of " + time_cost);
    buffer_mix (buf, t);
  }

  return block (buf, n_blocks - 1); 
};

onmessage = function(e) {
  var msgtype = e.data.type;
  var out = Balloon (e.data.password, e.data.salt, e.data.space_cost, e.data.time_cost);
  postMessage({hash : out, status: "OK"});
}

