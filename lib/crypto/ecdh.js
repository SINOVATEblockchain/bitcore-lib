'use strict';

var PublicKey  = require('../publickey');
var Hash = require('./hash');
var Random = require('./random');
var $ = require('../util/preconditions');
var CryptoJS = require('./crypto-js');

var ECDH = function ECDH(opts) {
  if (!(this instanceof ECDH)) {
    return new ECDH();
  }
  this.opts = opts || {};
};

ECDH.prototype.privateKey = function(privateKey) {
  $.checkArgument(privateKey, 'no private key provided');

  this._privateKey = privateKey || null;

  return this;
};

ECDH.prototype.publicKey = function(publicKey) {
  $.checkArgument(publicKey, 'no public key provided');

  this._publicKey = publicKey || null;

  return this;
};

var cachedProperty = function(name, getter) {
  var cachedName = '_' + name;
  Object.defineProperty(ECDH.prototype, name, {
    configurable: false,
    enumerable: true,
    get: function() {
      var value = this[cachedName];
      if (!value) {
        value = this[cachedName] = getter.apply(this);
      }
      return value;
    }
  });
};

cachedProperty('Rbuf', function() {
  return this._privateKey.publicKey.toDER(true);
});

cachedProperty('BN', function() {
  var r = this._privateKey.bn;
  var KB = this._publicKey.point;
  var P = KB.mul(r);
  var S = P.getX();
  return S;
});

cachedProperty('secret', function() {
  var r = this._privateKey.bn;
  var KB = this._publicKey.point;
  var P = KB.mul(r);
  var S = P.getX();
  //var Sbuf = S.toBuffer({size: 32});
  //return Hash.sha512(Sbuf);
  return CryptoJS.enc.Base64.parse(S.toString());
});

cachedProperty('key', function() {
  var key = this.secret;
  key.sigBytes = 32;
  return key;
});

cachedProperty('iv', function() {
  return CryptoJS.lib.WordArray.create(this.secret.words.slice(8), 16);
});

cachedProperty('salt', function() {
  return CryptoJS.lib.WordArray.create(this.secret.words.slice(12), 8);
});

ECDH.prototype.encrypt = function(message, ivbuf) {
  var iteration = Random.getRandomBuffer(16);
  CryptoJS.algo.EvpKDF.cfg.keySize=12;
  CryptoJS.algo.EvpKDF.cfg.iterations=iteration.readUInt16BE();
  var key = CryptoJS.algo.EvpKDF.create({ hasher: CryptoJS.algo.SHA512}).compute(this.key.toString(CryptoJS.enc.Hex), this.salt);
  var iv = CryptoJS.lib.WordArray.create(key.words.slice(8), 16);
  key.sigBytes = 32;
  
  var encrypted = CryptoJS.AES.encrypt(message, key, {iv:iv});
  var c = new Buffer(encrypted.toString(), 'base64');
  var d = Hash.sha256hmac(c, new Buffer(this.key.toString(CryptoJS.enc.Hex)).slice(0, 32));

  if(this.opts.shortTag) d = d.slice(0,4);
  if(this.opts.noKey) {
    var encbuf = Buffer.concat([c, d, iteration]);
  } else {
    var encbuf = Buffer.concat([this.Rbuf, c, d, iteration]);
  }

  return encbuf;
};

ECDH.prototype.decrypt = function(encbuf) {
  $.checkArgument(encbuf);
  var offset = 0;
  var tagLength = 32;
  if(this.opts.shortTag) {
    tagLength = 4;
  }
  if(!this.opts.noKey) {
    var pub;
    switch(encbuf[0]) {
    case 4:
      pub = encbuf.slice(0, 65);
      break;
    case 3:
    case 2:
      pub = encbuf.slice(0, 33);
      break;
    default:
      throw new Error('Invalid type: ' + encbuf[0]);
    }
    this._publicKey = PublicKey.fromDER(pub);
    offset += pub.length;
  }
  var c = encbuf.slice(offset, encbuf.length - tagLength - 16);
  var d = encbuf.slice(offset + c.length, encbuf.length - 16);
  var iteration = encbuf.slice(offset + c.length + d.length, encbuf.length);

  var d2 = Hash.sha256hmac(c, new Buffer(this.key.toString(CryptoJS.enc.Hex)).slice(0, 32));
  if(this.opts.shortTag) d2 = d2.slice(0,4);

  var equal = true;
  for (var i = 0; i < d.length; i++) {
    equal &= (d[i] === d2[i]);
  }
  if (!equal) {
    throw new Error('Invalid checksum');
  }

  CryptoJS.algo.EvpKDF.cfg.keySize=12;
  CryptoJS.algo.EvpKDF.cfg.iterations=iteration.readUInt16BE();
  var key = CryptoJS.algo.EvpKDF.create({ hasher: CryptoJS.algo.SHA512}).compute(this.key.toString(CryptoJS.enc.Hex), this.salt);
  var iv = CryptoJS.lib.WordArray.create(key.words.slice(8), 16);
  key.sigBytes = 32;
  var reb64 = CryptoJS.enc.Hex.parse(c.toString('hex'));
  var bytesecret = reb64.toString(CryptoJS.enc.Base64);
  var bytes = CryptoJS.AES.decrypt(bytesecret, key, {iv:iv});

  return bytes.toString(CryptoJS.enc.Utf8);
};

module.exports = ECDH;