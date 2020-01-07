'use strict';

var $ = require('../util/preconditions');
var CryptoJS = require('./crypto-js');

var AES = function AES() {};

AES.encrypt = function(messagebuf, keybuf) {
  var key = AES.buf2words(keybuf);
  var message = AES.buf2words(messagebuf);
  var enc = CryptoJS.AES.encrypt(message, key);
  var encbuf = AES.words2buf(enc);
  return encbuf;
};

AES.decrypt = function(encbuf, keybuf) {
  var enc = AES.buf2words(encbuf);
  var key = AES.buf2words(keybuf);
  var message = CryptoJS.AES.decrypt(enc, key);
  var messagebuf = AES.words2buf(message);
  return messagebuf;
};

AES.buf2words = function(buf) {
  $.checkArgument(buf);
  $.checkArgument(buf.length % 4 === 0, 'buf length must be a multiple of 4');

  var words = [];

  for (var i = 0; i < buf.length / 4; i++) {
    words.push(buf.readUInt32BE(i * 4));
  }

  return words;
};

AES.words2buf = function(words) {
  var buf = new Buffer(words.length * 4);

  for (var i = 0; i < words.length; i++) {
    buf.writeUInt32BE(words[i], i * 4);
  }

  return buf;
};

module.exports = AES;