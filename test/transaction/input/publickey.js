'use strict';

var should = require('chai').should();
var bitcore = require('../../..');
var Transaction = bitcore.Transaction;
var PrivateKey = bitcore.PrivateKey;

describe('PublicKeyInput', function() {

  var utxo = {
    txid: '597b7da8048da900223beab09d914914b4e6de2775be4b575da80a2f9bd17686',
    vout: 0,
    address: 'SQsrMpzRq5yhj6Gbjw7gWAbUBS3ztn68z1',
    scriptPubKey: '76a914274f47ce32ce0a16493720bb07e110e7fbc4dd2488ac',
    amount: 651.51137473,
    confirmations: 104,
    spendable: true
  };
  var privateKey = PrivateKey.fromWIF('VMg5hP9b6HTbQ8D4PeukRYpwHi6gs7LMkzTr7QGtUxtvHHhUQN9S');
  var address = privateKey.toAddress();
  utxo.address.should.equal(address.toString());

  var destKey = new PrivateKey();

  it('will correctly sign a publickey out transaction', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    tx.sign(privateKey);
    tx.inputs[0].script.toBuffer().length.should.be.above(0);
  });

  it('count can count missing signatures', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    input.isFullySigned().should.equal(false);
    tx.sign(privateKey);
    input.isFullySigned().should.equal(true);
  });

  it('it\'s size can be estimated', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    input._estimateSize().should.equal(73);
  });

  it('it\'s signature can be removed', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    tx.sign(privateKey);
    input.isFullySigned().should.equal(true);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });

  it('returns an empty array if private key mismatches', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    var signatures = input.getSignatures(tx, new PrivateKey(), 0);
    signatures.length.should.equal(0);
  });

});
