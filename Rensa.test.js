import * as t from "https://deno.land/std/testing/asserts.ts";
import { Rensa } from "./Rensa.js";
import Ed25519 from "https://taisukef.github.io/forge-es/lib/ed25519.js";
import { TAI64N } from "https://code4fukui.github.io/TAI64N-es/TAI64N.js";
import { CBOR } from "https://js.sabae.cc/CBOR.js";

Deno.test("make", async () => {
  const keys = Ed25519.generateKeyPair();

  const trx = new Rensa((signData) => {
    const sig = Ed25519.sign({
        privateKey: keys.privateKey,
        message: signData,
        encoding: "binary"
      });
    return [keys.publicKey, sig];
  });
  const data = { ammount: 300 };
  trx.addAndSign(1, data);
  trx.addAndSign(2, { "echizen": true });
  t.assert(trx.verify());
  //console.log(trx);
  const bin = trx.toCBOR();
  await Deno.writeFile("test.rensa", bin);
});
Deno.test("load from file", async () => {
  const bin = await Deno.readFile("test.rensa");
  const trx = Rensa.fromCBOR(bin);
  t.assert(trx.verify());
});
Deno.test("load from corrupted file", async () => {
  const bin = await Deno.readFile("test.rensa");
  bin[10] = 0; 
  t.assert(Rensa.fromCBOR(bin) == null);
});
/*
Deno.test("playback", async () => {
  const bin = await Deno.readFile("test.rensa");
  const trx = Rensa.fromCBOR(bin);
  let idx = 0;
  trx.playback((err, timestamp, publicKey, msg, obj) => {
    if (err) {
      return false;
    }
    const pkey = hex.fromBin(publicKey);
    console.log(obj);
    return false;
  });
});
*/
Deno.test("make certificate", async () => {
  const keys = Ed25519.generateKeyPair();
  
  const pubkey = keys.publicKey;
  const name = "test";
  const begin = TAI64N.now();
  const [sec, nsec] = TAI64N.decode(begin);
  const end = TAI64N.encode(sec + 31 * 24 * 60 * 60, nsec);
  //console.log("valid not before", TAI64N.toDate(begin));
  //console.log("valid not after", TAI64N.toDate(end));
  const cert = {
    v: 1, // int version = 1
    s: 1, // int serial
    r: 1, //"root", // enum role { 1: root, 2: auth, 3: inter, 4: end} ??
    i: name, // string issuer name
    ik: pubkey, // bin issuer public key
    vb: begin, // tai64n valid not before
    va: end, // tai64n valid not after
    sn: name, // strng subject name
    sk: pubkey, // bin subject public key data
  };
  
  const trx = new Rensa((signData) => {
    const sig = Ed25519.sign({
        privateKey: keys.privateKey,
        message: signData,
        encoding: "binary"
      });
    return [keys.publicKey, sig];
  });
  trx.addCertificate(cert);
  t.assert(trx.verify());
  const bin = trx.toCBOR();
  const trx2 = Rensa.fromCBOR(bin);
  const pubkey2 = CBOR.decode(trx2.data[0][Rensa.PC_PAYLOAD]).ik;
  t.assertEquals(pubkey, pubkey2);
});
