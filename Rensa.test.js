import * as t from "https://deno.land/std/testing/asserts.ts";
import { Rensa } from "./Rensa.js";
import Ed25519 from "https://taisukef.github.io/forge-es/lib/ed25519.js";

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
