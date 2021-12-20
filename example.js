import { Rensa } from "./Rensa.js";
import Ed25519 from "https://taisukef.github.io/forge-es/lib/ed25519.js";
import { hex } from "https://code4sabae.github.io/js/hex.js";

const keys = Ed25519.generateKeyPair();

const trx = new Rensa((signData) => {
  const sig = Ed25519.sign({
      privateKey: keys.privateKey,
      message: signData,
      encoding: "binary"
    });
  return [keys.publicKey, sig];
});
trx.addAndSign(Rensa.KIND_ROOT, { amount: 300 });
trx.addAndSign(Rensa.KIND_OVERWRITE, { echizen: true, amount: 301 });
trx.addAndSign(Rensa.KIND_OVERWRITE, { echizen: null });
console.log("verify:", trx.verify());
//console.log(trx);
const bin = trx.toCBOR();
await Deno.writeFile("test.rensa", bin);

console.log(trx.toString());
trx.playback((err, timestamp, publicKey, msg, obj) => {
  if (err) {
    return false;
  }
  const pkey = hex.fromBin(publicKey);
  console.log({ timestamp, pkey, msg, obj });
  return false;
});
