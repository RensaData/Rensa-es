import { Rensa } from "./Rensa.js";
import Ed25519 from "https://taisukef.github.io/forge-es/lib/ed25519.js";

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
console.log("verify:", trx.verify());
//console.log(trx);
const bin = trx.toCBOR();
await Deno.writeFile("test.rensa", bin);

console.log(trx.toString());
