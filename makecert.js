import { Rensa } from "./Rensa.js";
import Ed25519 from "https://taisukef.github.io/forge-es/lib/ed25519.js";
import { TAI64N } from "https://code4fukui.github.io/TAI64N-es/TAI64N.js";
import { hex } from "https://code4sabae.github.io/js/hex.js";
import { CBOR } from "https://js.sabae.cc/CBOR.js";
import { RensaIMI } from "https://RensaData.github.io/imi/RensaIMI.js";

const keys = Ed25519.generateKeyPair();

// write secret key
const secretKey = {};
secretKey[RensaIMI.privateKey.url] = keys.privateKey;
secretKey[RensaIMI.publicKey.url] = keys.publicKey;
const secretbin = CBOR.encode(secretKey);
await Deno.writeFile("key.cbor", secretbin);
await Deno.chmod("key.cbor", 0o600);
console.log("make key.cbor", secretbin.length, "byte");

// write public key
const pubkey = keys.publicKey;
const name = "福野泰介 / @taiuskef";
const begin = TAI64N.now();
const [sec, nsec] = TAI64N.decode(begin);
const end = TAI64N.encode(sec + 31 * 24 * 60 * 60, nsec);
console.log("valid not before", TAI64N.toDate(begin));
console.log("valid not after", TAI64N.toDate(end));
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
console.log("verify", trx.verify());
console.log(trx.toString());
const bin = trx.toCBOR();
await Deno.writeFile("cert.rensa", bin);

//
const trx2 = Rensa.fromCBOR(await Deno.readFile("cert.rensa"));
const pubkey2 = CBOR.decode(trx2.data[0][Rensa.PC_PAYLOAD]).ik;
console.log(hex.fromBin(pubkey2));
console.log(hex.fromBin(pubkey));
