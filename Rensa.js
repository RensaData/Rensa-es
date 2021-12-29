import { CBOR } from "https://js.sabae.cc/CBOR.js";
import { blake } from "https://taisukef.github.io/blakejs_es/blake2s.js";
import Ed25519 from "https://taisukef.github.io/forge-es/lib/ed25519.js";
import { TAI64N } from "https://code4fukui.github.io/TAI64N-es/TAI64N.js";
import { hex } from "https://code4sabae.github.io/js/hex.js";

class Rensa {
  constructor(sF) {
    this.data = [];
    this.signFunc = sF;
  }

  static P_KIND = 0;
  static P_TAI64N = 1;
  static P_PUBKEY = 2;
  static P_SIGNATURE = 3;
  static P_PAYLOAD = 4;

  static KIND_ROOT = 0x01;
  static KIND_OVERWRITE = 0x02;

  static KINDS = {
    0x01: "KIND_ROOT",
    0x02: "KIND_OVERWRITE",
  };

  static fromCBOR(input) {
    const trx = new Rensa();
    trx.data = CBOR.decode(input);
    if (!trx.verify()) {
      return null;
    }
    return trx;
  }

  verify() {
    for (let i = 0; i < this.data.length; i++) {
      const element = this.data[i];
      //
      const publicKey = element[Rensa.P_PUBKEY];
      const signature = element[Rensa.P_SIGNATURE];

      //verify datetime
      if (i > 0) {
        if (TAI64N.lt(element[Rensa.P_TAI64N], this.data[i - 1][Rensa.P_TAI64N])) {
          return false;
        }
      }

      //TODO: verify TYPE?
  
      const message = this._innerSignDigest(
        element[Rensa.P_KIND],
        element[Rensa.P_TAI64N],
        i > 0 ? this.data[i - 1][Rensa.P_SIGNATURE] : null, //last Signature
        element[Rensa.P_PAYLOAD]
      );
  
      const result = Ed25519.verify({
        signature,
        message,
        publicKey,
        encoding: "binary"
      });
      if (!result) {
        return false;
      }
    }
    return true;
  }

  // callback(err, timestmap, publicKey, update_payload, document_at_point) break if ret true
  playback(cb) {
    const obj = {};
    for (let i = 0; i < this.data.length; i++) {
      const element = this.data[i];
      //
      const publicKey = element[Rensa.P_PUBKEY];
      const signature = element[Rensa.P_SIGNATURE];

      //verify datetime
      if (i > 0) {
        if (TAI64N.lt(element[Rensa.P_TAI64N], this.data[i - 1][Rensa.P_TAI64N])) {
          if (cb) {
            cb(true);
          }
          return null;
        }
      }

      //TODO: verify TYPE?
      const payload = element[Rensa.P_PAYLOAD];
      const tai64n = element[Rensa.P_TAI64N];
      const message = this._innerSignDigest(
        element[Rensa.P_KIND],
        tai64n,
        i > 0 ? this.data[i - 1][Rensa.P_SIGNATURE] : null, //last Signature
        payload
      );
  
      const result = Ed25519.verify({
        signature,
        message,
        publicKey,
        encoding: "binary"
      });
      if (!result) {
        if (cb) {
          cb(true);
        }
        return null;
      }

      const pl = CBOR.decode(payload);
      for (const name in pl) {
        if (pl[name] == null) {
          delete obj[name];
        } else {
          obj[name] = pl[name];
        }
      }
      if (cb && cb(false, TAI64N.toDate(tai64n), publicKey, pl, obj)) {
        break;
      }
    }
    return obj;
  }

  _innerSignDigest(k, tai64, lastSig, encData) {
    //first we create the hash
    const enc = (s) => new TextEncoder().encode(s);
    const ctx = blake.blake2sInit(32, enc("Rensa OFFICIAL CLIENT"));
    blake.blake2sUpdate(ctx, enc(k));
    blake.blake2sUpdate(ctx, tai64);
    if (!lastSig) {
      blake.blake2sUpdate(ctx, new Uint8Array(1)); // if no last signature, update with null byte
    } else {
      blake.blake2sUpdate(ctx, lastSig);
    }
    blake.blake2sUpdate(ctx, encData);
    return blake.blake2sFinal(ctx);
  }

  addAndSign(kind, data) {
    const encData = CBOR.encode(data);
    const tai64nNow = TAI64N.now();
    //validationする？
    //validate: datetime must be >= than last member
    let lastSig = null;
    if (this.data.length) {
      const last = this.data[this.data.length - 1];
      lastSig = last[Rensa.P_SIGNATURE];
      if (TAI64N.lt(tai64nNow, last[Rensa.P_TAI64N])) {
        throw new Error("The world is over as we know it. Panic and light everything on fire");
      }
    }

    const signatureDigest = this._innerSignDigest(kind, tai64nNow, lastSig, encData);
    const [pubKey, signature] = this.signFunc(signatureDigest);

    this.data.push([
      kind,
      tai64nNow, 
      pubKey,
      signature,
      encData,
    ]);
  }

  toString() {
    const ss = [];
    ss.push(`[`);
    for (const d of this.data) {
      const dd = [
        Rensa.KINDS[d[Rensa.P_KIND]],
        TAI64N.stringify(d[Rensa.P_TAI64N]),
        hex.fromBin(d[Rensa.P_PUBKEY]),
        hex.fromBin(d[Rensa.P_SIGNATURE]),
        JSON.stringify(CBOR.decode(d[Rensa.P_PAYLOAD]))
      ];
      ss.push(`  [${dd.join(", ")}]`);
    }
    ss.push(`]`);
    return ss.join("\n");
  }
  toCBOR() {
    return CBOR.encode(this.data);
  }
}

export { Rensa };
