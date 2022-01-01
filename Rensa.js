import { CBOR } from "https://js.sabae.cc/CBOR.js";
import { blake } from "https://taisukef.github.io/blakejs_es/blake2s.js";
import Ed25519 from "https://taisukef.github.io/forge-es/lib/ed25519.js";
import { TAI64N } from "https://code4fukui.github.io/TAI64N-es/TAI64N.js";
import { hex } from "https://code4sabae.github.io/js/hex.js";

class Rensa {
  constructor(sF) {
    this.data = [];
    //this.cstore = new CertStore();
    this.signFunc = sF;
  }

  static P_KIND = 0;
  
  static PD_TAI64N = 1;
  static PD_PUBKEY = 2;
  static PD_SIGNATURE = 3;
  static PD_PAYLOAD = 4;

  static PC_PUBKEY = 1;
  static PC_SIGNATURE = 2;
  static PC_PAYLOAD = 3;

  // data
  static KIND_MASK_DATA = 0x0f;
  static KIND_ROOT = 0x01;
  static KIND_OVERWRITE = 0x02;

  //certificates
  static KIND_CERTIFICATE = 0x10;

  static KINDS = {
    0x01: "KIND_ROOT",
    0x02: "KIND_OVERWRITE",
    //
    0x10: "KIND_OVERWRITE",
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
      const kind = element[Rensa.P_KIND];
      if ((kind & Rensa.KIND_MASK_DATA) == kind) {
        const publicKey = element[Rensa.PD_PUBKEY];
        const signature = element[Rensa.PD_SIGNATURE];

        //verify datetime
        if (i > 0) {
          if (TAI64N.lt(element[Rensa.PD_TAI64N], this.data[i - 1][Rensa.PD_TAI64N])) {
            return false;
          }
        }

        const message = this._innerSignDigest(
          kind,
          element[Rensa.PD_TAI64N],
          i > 0 ? this.data[i - 1][Rensa.PD_SIGNATURE] : null, //last Signature
          element[Rensa.PD_PAYLOAD]
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
      } else { // kind certificate
        const publicKey = element[Rensa.PC_PUBKEY];
        const signature = element[Rensa.PC_SIGNATURE];

        const message = this._innerSignDigest(
          kind,
          null,
          null,
          element[Rensa.PC_PAYLOAD]
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
    }
    return true;
  }

  // callback(err, timestmap, publicKey, update_payload, document_at_point) break if ret true
  playback(cb) {
    const obj = {};
    for (let i = 0; i < this.data.length; i++) {
      const element = this.data[i];
      //
      const publicKey = element[Rensa.PD_PUBKEY];
      const signature = element[Rensa.PD_SIGNATURE];

      //verify datetime
      if (i > 0) {
        if (TAI64N.lt(element[Rensa.PD_TAI64N], this.data[i - 1][Rensa.PD_TAI64N])) {
          if (cb) {
            cb(true);
          }
          return null;
        }
      }

      //TODO: verify TYPE?
      const payload = element[Rensa.PD_PAYLOAD];
      const tai64n = element[Rensa.PD_TAI64N];
      const message = this._innerSignDigest(
        element[Rensa.P_KIND],
        tai64n,
        i > 0 ? this.data[i - 1][Rensa.PD_SIGNATURE] : null, //last Signature
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
    if (tai64) {
      blake.blake2sUpdate(ctx, tai64);
    }
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
      lastSig = last[Rensa.PD_SIGNATURE];
      if (TAI64N.lt(tai64nNow, last[Rensa.PD_TAI64N])) {
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

  addCertificate(issued_payload) {
    const kind = Rensa.KIND_CERTIFICATE;

    const issued_payload_cbor = CBOR.encode(issued_payload);
    const signatureDigest = this._innerSignDigest(kind, null, null, issued_payload_cbor);
    const [issuer_pubkey, issued_payload_sig] = this.signFunc(signatureDigest);

    //1 does cbor payload match sig from pubkey
    //2 open payload and check that ik matches PD_PUBKEY
    //if (!Bin.eqauls(issued_payload.ik, issuer_pubkey)) {
    if (hex.fromBin(issued_payload.ik) != hex.fromBin(issuer_pubkey)) {
      throw new Error("doesn't match pubkey");
    }

    //static PD_PUBKEY = 1;
    //static PC_SIGNATURE = 2;
    //static PC_PAYLOAD = 3;
    this.data.push([
      kind,
      issuer_pubkey,
      issued_payload_sig,
      issued_payload_cbor,
    ]);
  }

  toString() {
    const ss = [];
    ss.push(`[`);
    for (const d of this.data) {
      const kind = d[Rensa.P_KIND];
      let dd = null;
      if ((kind & Rensa.KIND_MASK_DATA) == kind) {
          dd = [
          Rensa.KINDS[kind],
          TAI64N.stringify(d[Rensa.PD_TAI64N]),
          hex.fromBin(d[Rensa.PD_PUBKEY]),
          hex.fromBin(d[Rensa.PD_SIGNATURE]),
          JSON.stringify(CBOR.decode(d[Rensa.PD_PAYLOAD]))
        ];
      } else {
        dd = [
          Rensa.KINDS[kind],
          hex.fromBin(d[Rensa.PC_PUBKEY]),
          hex.fromBin(d[Rensa.PC_SIGNATURE]),
          JSON.stringify(CBOR.decode(d[Rensa.PC_PAYLOAD]))
        ];
      }
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
