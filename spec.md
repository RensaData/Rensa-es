```json
[

]
{

}
```


//X ----GLOBAL
//X - ROOT (JP_GOV)
//X  \- INTERMEDIATE (FUKUI_PREF)
//X   \- END (CONNECTFREE)
//X ----ファイル内
//X  \- INTERMEDIATE (FUKUI_PREF)
//X   \- END (JIG.JP)

class Cert {
  v,
  s
  r,
  ROLE_ROOT = 1,
  ROLE_INTER = 2;
  ROLE_END = 3;
  constructor(issuerName, issuerPubkey, validNotBefore, validNoteAfter, subjectName, subjectPubkeey)
}


* v = int version = 1
* s = int serial
* r = enum role {root, auth, inter, end}
* i = string issuer name
* ik = bin issuer public key
* vb = tai64n valid not before
* va = tai64n valid not after
* sn = strng subject name
* sk = bin subject public key data

example)
const pubkey = bin;
const name = "福野泰介 / @taiuskef";
const begin = TAI64N.parse();
const end = TAI64N.parse();
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


//* sa = subject public key algo
