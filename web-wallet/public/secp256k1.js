
function rotr(a, b){ return (a >>> b) | (a << (32 - b)); }
const K256 = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

function sha256(msg) {
  const l = msg.length;
  const bitLen = l * 8;
  const withOne = l + 1;
  let padLen = (withOne % 64 <= 56) ? (56 - (withOne % 64)) : (56 + 64 - (withOne % 64));
  const total = withOne + padLen + 8;
  const b = new Uint8Array(total);
  b.set(msg, 0);
  b[l] = 0x80;
  const dv = new DataView(b.buffer);
  dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000), false);
  dv.setUint32(total - 4, bitLen >>> 0, false);

  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Uint32Array(64);

  for (let i=0; i<total; i+=64) {
    for (let t=0; t<16; t++) w[t] = dv.getUint32(i + t*4, false);
    for (let t=16; t<64; t++) {
      const s0 = rotr(w[t-15],7) ^ rotr(w[t-15],18) ^ (w[t-15]>>>3);
      const s1 = rotr(w[t-2],17) ^ rotr(w[t-2],19) ^ (w[t-2]>>>10);
      w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
    }
    let a=h0,bh=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let t=0; t<64; t++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & bh) ^ (a & c) ^ (bh & c);
      const temp2 = (S0 + maj) >>> 0;

      h=g; g=f; f=e; e=(d + temp1) >>> 0;
      d=c; c=bh; bh=a; a=(temp1 + temp2) >>> 0;
    }
    h0=(h0+a)>>>0; h1=(h1+bh)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }

  const out = new Uint8Array(32);
  const outv = new DataView(out.buffer);
  outv.setUint32(0,h0,false); outv.setUint32(4,h1,false); outv.setUint32(8,h2,false); outv.setUint32(12,h3,false);
  outv.setUint32(16,h4,false); outv.setUint32(20,h5,false); outv.setUint32(24,h6,false); outv.setUint32(28,h7,false);
  return out;
}

function sha256d(u8){ return sha256(sha256(u8)); }

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = (() => {
  const m = new Map();
  for (let i=0;i<B58.length;i++) m.set(B58[i], i);
  return m;
})();

function base58Decode(str){
  str = String(str||"").trim();
  if (!str) throw new Error("empty base58");
  let bytes = [0];
  for (const ch of str) {
    const val = B58_MAP.get(ch);
    if (val === undefined) throw new Error("invalid base58 char");
    let carry = val;
    for (let j=0;j<bytes.length;j++){
      const x = bytes[j]*58 + carry;
      bytes[j] = x & 0xff;
      carry = x >> 8;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  let leading = 0;
  for (let i=0;i<str.length && str[i]==="1"; i++) leading++;
  const out = new Uint8Array(leading + bytes.length);
  for (let i=0;i<bytes.length;i++) out[out.length-1-i] = bytes[i];
  return out;
}

function decodeWifToPriv32(wif){
  const raw = base58Decode(wif);
  if (raw.length < 4 + 1 + 32) throw new Error("WIF too short");

  const payload = raw.slice(0, raw.length - 4);
  const checksum = raw.slice(raw.length - 4);

  try{
    const ck = sha256d(payload).slice(0,4);
    let ok = true;
    for (let i=0;i<4;i++) if (ck[i] !== checksum[i]) ok = false;
  }catch(_e){
  }

  let pl = payload;
  if (pl.length >= 1+32+1 && pl[pl.length-1] === 0x01) pl = pl.slice(0, pl.length-1);

  if (pl.length < 32) throw new Error("WIF payload too short");
  return pl.slice(pl.length - 32);
}




const _0n = 0n;
const _1n = 1n;
const CURVE = {
  P: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
  n: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
  Gx: BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
  Gy: BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
};

function mod(a, m){ const r = a % m; return r >= 0n ? r : r + m; }
function pow2(x, n){ let r=x; for (let i=0;i<n;i++) r = mod(r*r, CURVE.P); return r; }
function inv(a, m){ 
  let n = m - 2n;
  let x = mod(a, m), r = 1n;
  while (n > 0n) {
    if (n & 1n) r = mod(r * x, m);
    x = mod(x * x, m);
    n >>= 1n;
  }
  return r;
}

function bytesToBigInt(b){
  let n = 0n;
  for (const x of b) n = (n<<8n) + BigInt(x);
  return n;
}
function bigIntToBytes(n, len){
  const b = new Uint8Array(len);
  for (let i=len-1;i>=0;i--){
    b[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return b;
}

class Point {
  constructor(x, y){ this.x=x; this.y=y; }
  static BASE(){ return new Point(CURVE.Gx, CURVE.Gy); }
  static INF(){ return new Point(null, null); }
  isInf(){ return this.x===null || this.y===null; }

  double(){
    if (this.isInf()) return this;
    const {x,y} = this;
    const m = mod((3n*x*x) * inv(2n*y, CURVE.P), CURVE.P);
    const nx = mod(m*m - 2n*x, CURVE.P);
    const ny = mod(m*(x - nx) - y, CURVE.P);
    return new Point(nx, ny);
  }

  add(other){
    if (this.isInf()) return other;
    if (other.isInf()) return this;
    const {x:x1,y:y1} = this;
    const {x:x2,y:y2} = other;
    if (x1 === x2) {
      if (y1 !== y2) return Point.INF();
      return this.double();
    }
    const m = mod((y2 - y1) * inv((x2 - x1), CURVE.P), CURVE.P);
    const nx = mod(m*m - x1 - x2, CURVE.P);
    const ny = mod(m*(x1 - nx) - y1, CURVE.P);
    return new Point(nx, ny);
  }

  mul(s){
    let n = mod(s, CURVE.n);
    if (n === 0n || this.isInf()) return Point.INF();
    let p = Point.INF();
    let d = this;
    while (n > 0n) {
      if (n & 1n) p = p.add(d);
      d = d.double();
      n >>= 1n;
    }
    return p;
  }

  toRawBytes(compressed=true){
    if (this.isInf()) throw new Error("inf");
    const x = bigIntToBytes(this.x, 32);
    const y = bigIntToBytes(this.y, 32);
    if (!compressed){
      const out = new Uint8Array(65);
      out[0]=4; out.set(x,1); out.set(y,33);
      return out;
    }
    const out = new Uint8Array(33);
    out[0] = (this.y & 1n) ? 3 : 2;
    out.set(x, 1);
    return out;
  }
}

function getPublicKey(priv32, compressed=true){
  const d = bytesToBigInt(priv32);
  if (d <= 0n || d >= CURVE.n) throw new Error("bad privkey");
  return Point.BASE().mul(d).toRawBytes(compressed);
}

function deterministicK(msg32, priv32){
  const key = new Uint8Array(64);
  key.set(priv32, 0);
  key.set(msg32, 32);

  for (let ctr=0; ctr<256; ctr++){
    const data = new Uint8Array(65);
    data.set(key, 0);
    data[64] = ctr;

    const k = bytesToBigInt(sha256(data));
    const kk = mod(k, CURVE.n);
    if (kk > 0n) return kk;
  }
  throw new Error("k generation failed");
}

function derIntBytes(b){
  let i = 0;
  while (i < b.length-1 && b[i] === 0) i++;
  let v = b.slice(i);
  if (v[0] & 0x80) {
    const vv = new Uint8Array(v.length+1);
    vv[0]=0;
    vv.set(v,1);
    v = vv;
  }
  return v;
}

function encodeDerSig(r, s){
  const rb = derIntBytes(bigIntToBytes(r, 32));
  const sb = derIntBytes(bigIntToBytes(s, 32));
  const len = 2 + rb.length + 2 + sb.length;
  const out = new Uint8Array(2 + len);
  out[0]=0x30; out[1]=len;
  out[2]=0x02; out[3]=rb.length; out.set(rb,4);
  const p = 4 + rb.length;
  out[p]=0x02; out[p+1]=sb.length; out.set(sb, p+2);
  return out;
}

function signDer(msg32, priv32){
  if (!(msg32 instanceof Uint8Array) || msg32.length !== 32) throw new Error("msg32 must be 32 bytes");
  const d = bytesToBigInt(priv32);
  if (d <= 0n || d >= CURVE.n) throw new Error("bad privkey");

  const z = bytesToBigInt(msg32);
  let k = deterministicK(msg32, priv32);
  const R = Point.BASE().mul(k);
  const r = mod(R.x, CURVE.n);
  if (r === 0n) throw new Error("r=0");

  const kinv = inv(k, CURVE.n);
  let s = mod(kinv * (z + r*d), CURVE.n);
  if (s === 0n) throw new Error("s=0");

  const halfN = CURVE.n >> 1n;
  if (s > halfN) s = CURVE.n - s;

  return encodeDerSig(r, s);
}

window.secp = {
  decodeWifToPriv32,
  getPublicKey,
  signDer,
  _sha256: sha256,    
  _sha256d: sha256d
};


