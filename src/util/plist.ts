/**
 * macOS のプロパティリスト（plist）を、外部コマンド（plutil）を使わずに読む。
 * XML 形式とバイナリ形式（bplist00）の両方に対応する。管理設定（構成プロファイル）の読み取り用。
 *
 * - 書き込みはしない
 * - オブジェクトはプロトタイプなしで組み立てる（"__proto__" キーでも安全）
 * - 入れ子の深さと参照の循環に上限を設け、壊れた・悪意のある入力でも止まらない
 */

export type PlistResult = { ok: true; value: unknown } | { ok: false; reason: string };

const MAX_DEPTH = 256;

export function parsePlist(bytes: Buffer): PlistResult {
  try {
    if (bytes.subarray(0, 8).toString('latin1') === 'bplist00') return { ok: true, value: parseBinary(bytes) };
    return { ok: true, value: parseXml(bytes.toString('utf8')) };
  } catch (err) {
    // 例外の内容は入力の一部を含みうるため、種類だけを返す
    return { ok: false, reason: err instanceof PlistError ? err.message : 'malformed plist' };
  }
}

class PlistError extends Error {}

function obj(): Record<string, unknown> {
  return Object.create(null) as Record<string, unknown>;
}

function setKey(target: Record<string, unknown>, key: string, value: unknown) {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

// ---- バイナリ形式 -------------------------------------------------------------

function parseBinary(buf: Buffer): unknown {
  if (buf.length < 8 + 32) throw new PlistError('truncated binary plist');
  const trailer = buf.subarray(buf.length - 32);
  const offsetSize = trailer[6]!;
  const refSize = trailer[7]!;
  const numObjects = Number(trailer.readBigUInt64BE(8));
  const topObject = Number(trailer.readBigUInt64BE(16));
  const tableOffset = Number(trailer.readBigUInt64BE(24));
  if (offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8) throw new PlistError('invalid binary plist trailer');
  if (numObjects <= 0 || topObject >= numObjects || tableOffset + numObjects * offsetSize > buf.length - 32) {
    throw new PlistError('invalid binary plist offsets');
  }

  const readUInt = (pos: number, size: number): number => {
    if (pos + size > buf.length) throw new PlistError('out of range');
    let n = 0;
    for (let i = 0; i < size; i++) n = n * 256 + buf[pos + i]!;
    return n;
  };
  const offsetOf = (ref: number): number => {
    if (ref >= numObjects) throw new PlistError('invalid object reference');
    return readUInt(tableOffset + ref * offsetSize, offsetSize);
  };

  const readObject = (ref: number, depth: number, path: Set<number>): unknown => {
    if (depth > MAX_DEPTH) throw new PlistError('nesting too deep');
    if (path.has(ref)) throw new PlistError('reference cycle');
    const pos = offsetOf(ref);
    if (pos >= buf.length - 32) throw new PlistError('out of range');
    const marker = buf[pos]!;
    const type = marker >> 4;
    const info = marker & 0x0f;

    // 長さ（info が 0xF のときは続く整数オブジェクトで表す）
    const lengthAt = (): { len: number; start: number } => {
      if (info !== 0x0f) return { len: info, start: pos + 1 };
      const intMarker = buf[pos + 1]!;
      if (intMarker >> 4 !== 0x1) throw new PlistError('invalid length');
      const size = 1 << (intMarker & 0x0f);
      return { len: readUInt(pos + 2, size), start: pos + 2 + size };
    };

    switch (type) {
      case 0x0:
        if (marker === 0x00) return null;
        if (marker === 0x08) return false;
        if (marker === 0x09) return true;
        throw new PlistError('unsupported marker');
      case 0x1: {
        const size = 1 << info;
        if (size === 8) return Number(buf.readBigInt64BE(pos + 1));
        if (size > 8) throw new PlistError('integer too large');
        return readUInt(pos + 1, size);
      }
      case 0x2: {
        const size = 1 << info;
        if (size === 4) return buf.readFloatBE(pos + 1);
        if (size === 8) return buf.readDoubleBE(pos + 1);
        throw new PlistError('invalid real');
      }
      case 0x3:
        return new Date(978307200000 + buf.readDoubleBE(pos + 1) * 1000).toISOString();
      case 0x4: {
        const { len, start } = lengthAt();
        if (start + len > buf.length) throw new PlistError('out of range');
        return buf.subarray(start, start + len).toString('base64');
      }
      case 0x5: {
        const { len, start } = lengthAt();
        if (start + len > buf.length) throw new PlistError('out of range');
        return buf.subarray(start, start + len).toString('latin1');
      }
      case 0x6: {
        const { len, start } = lengthAt();
        if (start + len * 2 > buf.length) throw new PlistError('out of range');
        const be = buf.subarray(start, start + len * 2);
        const le = Buffer.alloc(be.length);
        for (let i = 0; i < be.length; i += 2) {
          le[i] = be[i + 1]!;
          le[i + 1] = be[i]!;
        }
        return le.toString('utf16le');
      }
      case 0xa: {
        const { len, start } = lengthAt();
        const next = new Set(path).add(ref);
        const out: unknown[] = [];
        for (let i = 0; i < len; i++) out.push(readObject(readUInt(start + i * refSize, refSize), depth + 1, next));
        return out;
      }
      case 0xd: {
        const { len, start } = lengthAt();
        const next = new Set(path).add(ref);
        const out = obj();
        for (let i = 0; i < len; i++) {
          const key = readObject(readUInt(start + i * refSize, refSize), depth + 1, next);
          if (typeof key !== 'string') throw new PlistError('non-string dictionary key');
          setKey(out, key, readObject(readUInt(start + (len + i) * refSize, refSize), depth + 1, next));
        }
        return out;
      }
      default:
        throw new PlistError('unsupported object type');
    }
  };

  return readObject(topObject, 0, new Set());
}

// ---- XML 形式 -----------------------------------------------------------------

interface Token {
  kind: 'open' | 'close' | 'empty' | 'text';
  name?: string;
  text?: string;
}

function tokenizeXml(xml: string): Token[] {
  const tokens: Token[] = [];
  const s = xml.replace(/<\?[\s\S]*?\?>/g, '').replace(/<!DOCTYPE[\s\S]*?>/gi, '').replace(/<!--[\s\S]*?-->/g, '');
  const re = /<(\/?)([A-Za-z][\w.-]*)[^>]*?(\/?)>|([^<]+)/g;
  for (const m of s.matchAll(re)) {
    if (m[4] !== undefined) {
      if (m[4].trim() !== '') tokens.push({ kind: 'text', text: m[4] });
      continue;
    }
    tokens.push({ kind: m[1] ? 'close' : m[3] ? 'empty' : 'open', name: m[2]! });
  }
  if (s.replace(re, '').trim() !== '') throw new PlistError('malformed XML');
  return tokens;
}

function decodeEntities(s: string): string {
  return s.replace(/&(lt|gt|amp|quot|apos|#x[0-9a-fA-F]+|#[0-9]+);/g, (_m, e: string) => {
    if (e === 'lt') return '<';
    if (e === 'gt') return '>';
    if (e === 'amp') return '&';
    if (e === 'quot') return '"';
    if (e === 'apos') return "'";
    const code = e.startsWith('#x') ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : '';
  });
}

function parseXml(xml: string): unknown {
  const tokens = tokenizeXml(xml);
  let i = 0;
  const peek = () => tokens[i];
  const expectClose = (name: string) => {
    const t = tokens[i++];
    if (!t || t.kind !== 'close' || t.name !== name) throw new PlistError('malformed XML');
  };
  const textUntilClose = (name: string): string => {
    let text = '';
    while (peek() && peek()!.kind === 'text') text += tokens[i++]!.text;
    expectClose(name);
    return decodeEntities(text);
  };

  const value = (depth: number): unknown => {
    if (depth > MAX_DEPTH) throw new PlistError('nesting too deep');
    const t = tokens[i++];
    if (!t || (t.kind !== 'open' && t.kind !== 'empty')) throw new PlistError('malformed XML');
    const name = t.name!;
    if (t.kind === 'empty') {
      if (name === 'true') return true;
      if (name === 'false') return false;
      if (name === 'dict') return obj();
      if (name === 'array') return [];
      if (name === 'string') return '';
      throw new PlistError('unsupported element');
    }
    switch (name) {
      case 'dict': {
        const out = obj();
        while (peek() && peek()!.kind !== 'close') {
          const k = tokens[i++];
          if (!k || k.kind !== 'open' || k.name !== 'key') throw new PlistError('malformed dict');
          const key = textUntilClose('key');
          setKey(out, key, value(depth + 1));
        }
        expectClose('dict');
        return out;
      }
      case 'array': {
        const out: unknown[] = [];
        while (peek() && peek()!.kind !== 'close') out.push(value(depth + 1));
        expectClose('array');
        return out;
      }
      case 'string':
        return textUntilClose('string');
      case 'integer': {
        const n = Number(textUntilClose('integer').trim());
        if (!Number.isFinite(n)) throw new PlistError('invalid integer');
        return n;
      }
      case 'real': {
        const n = Number(textUntilClose('real').trim());
        if (Number.isNaN(n)) throw new PlistError('invalid real');
        return n;
      }
      case 'date':
      case 'data':
        return textUntilClose(name).trim();
      case 'true':
        expectClose('true');
        return true;
      case 'false':
        expectClose('false');
        return false;
      case 'plist': {
        const v = value(depth + 1);
        expectClose('plist');
        return v;
      }
      default:
        throw new PlistError('unsupported element');
    }
  };

  const result = value(0);
  if (i !== tokens.length) throw new PlistError('trailing content');
  return result;
}
