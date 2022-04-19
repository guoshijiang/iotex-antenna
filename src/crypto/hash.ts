// @ts-ignore
import { Keccak } from "sha3";

export function hash160b(input: string | Buffer | Uint8Array): Buffer {
  const digest = hash256b(input);
  return digest.slice(12);
}

export function hash256b(input: string | Buffer | Uint8Array): Buffer {
  const k = new Keccak(256);
  // @ts-ignore
  k.update(Buffer.from(input));
  return k.digest();
}
