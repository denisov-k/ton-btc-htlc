// core/*.mjs was written for Node and reaches for Buffer; give the browser one before anything runs
import { Buffer } from 'buffer';
globalThis.Buffer ??= Buffer;
