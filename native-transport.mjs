import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// Only the current loopback service may receive its private credential.
export function nativeTransport({
  serviceFile = path.join(
    process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local/state'),
    'opencode/service.json',
  ),
  pid = process.pid,
  fetcher = fetch,
} = {}) {
  return async (method, pathname, { query = {}, body, signal } = {}) => {
    if (
      !(
        method === 'GET' && ['/api/permission/saved', '/api/permission/request'].includes(pathname)
      ) &&
      !(method === 'POST' && /^\/api\/session\/ses_[A-Za-z0-9_-]+\/permission$/.test(pathname))
    ) {
      throw Error('Unsupported native permission endpoint');
    }
    const file = await open(
      serviceFile,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    let service;
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.uid !== process.getuid() || stat.mode & 0o077 || stat.size > 8192)
        throw Error('Unsafe OpenCode service discovery file');
      const buffer = Buffer.alloc(8193),
        { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
      if (bytesRead > 8192) throw Error('Oversized OpenCode service discovery file');
      service = JSON.parse(buffer.subarray(0, bytesRead).toString('utf8'));
    } finally {
      await file.close();
    }
    const url = new URL(service.url);
    if (
      service.pid !== pid ||
      url.protocol !== 'http:' ||
      url.hostname !== '127.0.0.1' ||
      !url.port ||
      url.username ||
      url.password ||
      url.pathname !== '/' ||
      url.search ||
      url.hash ||
      typeof service.password !== 'string' ||
      !service.password
    )
      throw Error('OpenCode service identity mismatch');
    url.pathname = pathname;
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    const response = await fetcher(url, {
      method,
      signal,
      redirect: 'error',
      headers: {
        Authorization: 'Basic ' + Buffer.from('opencode:' + service.password).toString('base64'),
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok || !response.body) throw Error('Native permission API unavailable');
    const reader = response.body.getReader(),
      chunks = [];
    let bytes = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        bytes += part.value.length;
        if (bytes > 256 * 1024) throw Error('Native permission response exceeds its budget');
        chunks.push(Buffer.from(part.value));
      }
    } finally {
      await reader.cancel();
    }
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return value.data ?? value;
  };
}
