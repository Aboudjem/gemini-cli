/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { getErrorMessage, isNodeError } from './errors.js';
import { URL } from 'node:url';
import * as dns from 'node:dns';
import { lookup } from 'node:dns/promises';
import { Agent, ProxyAgent, setGlobalDispatcher } from 'undici';

const DEFAULT_HEADERS_TIMEOUT = 300000; // 5 minutes
const DEFAULT_BODY_TIMEOUT = 300000; // 5 minutes

// Configure default global dispatcher with higher timeouts
setGlobalDispatcher(
  new Agent({
    headersTimeout: DEFAULT_HEADERS_TIMEOUT,
    bodyTimeout: DEFAULT_BODY_TIMEOUT,
  }),
);

const PRIVATE_IP_RANGES = [
  /^10\./,
  /^127\./,
  /^0\.0\.0\.0$/,
  /^169\.254\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^::1$/,
  /^::$/,
  /^fc00:/,
  /^fe80:/,
];

export class FetchError extends Error {
  constructor(
    message: string,
    public code?: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'FetchError';
  }
}

export function isPrivateIp(url: string): boolean {
  try {
    const hostname = new URL(url).hostname;
    return isAddressPrivate(hostname);
  } catch (_e) {
    return false;
  }
}

/**
 * Checks if a URL resolves to a private IP address.
 * Performs DNS resolution to prevent DNS rebinding/SSRF bypasses.
 */
export async function isPrivateIpAsync(url: string): Promise<boolean> {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // Fast check for literal IPs or localhost
    if (isAddressPrivate(hostname)) {
      return true;
    }

    // Resolve DNS to check the actual target IP
    const addresses = await lookup(hostname, { all: true });
    return addresses.some((addr) => isAddressPrivate(addr.address));
  } catch (_e) {
    return false;
  }
}

/**
 * Internal helper to check if an IP address string is in a private range.
 */
export function isAddressPrivate(address: string): boolean {
  return (
    address === 'localhost' ||
    PRIVATE_IP_RANGES.some((range) => range.test(address))
  );
}

/**
 * A custom DNS lookup implementation for undici agents that prevents
 * connection to private IP ranges (SSRF protection).
 */
export function safeLookup(
  hostname: string,
  options: dns.LookupOptions | number | null | undefined,
  callback: (
    err: Error | null,
    addresses: Array<{ address: string; family: number }>,
  ) => void,
): void {
  // Use the callback-based dns.lookup to match undici's expected signature.
  // We explicitly handle the 'all' option to ensure we get an array of addresses.
  const lookupOptions =
    typeof options === 'number' ? { family: options } : { ...options };
  const finalOptions = { ...lookupOptions, all: true };

  dns.lookup(hostname, finalOptions, (err, addresses) => {
    if (err) {
      callback(err, []);
      return;
    }

    const addressArray = Array.isArray(addresses) ? addresses : [];

    const isExplicitLocalhost =
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1';

    const filtered = addressArray.filter((addr) => 
      // Allow if the hostname is explicitly localhost, otherwise block private ranges.
       isExplicitLocalhost || !isAddressPrivate(addr.address)
    );

    if (filtered.length === 0 && addressArray.length > 0) {
      callback(
        new Error(
          `Refusing to connect to private IP address resolved from ${hostname}`,
        ),
        [],
      );
      return;
    }

    callback(null, filtered);
  });
}

export async function fetchWithTimeout(
  url: string,
  timeout: number,
  options?: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  if (options?.signal) {
    if (options.signal.aborted) {
      controller.abort();
    } else {
      options.signal.addEventListener('abort', () => controller.abort(), {
        once: true,
      });
    }
  }

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } catch (error) {
    if (isNodeError(error) && error.code === 'ABORT_ERR') {
      throw new FetchError(`Request timed out after ${timeout}ms`, 'ETIMEDOUT');
    }
    throw new FetchError(getErrorMessage(error), undefined, { cause: error });
  } finally {
    clearTimeout(timeoutId);
  }
}

export function setGlobalProxy(proxy: string) {
  setGlobalDispatcher(
    new ProxyAgent({
      uri: proxy,
      headersTimeout: DEFAULT_HEADERS_TIMEOUT,
      bodyTimeout: DEFAULT_BODY_TIMEOUT,
    }),
  );
}
