#!/usr/bin/env node
import { isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { startTextService } from './service.js';

const controller = new AbortController();
let service: Awaited<ReturnType<typeof startTextService>> | undefined, stopping = false;
const stop = () => {
  if (stopping) return; stopping = true; controller.abort();
  service?.close().catch(() => {process.stderr.write('SERVICE_STOP_FAILED\n'); process.exitCode = 1;});
};
process.once('SIGINT', stop); process.once('SIGTERM', stop);
try {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--config' || !isAbsolute(args[1]!)) throw new Error();
  // This module is trusted administrator code and may load mounted secrets/broker adapters.
  const config = await import(pathToFileURL(args[1]!).href);
  service = await startTextService(config.default, controller.signal);
  if (stopping) await service.close();
  else {service.server.on('error', () => {process.stderr.write('SERVICE_RUNTIME_FAILED\n'); process.exitCode = 1; stop();}); process.stdout.write('SERVICE_READY\n');}
} catch {
  // Configuration, identity and model errors may contain secret paths or tokens; log a fixed code.
  if (!stopping) {process.stderr.write('SERVICE_START_FAILED\n'); process.exitCode = 1;}
}
