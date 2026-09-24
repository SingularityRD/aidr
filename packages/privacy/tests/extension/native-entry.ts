// Test-only export of production Native Messaging client.
import { nativeCall } from '../../extension/src/native-client.js';
(globalThis as unknown as {nativeClient:typeof nativeCall}).nativeClient=nativeCall;
