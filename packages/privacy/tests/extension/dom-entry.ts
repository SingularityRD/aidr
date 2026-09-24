// Test-only entry. Never distributed in extension/chrome.
import { installContentGuard } from '../../extension/src/content.js';
installContentGuard((globalThis as unknown as {__fixtureUrl:string}).__fixtureUrl,new URL((globalThis as unknown as {__fixtureUrl:string}).__fixtureUrl).origin);
