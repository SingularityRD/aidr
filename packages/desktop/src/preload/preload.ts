import { contextBridge, type IpcRendererEvent, ipcRenderer } from "electron";
import {
	type AidrBridge,
	INVOKE_CHANNELS,
	type InvokeChannel,
	PUSH_CHANNELS,
	type PushChannel,
} from "../shared/contract.js";

/**
 * The only bridge between the page and the main process. The page gets two
 * functions; each refuses any channel outside the typed allowlist, and no
 * Electron or Node object is ever handed to the page.
 */
const bridge: AidrBridge = {
	invoke: ((channel: InvokeChannel, ...payload: unknown[]) => {
		if (!INVOKE_CHANNELS.includes(channel)) {
			return Promise.reject(new Error(`channel ${String(channel)} is not allowed`));
		}
		return ipcRenderer.invoke(channel, ...payload.slice(0, 1));
	}) as AidrBridge["invoke"],
	on: (channel, listener) => {
		if (!PUSH_CHANNELS.includes(channel as PushChannel)) {
			throw new Error(`channel ${String(channel)} is not allowed`);
		}
		const wrapped = (_event: IpcRendererEvent, payload: unknown) =>
			(listener as (value: unknown) => void)(payload);
		ipcRenderer.on(channel, wrapped);
		return () => {
			ipcRenderer.removeListener(channel, wrapped);
		};
	},
};

contextBridge.exposeInMainWorld("aidr", bridge);
