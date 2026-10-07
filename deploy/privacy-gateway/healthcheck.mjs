// Container health probe for the AIDR privacy gateway.
//
// aidr-privacy-service opens its mutually authenticated listener only after the
// NER model, signed policy, identity broker and durable state are ready, so an
// accepted TCP connection on the loopback port means "ready". The probe does not
// start a TLS handshake (it holds no client certificate) and sends no request,
// so it can never reach the egress path or a provider.
import { connect } from "node:net";

const port = Number(process.env.AIDR_PRIVACY_HEALTH_PORT ?? 8443);
const socket = connect({ host: "127.0.0.1", port, timeout: 3000 });
const finish = (code) => { socket.destroy(); process.exit(code); };
socket.once("connect", () => finish(0));
socket.once("timeout", () => finish(1));
socket.once("error", () => finish(1));
