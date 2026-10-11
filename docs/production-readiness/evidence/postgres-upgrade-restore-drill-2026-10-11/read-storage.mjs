import { createHash } from "node:crypto";
const key = process.env.SRK; const h = { authorization: `Bearer ${key}`, apikey: key };
const out = [];
for (let i = 0; i < 60; i++) {
  const r = await fetch(`http://storage:5000/object/drill-objects/tenant-${i % 6}/obj-${i}.bin`, { headers: h });
  if (r.status !== 200) throw new Error(`read ${i} ${r.status}`);
  out.push(createHash("sha256").update(Buffer.from(await r.arrayBuffer())).digest("hex"));
}
const anon = await fetch(`http://storage:5000/object/drill-objects/tenant-0/obj-0.bin`);
console.log("read", out.length, createHash("sha256").update(out.join("\n")).digest("hex"), "unauthenticated_status", anon.status);
