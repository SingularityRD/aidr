import { randomBytes, createHash } from "node:crypto";
const key = process.env.SRK; const base = "http://storage:5000";
const h = { authorization: `Bearer ${key}`, apikey: key };
let r = await fetch(`${base}/bucket`, { method: "POST", headers: { ...h, "content-type": "application/json" }, body: JSON.stringify({ id: "drill-objects", name: "drill-objects", public: false }) });
console.log("bucket", r.status);
const out = [];
for (let i = 0; i < 60; i++) {
  const body = randomBytes(i % 10 === 0 ? 1024 * 1024 : 16 * 1024 + i);
  r = await fetch(`${base}/object/drill-objects/tenant-${i % 6}/obj-${i}.bin`, { method: "POST", headers: { ...h, "content-type": "application/octet-stream" }, body });
  if (r.status !== 200) throw new Error(`upload ${i} ${r.status} ${await r.text()}`);
  out.push(createHash("sha256").update(body).digest("hex"));
}
console.log("uploaded", out.length, createHash("sha256").update(out.join("\n")).digest("hex"));
