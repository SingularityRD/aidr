/**
 * Shell-command rules in threats/agent-safety.yaml: reward hacking / sabotage,
 * autonomy escalation and irreversible actions. Every rule has benign twins
 * that must NOT match (a normal test run, `git push origin feature`,
 * `terraform plan`, `DELETE ... WHERE id=1`, ...).
 */
import { beforeAll, describe, expect, it } from "vitest";
import { DecisionEngine } from "../engine.js";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

let engine: HeuristicsEngine;

beforeAll(async () => {
	engine = await loadEngine();
});

function agentIds(command: string): string[] {
	return matchCommand(engine, command).filter((id) => id.startsWith("CLT-AGENT-"));
}

function expectRule(id: string, positives: string[], negatives: string[]): void {
	for (const command of positives) {
		expect(agentIds(command), `expected ${id} for: ${command}`).toContain(id);
	}
	for (const command of negatives) {
		expect(agentIds(command), `unexpected agent-safety match for: ${command}`).toEqual([]);
	}
}

describe("reward hacking / sabotage — shell commands", () => {
	it("CLT-AGENT-RH-001 flags git hook bypass, not ordinary commits", () => {
		expectRule(
			"CLT-AGENT-RH-001",
			[
				'git commit --no-verify -m "wip"',
				"git push --no-verify origin feature/x",
				'git commit -n -m "skip hooks"',
				'git commit -anm "all"',
				"git -c core.hooksPath=/dev/null commit -m x",
				"git config core.hooksPath /dev/null",
				'"git" commit "--no-verify" -m x',
			],
			[
				'git commit -m "fix: handle empty input"',
				'git commit -am "update docs"',
				"git push origin feature/login",
				"git push -n origin main",
				"git config core.hooksPath .husky",
				"git log --no-merges",
			],
		);
	});

	it("CLT-AGENT-RH-002 flags hook-manager kill switches", () => {
		expectRule(
			"CLT-AGENT-RH-002",
			[
				'HUSKY=0 git commit -m "x"',
				"export HUSKY=0",
				"LEFTHOOK=0 git push",
				"$env:HUSKY=0; git commit -m x",
				'SKIP=eslint,prettier git commit -m "x"',
			],
			["HUSKY=1 git commit -m x", "npx husky init", "SKIP_BUILD=1 npm run dev"],
		);
	});

	it("CLT-AGENT-RH-003 flags force-pushes to protected branches only", () => {
		expectRule(
			"CLT-AGENT-RH-003",
			[
				"git push --force origin main",
				"git push -f origin master",
				"git push --force-with-lease origin HEAD:main",
				"git push origin +main",
				"git push -f upstream release/2.3",
			],
			[
				"git push origin feature",
				"git push --force origin feature/refactor",
				"git push -f origin fix/main-menu",
				"git push origin main",
				"git push -u origin main",
			],
		);
	});

	it("CLT-AGENT-RH-004 flags shell history erasure", () => {
		expectRule(
			"CLT-AGENT-RH-004",
			[
				"history -c",
				"history -c && history -w",
				"unset HISTFILE",
				"export HISTFILE=/dev/null",
				"HISTSIZE=0",
				"set +o history",
				"rm ~/.bash_history",
				"cat /dev/null > ~/.zsh_history",
				"Clear-History",
			],
			["history | tail -20", "cat ~/.bash_history | grep ssh", "echo $HISTFILE"],
		);
	});

	it("CLT-AGENT-RH-005 flags git history rewrites and protected-branch deletion", () => {
		expectRule(
			"CLT-AGENT-RH-005",
			[
				"git reflog expire --expire=now --all",
				"git filter-branch --tree-filter 'rm -f secrets.txt' HEAD",
				"git filter-repo --path secrets.txt --invert-paths",
				"git push origin --delete main",
				"git push origin :master",
				"java -jar bfg.jar --delete-files id_rsa",
			],
			[
				"git reflog",
				"git reflog show HEAD",
				"git push origin --delete feature/old",
				"git branch -d feature/old",
			],
		);
	});

	it("CLT-AGENT-RH-006 flags log and audit truncation or deletion", () => {
		expectRule(
			"CLT-AGENT-RH-006",
			[
				"truncate -s 0 /var/log/app.log",
				": > server.log",
				"> app.log",
				'echo "" > audit.log',
				"cat /dev/null > /var/log/syslog",
				"rm -rf /var/log/nginx/",
				"rm -f ~/audit-trail.jsonl",
			],
			[
				"npm test > test-output.log",
				"tail -f server.log",
				'echo "starting" > build.log',
				"node app.js >> app.log",
				"rm -f build.log",
				"rm src/audit.ts",
			],
		);
	});

	it("CLT-AGENT-RH-007 flags disabling audit logging", () => {
		expectRule(
			"CLT-AGENT-RH-007",
			[
				"journalctl --vacuum-time=1s",
				"sudo auditctl -e 0",
				"auditctl -D",
				"sudo systemctl stop auditd",
				"service auditd stop",
				"Clear-EventLog -LogName Application",
			],
			["journalctl -u nginx --since today", "auditctl -l", "systemctl status auditd"],
		);
	});

	it("CLT-AGENT-RH-008 flags deleting or emptying test files", () => {
		expectRule(
			"CLT-AGENT-RH-008",
			[
				"rm src/auth.test.ts",
				"git rm tests/test_api.py",
				"rm -rf tests",
				"rm -rf src/__tests__/",
				"rm pkg/server_test.go",
				'find . -name "*.spec.js" -delete',
				": > src/parser.test.ts",
				"truncate -s 0 tests/test_models.py",
			],
			[
				"rm -rf /tmp/test",
				"rm -rf test-results",
				"rm -rf coverage",
				"rm src/auth.ts",
				"rm -f testdata.json",
				"npm test",
				"pytest tests/test_api.py",
			],
		);
	});

	it("CLT-AGENT-RH-009 flags in-place edits that skip tests or strip assertions", () => {
		expectRule(
			"CLT-AGENT-RH-009",
			[
				"sed -i 's/it(/it.skip(/' src/app.test.ts",
				"sed -i '/expect(/d' src/app.test.ts",
				"perl -pi -e 's/def test_/@pytest.mark.skip\\ndef test_/' tests/test_x.py",
			],
			[
				"sed -i 's/foo/bar/' src/app.ts",
				'grep -rn "it.skip" src',
				"sed -n '1,20p' src/app.test.ts",
			],
		);
	});

	it("CLT-AGENT-RH-010 flags removing branch protection via the GitHub API", () => {
		expectRule(
			"CLT-AGENT-RH-010",
			[
				"gh api -X DELETE repos/acme/app/branches/main/protection",
				"gh api --method DELETE repos/acme/app/rulesets/42",
			],
			["gh api repos/acme/app/branches/main/protection", "gh pr list"],
		);
	});
});

describe("autonomy escalation", () => {
	it("CLT-AGENT-AUTO-001 flags Claude Code without permission prompts", () => {
		expectRule(
			"CLT-AGENT-AUTO-001",
			[
				'claude --dangerously-skip-permissions -p "fix the build"',
				'claude -p "refactor" --permission-mode bypassPermissions',
				"claude --permission-mode=bypassPermissions",
				"npx @anthropic-ai/claude-code --dangerously-skip-permissions",
				"'claude' '--dangerously-skip-permissions'",
			],
			[
				'claude -p "explain this repo"',
				"claude --permission-mode plan",
				"claude mcp list",
				'grep -rn "skip-permissions" docs',
			],
		);
	});

	it("CLT-AGENT-AUTO-002 flags Codex without approvals or sandbox", () => {
		expectRule(
			"CLT-AGENT-AUTO-002",
			[
				'codex exec --dangerously-bypass-approvals-and-sandbox "deploy"',
				'codex --full-auto "fix tests"',
				'codex -a never "do it"',
				"codex --sandbox danger-full-access",
				'codex -c approval_policy=never exec "x"',
				"codex --yolo",
			],
			['codex exec "summarize the diff"', "codex -a on-request", "pnpm -C packages/codex test"],
		);
	});

	it("CLT-AGENT-AUTO-003..006 flag other agent CLIs in unattended mode", () => {
		expectRule(
			"CLT-AGENT-AUTO-003",
			['gemini --yolo -p "fix"', "gemini --approval-mode yolo", "qwen -y"],
			['gemini -p "explain"'],
		);
		expectRule(
			"CLT-AGENT-AUTO-004",
			['cursor-agent -p "fix lint" --force', "cursor-agent -f"],
			['cursor-agent -p "review"'],
		);
		expectRule(
			"CLT-AGENT-AUTO-005",
			["aider --yes-always --message 'fix'", "aider --yes"],
			["aider --model sonnet"],
		);
		expectRule(
			"CLT-AGENT-AUTO-006",
			[
				'amp --dangerously-allow-all -x "ship it"',
				'droid exec --skip-permissions-unsafe "x"',
				'q chat --trust-all-tools "x"',
				'copilot -p "x" --allow-all-tools',
				'opencode run --dangerously-skip-permissions "x"',
			],
			['opencode run "explain"', 'copilot -p "explain"'],
		);
	});

	it("CLT-AGENT-AUTO-007 flags agents spawned detached", () => {
		expectRule(
			"CLT-AGENT-AUTO-007",
			[
				'nohup claude -p "keep fixing" > out.log 2>&1 &',
				'setsid codex exec "loop"',
				'screen -dm claude -p "x"',
				"tmux new -d -s bot 'gemini -p x'",
				'claude -p "long task" &',
			],
			['claude -p "task" && echo done', 'claude -p "task" 2>&1 | tee log', "nohup npm run dev &"],
		);
	});

	it("is a deny at balanced and an ask at relaxed", async () => {
		const matches = engine.match([
			{ type: "command", value: "claude --dangerously-skip-permissions -p x" },
		]);
		const balanced = await new DecisionEngine("balanced").decide({
			heuristicMatches: matches,
			urlCheckResults: [],
		});
		const relaxed = await new DecisionEngine("relaxed").decide({
			heuristicMatches: matches,
			urlCheckResults: [],
		});
		expect(balanced.decision).toBe("deny");
		expect(balanced.category).toBe("autonomy_escalation");
		expect(relaxed.decision).toBe("ask");
	});
});

describe("irreversible actions", () => {
	it("CLT-AGENT-IRR-001 flags destructive SQL through DB clients, not scoped deletes", () => {
		expectRule(
			"CLT-AGENT-IRR-001",
			[
				'psql -d prod -c "DROP TABLE users;"',
				"mysql -e 'DROP DATABASE shop'",
				'sqlite3 app.db "DELETE FROM sessions"',
				'psql -c "delete from orders;"',
				'psql -c "TRUNCATE TABLE audit_events"',
				'echo "DROP SCHEMA public CASCADE;" | psql $DATABASE_URL',
			],
			[
				'psql -c "DELETE FROM users WHERE id=1"',
				'psql -c "SELECT * FROM users"',
				'sqlite3 app.db "delete from sessions where expires_at < now()"',
				"psql -c '\\dt'",
			],
		);
	});

	it("CLT-AGENT-IRR-002 flags framework database drops and resets", () => {
		expectRule(
			"CLT-AGENT-IRR-002",
			[
				"bin/rails db:drop",
				"npx prisma migrate reset --force",
				"prisma db push --accept-data-loss",
				"python manage.py flush --noinput",
				"redis-cli -h cache FLUSHALL",
				"dropdb production",
			],
			[
				"bin/rails db:migrate",
				"npx prisma migrate dev",
				"python manage.py migrate",
				"redis-cli GET key",
			],
		);
	});

	it("CLT-AGENT-IRR-003 flags infrastructure teardown, not plans", () => {
		expectRule(
			"CLT-AGENT-IRR-003",
			[
				"terraform destroy",
				"terraform -chdir=infra apply -auto-approve",
				"tofu apply -destroy",
				"pulumi destroy --yes",
				"pulumi up --yes",
				"cdk destroy MyStack",
			],
			[
				"terraform plan",
				"terraform plan -destroy",
				"terraform apply",
				"pulumi preview",
				"terraform init",
			],
		);
	});

	it("CLT-AGENT-IRR-004 flags Kubernetes bulk and namespace deletion", () => {
		expectRule(
			"CLT-AGENT-IRR-004",
			[
				"kubectl delete namespace staging",
				"kubectl delete pods --all -n prod",
				"kubectl delete pvc data-db-0",
				"helm uninstall api -n prod",
			],
			[
				"kubectl get pods -A",
				"kubectl delete pod api-7d9f",
				"helm upgrade api ./chart",
				"helm list",
			],
		);
	});

	it("CLT-AGENT-IRR-005..008 flag cloud and hosted resource deletion", () => {
		expectRule(
			"CLT-AGENT-IRR-005",
			[
				"aws s3 rb s3://prod-assets --force",
				"aws s3 rm s3://prod-assets --recursive",
				"aws ec2 terminate-instances --instance-ids i-123",
				"aws rds delete-db-instance --db-instance-identifier prod",
				"aws dynamodb delete-table --table-name users",
			],
			["aws s3 ls", "aws s3 rm s3://bucket/tmp/file.txt", "aws sqs delete-message --queue-url q"],
		);
		expectRule(
			"CLT-AGENT-IRR-006",
			[
				"gcloud compute instances delete vm-1",
				"gsutil rm -r gs://bucket",
				"gcloud projects delete my-proj",
			],
			["gcloud compute instances list", "gsutil ls gs://bucket"],
		);
		expectRule(
			"CLT-AGENT-IRR-007",
			["az group delete --name prod-rg --yes", "az keyvault purge --name kv"],
			["az group list"],
		);
		expectRule(
			"CLT-AGENT-IRR-008",
			[
				"heroku apps:destroy --app shop",
				"gh repo delete acme/app --yes",
				"npm unpublish my-pkg@1.0.0",
			],
			["heroku logs --tail", "gh repo view acme/app"],
		);
	});

	it("CLT-AGENT-IRR-009 flags admin merges and repository exposure", () => {
		expectRule(
			"CLT-AGENT-IRR-009",
			["gh pr merge 42 --admin --squash", "gh repo edit acme/app --visibility public"],
			["gh pr merge 42 --squash", "gh pr view 42"],
		);
	});

	it("CLT-AGENT-IRR-010 flags publishing, but not dry runs or local installs", () => {
		expectRule(
			"CLT-AGENT-IRR-010",
			[
				"npm publish",
				"pnpm -r publish --access public",
				"twine upload dist/*",
				"python -m twine upload dist/*",
				"cargo publish",
				"gh release create v1.2.0",
				"./gradlew publishToMavenCentral",
			],
			[
				"npm publish --dry-run",
				"cargo publish --dry-run",
				"npm run publish-docs",
				"twine check dist/*",
				"./gradlew publishToMavenLocal",
				"npm install",
			],
		);
	});

	it("CLT-AGENT-IRR-011 flags pushes to public registries only", () => {
		expectRule(
			"CLT-AGENT-IRR-011",
			[
				"docker push acme/api:1.2",
				"docker push ghcr.io/acme/api:latest",
				"docker buildx build --push -t acme/api:1.2 .",
			],
			[
				"docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/api:1.2",
				"docker push localhost:5000/api",
				"docker push registry.internal:5000/api",
				"docker build -t acme/api .",
			],
		);
	});

	it("CLT-AGENT-IRR-012..013 flag messaging and payments on the user's behalf", () => {
		expectRule(
			"CLT-AGENT-IRR-012",
			[
				'echo "report" | mail -s "Weekly" boss@example.com',
				"sendmail -t < message.txt",
				"aws ses send-email --from a@example.com --to b@example.com",
				"curl -X POST -d @msg.json https://hooks.slack.com/services/T0/B0/XYZ",
			],
			["man mail", "cat /var/mail/user", "curl https://example.com/api"],
		);
		expectRule(
			"CLT-AGENT-IRR-013",
			[
				"stripe charges create --amount 5000 --currency usd",
				"stripe payment_intents confirm pi_123",
				"curl https://api.stripe.com/v1/refunds -u sk_test_x: -d charge=ch_1",
			],
			[
				"stripe charges list",
				"stripe listen --forward-to localhost:3000",
				"stripe trigger payment_intent.succeeded",
			],
		);
	});

	it("CLT-AGENT-IRR-014 flags production deploys", () => {
		expectRule(
			"CLT-AGENT-IRR-014",
			[
				"vercel --prod",
				"vercel deploy --prod",
				"firebase deploy --only functions",
				"fly deploy",
				"gcloud run deploy api --image gcr.io/x/api",
				"git push heroku main",
				"kubectl apply -f deploy.yaml --context prod-eu",
			],
			[
				"vercel dev",
				"vercel deploy",
				"firebase emulators:start",
				"kubectl apply -f deploy.yaml -n staging",
			],
		);
	});

	it("irreversible actions are asks, never denies", async () => {
		for (const command of ["terraform destroy", "npm publish", "docker push acme/api:1"]) {
			const verdict = await new DecisionEngine("paranoid").decide({
				heuristicMatches: engine.match([{ type: "command", value: command }]),
				urlCheckResults: [],
			});
			expect(verdict.decision, command).toBe("ask");
			expect(verdict.category, command).toBe("irreversible_action");
			expect(verdict.reasons.join(" "), command).toMatch(/^Irreversible action:/);
		}
	});
});

describe("benign developer commands stay clean", () => {
	it("does not flag everyday coding-agent commands", () => {
		const benign = [
			"npm test",
			"pnpm test -- --reporter=verbose",
			"pytest -q tests/",
			"go test ./...",
			"git status",
			"git add -A && git commit -m 'feat: add parser'",
			"git push origin feature/parser",
			"git pull --rebase",
			"terraform plan -out=tfplan",
			"kubectl get deployments",
			"docker build -t app .",
			"npm run build",
			"cargo build --release",
			"ls -la",
			"cat package.json",
			"rm -rf node_modules dist",
			"mkdir -p src/utils",
			"psql -c 'SELECT count(*) FROM users'",
			"aws s3 cp build/ s3://bucket/ --recursive",
		];
		for (const command of benign) {
			expect(agentIds(command), command).toEqual([]);
		}
	});
});
