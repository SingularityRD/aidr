/**
 * Local typosquat signal for package installs.
 *
 * This runs without any network access. It compares a requested package name
 * with a small, shipped list of widely used package names per registry and
 * reports a name that is one edit (insert, delete, substitute or swap two
 * adjacent characters) away from one of them, or that differs from one only in
 * its separators. It is a review signal, not a verdict on the package: a
 * legitimate package can sit one edit away from a popular one, so a hit asks
 * and never denies.
 *
 * It is deliberately narrow. Names shorter than MIN_NAME_LENGTH are skipped
 * because short names are dense (`ws`, `qs`, `pg` are all one edit apart), and
 * an exact match with any listed name is never a hit. The list is reference
 * data: it says which names attackers imitate, not which packages are safe, and
 * a name that is not near any listed name is NOT reported as clean by this
 * module.
 */

export type TyposquatRegistry = "npm" | "pypi";

export interface TyposquatHit {
	/** The requested package name, as given. */
	packageName: string;
	/** The widely used package it closely resembles. */
	resembles: string;
	registry: TyposquatRegistry;
}

const MIN_NAME_LENGTH = 5;

// Widely used npm package names (and a few legitimate near neighbours, such as
// `preact`, `color` and `tslint`, listed so they are not mistaken for squats).
const POPULAR_NPM = [
	"@angular/core",
	"@anthropic-ai/sdk",
	"@apollo/client",
	"@babel/core",
	"@nestjs/core",
	"@types/node",
	"@types/react",
	"ajv",
	"apollo-server",
	"async",
	"autoprefixer",
	"aws-sdk",
	"axios",
	"babel-core",
	"babel-loader",
	"bcrypt",
	"bcryptjs",
	"bluebird",
	"body-parser",
	"bootstrap",
	"chalk",
	"chart.js",
	"cheerio",
	"chokidar",
	"classnames",
	"color",
	"colors",
	"commander",
	"concurrently",
	"cookie",
	"cookie-parser",
	"core-js",
	"cross-env",
	"cross-fetch",
	"crypto-js",
	"css-loader",
	"date-fns",
	"dayjs",
	"debug",
	"dotenv",
	"echarts",
	"electron",
	"esbuild",
	"eslint",
	"eslint-config-airbnb",
	"eslint-config-prettier",
	"eslint-plugin-import",
	"eslint-plugin-react",
	"express",
	"express-session",
	"fastify",
	"file-loader",
	"firebase",
	"fs-extra",
	"graphql",
	"handlebars",
	"helmet",
	"highlight.js",
	"html-webpack-plugin",
	"husky",
	"immutable",
	"inquirer",
	"ioredis",
	"jquery",
	"js-yaml",
	"jsdom",
	"jsonwebtoken",
	"leaflet",
	"lint-staged",
	"lodash",
	"luxon",
	"marked",
	"mime-types",
	"minimist",
	"mkdirp",
	"mocha",
	"moment",
	"moment-timezone",
	"mongodb",
	"mongoose",
	"morgan",
	"multer",
	"mustache",
	"mysql",
	"mysql2",
	"nanoid",
	"node-fetch",
	"nodemailer",
	"nodemon",
	"numeral",
	"openai",
	"parcel",
	"passport",
	"playwright",
	"postcss",
	"preact",
	"prettier",
	"prisma",
	"prop-types",
	"puppeteer",
	"ramda",
	"react",
	"react-dom",
	"react-native",
	"react-redux",
	"react-router",
	"react-router-dom",
	"redis",
	"redux",
	"regenerator-runtime",
	"request",
	"rimraf",
	"rollup",
	"rxjs",
	"semver",
	"sequelize",
	"sharp",
	"sinon",
	"socket.io",
	"socket.io-client",
	"stripe",
	"style-loader",
	"styled-components",
	"superagent",
	"svelte",
	"tailwindcss",
	"three",
	"ts-node",
	"tslib",
	"tslint",
	"twilio",
	"typeorm",
	"typescript",
	"underscore",
	"url-loader",
	"validator",
	"vitest",
	"webpack",
	"webpack-cli",
	"webpack-dev-server",
	"winston",
	"xml2js",
	"yargs",
];

// Widely used PyPI project names (PEP 503 normalised when compared).
const POPULAR_PYPI = [
	"aiohttp",
	"alembic",
	"anthropic",
	"ansible",
	"arrow",
	"asn1crypto",
	"async-timeout",
	"attrs",
	"awscli",
	"bcrypt",
	"beautifulsoup4",
	"black",
	"boto3",
	"botocore",
	"celery",
	"certifi",
	"chardet",
	"charset-normalizer",
	"click",
	"colorama",
	"coverage",
	"cryptography",
	"dateparser",
	"decorator",
	"django",
	"djangorestframework",
	"docker",
	"docutils",
	"fastapi",
	"filelock",
	"flake8",
	"flask",
	"frozenlist",
	"gensim",
	"google-api-core",
	"gradio",
	"grpcio",
	"gunicorn",
	"httpcore",
	"httpx",
	"huggingface-hub",
	"ipykernel",
	"ipython",
	"isort",
	"itsdangerous",
	"jinja2",
	"jmespath",
	"joblib",
	"jupyter",
	"keras",
	"kubernetes",
	"langchain",
	"lightgbm",
	"lxml",
	"markdown",
	"markupsafe",
	"marshmallow",
	"matplotlib",
	"multidict",
	"mypy",
	"networkx",
	"nltk",
	"notebook",
	"numba",
	"numpy",
	"oauthlib",
	"openai",
	"opencv-python",
	"openpyxl",
	"orjson",
	"packaging",
	"pandas",
	"paramiko",
	"pillow",
	"platformdirs",
	"plotly",
	"pluggy",
	"poetry",
	"polars",
	"protobuf",
	"psycopg2",
	"psycopg2-binary",
	"pyarrow",
	"pycparser",
	"pydantic",
	"pydantic-core",
	"pygments",
	"pyjwt",
	"pylint",
	"pymongo",
	"pynacl",
	"pyopenssl",
	"pytest",
	"python-dateutil",
	"python-dotenv",
	"pytz",
	"pyyaml",
	"redis",
	"regex",
	"requests",
	"requests-oauthlib",
	"rich",
	"ruff",
	"s3transfer",
	"safetensors",
	"scikit-learn",
	"scipy",
	"seaborn",
	"selenium",
	"setuptools",
	"simplejson",
	"soupsieve",
	"spacy",
	"sphinx",
	"sqlalchemy",
	"starlette",
	"streamlit",
	"sympy",
	"tenacity",
	"tensorflow",
	"tiktoken",
	"tokenizers",
	"tomli",
	"torch",
	"torchvision",
	"tqdm",
	"transformers",
	"typing-extensions",
	"tzdata",
	"ujson",
	"urllib3",
	"uvicorn",
	"virtualenv",
	"werkzeug",
	"wheel",
	"wrapt",
	"xgboost",
	"yarl",
];

function normalizeName(name: string, registry: TyposquatRegistry): string {
	const lower = name.trim().toLowerCase();
	// PEP 503: runs of `-`, `_` and `.` are one separator, so `python_dateutil`
	// IS `python-dateutil` on PyPI and must not be reported as an imitation.
	return registry === "pypi" ? lower.replace(/[-_.]+/g, "-") : lower;
}

const POPULAR: Record<TyposquatRegistry, ReadonlySet<string>> = {
	npm: new Set(POPULAR_NPM.map((name) => normalizeName(name, "npm"))),
	pypi: new Set(POPULAR_PYPI.map((name) => normalizeName(name, "pypi"))),
};

function withoutSeparators(name: string): string {
	return name.replace(/[-_.]/g, "");
}

/**
 * True when `a` and `b` are at most one edit apart (optimal string alignment:
 * insertion, deletion, substitution, or a swap of two adjacent characters).
 */
function withinOneEdit(a: string, b: string): boolean {
	if (a === b) return true;
	if (a.length === b.length) return oneSubstitutionOrSwap(a, b);
	if (Math.abs(a.length - b.length) > 1) return false;
	const [shorter, longer] = a.length < b.length ? [a, b] : [b, a];
	let i = 0;
	while (i < shorter.length && shorter[i] === longer[i]) i++;
	return shorter.slice(i) === longer.slice(i + 1);
}

/** Equal-length strings that differ in one position, or in two adjacent swapped ones. */
function oneSubstitutionOrSwap(a: string, b: string): boolean {
	const diffs: number[] = [];
	for (let i = 0; i < a.length && diffs.length <= 2; i++) {
		if (a[i] !== b[i]) diffs.push(i);
	}
	if (diffs.length === 1) return true;
	if (diffs.length !== 2) return false;
	const [i, j] = diffs as [number, number];
	return j === i + 1 && a[i] === b[j] && a[j] === b[i];
}

/**
 * The widely used package `packageName` imitates, or null when it is listed
 * itself, too short to judge, or not close to any listed name.
 */
export function findTyposquat(
	packageName: string,
	registry: TyposquatRegistry,
): TyposquatHit | null {
	const candidate = normalizeName(packageName, registry);
	const popular = POPULAR[registry];
	if (candidate.length < MIN_NAME_LENGTH || popular.has(candidate)) return null;
	const bareCandidate = withoutSeparators(candidate);
	for (const name of popular) {
		if (name.length < MIN_NAME_LENGTH) continue;
		if (withinOneEdit(candidate, name) || bareCandidate === withoutSeparators(name)) {
			return { packageName, resembles: name, registry };
		}
	}
	return null;
}
