import { Child } from "hono/jsx";
import { Hono } from "jsr:@hono/hono";
import { validator } from "jsr:@hono/hono/validator";
import { z, ZodError } from "npm:zod";
// @ts-types="npm:@types/jsdom"
import { JSDOM } from "npm:jsdom";
import { Cookie, CookieJar } from "npm:tough-cookie";
import { Buffer } from "node:buffer";
import ical, {ICalEventClass} from "ical-generator";
import { createDecipheriv, createCipheriv, createHash, randomBytes, randomUUID, scrypt } from "node:crypto";
import { StatusCode } from "hono/utils/http-status";

console.log("starting...");
const app = new Hono();
const kv = await Deno.openKv("./deno_kv");

const password = Deno.env.get("PASSWORD");

const host = Deno.env.get("HOST");
if (!host) {
	console.error("No HOST env variable");
	Deno.exit(1);
}

if (password) console.log("using password");
//idk how to do secure string comparison in JS and this makes me feel safer :)
const doHash = (pass: string)=>createHash("SHA256").update(Buffer.from(pass)).digest();
const passwordHash = password ? doHash(password) : null;

const Layout = ({children, title}: {children: Child, title?: string}) =>
	<html lang="en">
		<head>
			<meta charset="UTF-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1.0" />
			<title>{title ?? ""}</title>
			<link rel="stylesheet" href="/simple.min.css" />
		</head>
		<body>
			<header>
				<h1>Gradescope to iCalendar</h1>
			</header>
			<main>
				{children}
			</main>
			<footer>
				<p>Made by <a href="https://thomasqm.com" >Thomas Marlowe</a>.</p>
			</footer>
		</body>
	</html>;

app.get("/simple.min.css", async c=>{
	c.header("Content-Type", "text/css");
	return c.body((await Deno.open("./simple.min.css")).readable);
});

app.get("/", c=>c.html(<Layout>
	<p>Input your Gradescope <code>signed_token</code> cookie below. It will be used to access Gradescope to retrieve assignments from current courses</p>
	<p>Your Gradescope token will be stored encrypted server-side and will require the token in your calendar URL to decode, which will never be stored on the server.</p>
	<p>To revoke access, simply log out of Gradescope to invalidate your token.</p>

	<form action="/create" method="post" >
		{passwordHash && <div>
			<label for="pass" >Password</label>
			<input name="pass" required type="password" ></input>
		</div>}
		<div>
			<label for="token" ><code>signed_token</code> Cookie</label>
			<input type="password" required name="token" ></input>
		</div>
		<input type="submit" value="Create iCalendar" ></input>
	</form>
</Layout>));

type AppErrorType = "unauthorized"|"invalid"|"internal"|"notFound";
const errName = (type: AppErrorType) => ({
	unauthorized: "Unauthorized",
	invalid: "Invalid input",
	internal: "Internal server error",
	notFound: "Not found"
}[type]);

const errStatus = (type: AppErrorType): StatusCode => ({
	unauthorized: 401,
	invalid: 400,
	internal: 500,
	notFound: 404
} as const)[type];

class AppError extends Error {
	constructor(public type: AppErrorType, public msg?: string) {
		super(`${errName(type)}${msg ? `: ${msg}` : ""}`);
	}
};

type Encrypted = {
	salt: string,
	iv: string,
	enc: string,
	authTag: string
};

const deriveKey = (key: string, salt: Buffer) =>
	new Promise<Buffer>((res,rej) => scrypt(key, salt, 32, (err,k)=>{
		if (err) rej(err); else res(k);
	}));

// fairly unnecessary. i had fun though
async function encrypt(text: string, key: string): Promise<Encrypted> {
	const salt = randomBytes(16);
	const k = await deriveKey(key, salt);

	const iv = randomBytes(16);
	const enc = createCipheriv("aes-256-gcm", k, iv);
	const ciphertext = enc.update(text, "binary", "binary") + enc.final("binary");

	return {
		salt: salt.toString("binary"), iv: iv.toString("binary"),
		enc: ciphertext,
		authTag: enc.getAuthTag().toString("binary")
	};
}

async function decrypt(enc: Encrypted, key: string) {
	const k = await deriveKey(key, Buffer.from(enc.salt, "binary"));
	const dec = createDecipheriv("aes-256-gcm", k, Buffer.from(enc.iv, "binary"));

	dec.setAuthTag(Buffer.from(enc.authTag, "binary"));
	const out = dec.update(enc.enc, "binary", "binary");
	return out + dec.final("binary");
}

const gradescopeUrl = "https://www.gradescope.com";

async function getGradescope(path: string, token: string) {
	const jar = new CookieJar();
	jar.setCookie(new Cookie({key: "signed_token", value: token}), gradescopeUrl);

	const r = await JSDOM.fromURL(new URL(path, gradescopeUrl).toString(), {
		cookieJar: jar
	});
	
	return r.window.document;
}

type Assignment = {
	due: number,
	release?: number,
	lateDue?: number,
	name: string,
	course?: string,
	courseShort: string,
	url: string,
	utcOffset?: string,
	status?: string
};

async function getAssignments(token: string): Promise<Assignment[]> {
	const g = await getGradescope("/", token);
	const allAssignments: Assignment[] = [];

	const courseBoxes = g.querySelectorAll(".courseList > .courseList--coursesForTerm a.courseBox");
	if (courseBoxes.length==0) {
		throw new AppError("notFound", "No courses found on Gradescope. Is your token (still) valid?");
	}

	for (const el of courseBoxes) {
		const courseShort = el.querySelector(".courseBox--shortname")?.textContent;
		const course = el.querySelector(".courseBox--name")?.textContent;

		const hr = el.getAttribute("href");
		if (!hr || !/^\/courses\/\d+$/.test(hr)) continue; //???

		const g2 = await getGradescope(hr, token);
		for (const row of g2.querySelectorAll("#assignments-student-table > tbody > tr")) {
			const name = row.querySelector("th.table--primaryLink")?.textContent;
			const release = row.querySelector("time.submissionTimeChart--releaseDate")?.getAttribute("datetime");
			const releaseDate = release ? Date.parse(release) : NaN;

			let due: number|undefined; let lateDue: number|undefined, offset: string|undefined;
			for (const el2 of row.querySelectorAll("time.submissionTimeChart--dueDate")) {
				const dt = el2.getAttribute("datetime");
				if (!dt) continue;

				const tzOffsetRe = /([+-]\d{4})$/;
				const match = dt.match(tzOffsetRe);
				if (match && offset==undefined) {
					// const n = Number.parseInt(match[1]);
					// offset = 60*Math.floor(Math.abs(n)/100) + Math.abs(n)%100;
					// if (n<0) offset*=-1;
					offset = match[1];
				}

				const dtDate = Date.parse(dt);
				if (isNaN(dtDate)) continue;

				if (el2.innerHTML.startsWith("Late")) {
					lateDue=Math.min(dtDate, lateDue ?? Infinity);
				} else {
					due=Math.min(dtDate, due ?? Infinity);
				}
			}

			if (!due) continue;

			allAssignments.push({
				due, lateDue, release: isNaN(releaseDate) ? undefined : releaseDate,
				name: name ?? "Untitled assignment",
				course: course ?? undefined,
				courseShort: courseShort ?? "Unknown course",
				url: new URL(hr, gradescopeUrl).toString(),
				utcOffset: offset,
				status: row.querySelector(".submissionStatus--text")?.textContent ?? undefined
			});
		}
	}

	return allAssignments;
}

type Calendar = {
	encryptedGradescopeToken: Encrypted,
	tokenHash: string
};

app.post(
	"/create",
	validator('form', (v) => 
		z.object({
			token: z.string().nonempty(),
			pass: z.string().optional()
		}).parse(v)
  ),
	async c=>{
		const {token, pass} = c.req.valid("form");
		if (passwordHash!=null && (pass==undefined || !doHash(pass).equals(passwordHash))) {
			throw new AppError("unauthorized");
		}

		const calId = randomUUID();
		const calToken = randomBytes(16).toString("base64");

		//test if can access assignments...
		await getAssignments(token);

		await kv.set(["calendar", calId], {
			encryptedGradescopeToken: await encrypt(token, calToken),
			tokenHash: doHash(calToken).toString("binary")
		} satisfies Calendar);

		const url = new URL(`${host}/${calId}.ics`);
		url.searchParams.append("token", calToken);
		const urlS = url.toString();

		return c.html(<Layout>
			<h1>Calendar created</h1>
			<p>
				It can be accessed at <a href={urlS} >{urlS}</a>
			</p>
		</Layout>);
	}
);

app.get("/:calId{[0-9a-f-]+\\.ics}", async c => {
	const id = c.req.param("calId").slice(0,-".ics".length);
	const token = c.req.query("token");
	if (!token) throw new AppError("unauthorized", "No token");

	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	if (!uuidRegex.test(id)) throw new AppError("invalid", "Invalid calendar ID");

	const cal = (await kv.get<Calendar>(["calendar", id])).value;
	if (!cal) throw new AppError("notFound", "Calendar not found");

	if (!doHash(token).equals(Buffer.from(cal.tokenHash, "binary")))
		throw new AppError("unauthorized", "Invalid token");

	const gradescopeToken = await decrypt(cal.encryptedGradescopeToken, token);

	const assignments = await getAssignments(gradescopeToken);

	const calendar = ical({
		name: "Gradescope Assignments",
		description: `from ${host}`
	});

	for (const a of assignments) {
		const renderDate = (x: number) => {
			if (a.utcOffset==undefined) return new Date(x).toString();
			else return new Date(x).toLocaleString("en-US", {timeZone: a.utcOffset});
		};

		const bits = [
			a.course && `Course ${a.course}. `,
			a.release && `Released ${renderDate(a.release)}`,
			a.lateDue && `Late due date ${renderDate(a.lateDue)}`,
			a.status && `Status: ${a.status}`
		];

		calendar.createEvent({
			start: new Date(a.due),
			end: new Date(a.due),
			url: a.url,
			timezone: a.utcOffset,
			summary: a.name,
			location: `${a.courseShort} on Gradescope`,
			description: bits.filter(x=>x).join("\n\n"),
			created: a.release ? new Date(a.release) : undefined,
			class: ICalEventClass.PUBLIC
		});
	}

	c.header("Content-Type", "text/calendar");
	return c.body(calendar.toString());
});

app.onError((err,c)=>{
	console.error("Request error", err);

	if (err instanceof ZodError) err=new AppError("invalid", "Malformed request");

	c.status(err instanceof AppError ? errStatus(err.type) : 500);

	return c.html(<Layout title="An error occurred" >
		<h1>{err instanceof AppError ? errName(err.type) : "An unexpected error occurred."}</h1>
		{err instanceof AppError && err.msg && <h3>{err.msg}</h3>}
		<p>Please check server logs for more details.</p>
	</Layout>);
});

const portEnv = Deno.env.get("PORT");
const port = portEnv ? Number.parseInt(portEnv) : 5555;
console.log(`listening on port ${port}`);
Deno.serve({port}, app.fetch);
