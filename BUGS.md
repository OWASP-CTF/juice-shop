# Security & Code Review — OWASP Juice Shop (branch `ctf/juice-shop`)

Manual read of the server-side code (`server.ts`, all 61 `routes/`, `lib/`, `models/`, `data/`, `views/`)
plus the Angular hot spots and the dependency/build configuration. No fixes applied.

Findings are ranked by severity. Confidence is stated where I could not fully prove exploitability
from reading alone. Chainability is called out per finding — several individually-moderate issues
combine into full account takeover.

## Scope of this review

Read in full: `server.ts`, all 61 files in `routes/`, all of `lib/` (including `lib/startup/`),
all of `models/`, `views/`, `config/default.yml` + `config/ctf.yml`, `Dockerfile`, `.dockerignore`,
`.gitignore`, `package.json`, and the relevant parts of `node_modules` needed to verify dependency
claims.

Sampled, not exhaustive — **this is where to look next**:
- **`frontend/src` (384 files): roughly 8 read.** I grepped the whole tree for DOM-injection sinks
  (`innerHTML`, `bypassSecurityTrust*`, `eval`, `document.write`) and read every file those hits
  landed in, plus the auth guards, the OAuth component and `user.service.ts`. Client-side logic
  outside those greps is unreviewed.
- **`data/datacreator.ts` (~770 lines): grepped, not read.** Findings from it are keyword hits, not
  a full pass over the seeding logic.
- **Not opened at all:** `test/`, `rsn/`, `data/static/codefixes/`, `frontend/src/hacking-instructor/`,
  the `.well-known/csaf` documents, `swagger.yml`, and the remaining `config/*.yml` profiles.
- **Nothing was executed.** No request was issued against a running instance, so every finding is
  from static reading. The two marked "not confirmed" (M9, M10b) specifically need a live check.

---

## Critical

### C1. The RSA signing key is hardcoded in the source
`lib/insecurity.ts:23`

```ts
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDb...'
```

Every session token is signed RS256 with a private key that is committed to the repository, and the
matching public key is served to the world at `/encryptionkeys/jwt.pub` (`server.ts:277`, no
allowlist on that handler). Anyone holding a copy of the source can mint a syntactically perfect,
signature-valid token asserting any `id`, `email` or `role` they like.

This defeats every authorization control in the app at once: `isAuthorized`, `isAdmin`,
`isAccounting`, `isDeluxe`, `verify` and `updateAuthenticatedUsers` all reduce to "is this signed
with the published key". The careful algorithm-pinning work throughout `insecurity.ts` and
`routes/verify.ts` is defending the front door while the key is under the mat.

**Chains with:** C4 (guards that fall open when the caller is not in the session map — a forged
token is never in that map), C3 (any basket by id), H7 (`deluxeToken` disclosure), M19.

### C2. No lockfile, and the manifest disagrees with the installed tree — so nobody can say what the security controls actually do

`.gitignore` (ignores `package-lock.json`), `package.json`, `Dockerfile:6`

There is no `package-lock.json`, `npm-shrinkwrap.json` or `yarn.lock` in the repo, and the Dockerfile
runs a bare `npm install --omit=dev`, so every build re-resolves floating ranges. The declared
versions and the versions actually sitting in `node_modules` do not match, **in both directions**:

| Package | `package.json` | Installed locally | Which is riskier |
|---|---|---|---|
| `jsonwebtoken` | `^8.5.1` | **0.4.0** | installed tree |
| `js-yaml` | `^3.14.0` | reports `5.2.3` (v4 layout) | manifest |
| `sanitize-html` | `1.4.2` (exact) | 2.17.6 | manifest |
| `unzipper` | `0.9.15` | 0.12.5 | manifest |
| `express-jwt` | `0.1.3` | 0.1.3 | both |

This is the finding, and it is critical because it makes every other dependency-dependent conclusion
in this report — including several of mine — unverifiable without first pinning the tree. Reading
`node_modules` tells you about a developer's laptop; reading `package.json` tells you about the
image. They currently describe different applications.

Three concrete, demonstrated consequences:

**(a) On the installed tree, tokens never expire.** `lib/insecurity.ts:85` asks for a 6-hour token:

```ts
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```

`jsonwebtoken@0.4.0`'s `sign()` (`node_modules/jsonwebtoken/index.js:14`) only honours
`expiresInMinutes`, so `expiresIn` is ignored, no `exp` claim is written, and no token ever expires.
Nothing else imposes a lifetime — `authenticatedUsers.tokenMap` (`lib/insecurity.ts:109`) is only
ever added to, and entries are removed only by an explicit `POST /rest/user/logout`.
**On a fresh build from the manifest (8.5.1) this is fixed** and the 6-hour expiry works.

**(b) On the installed tree, the algorithm restriction in `updateAuthenticatedUsers` is a no-op.**
See H13 — same root cause, same "fixed by a correct install" resolution.

**(c) In the opposite direction, the build is *worse* than the laptop.** `sanitize-html` is pinned
**exact** at `1.4.2`, a version with documented filter bypasses, and it is the engine behind
`sanitizeSecure()` — the single defence standing behind every stored-XSS surface in the app
(`models/user.ts:49,56`, `models/feedback.ts:43`, `models/product.ts:48`, `routes/saveLoginIp.ts:24`).
The dev tree's 2.17.6 hides this entirely. Likewise `js-yaml`: the manifest range resolves to v3,
where `load()` is the unsafe full-schema loader (H11), while the installed package has the v4 layout
where `load()` is safe.

Commit `e34ecff` ("Upgrade jsonwebtoken from 0.4.0 to 8.5.1") shows the manifest bump was deliberate
and `node_modules` was simply never reinstalled — which is exactly how this class of drift arises and
why a committed lockfile plus a clean-install check in CI is the actual fix.

**Also worth verifying:** the installed `js-yaml` reports version **5.2.3**, which does not exist
upstream (v3 tops out at 3.14.1, v4 at 4.1.0). The package metadata otherwise looks genuine
(`"repository": "nodeca/js-yaml"`, correct author, v4-style `dist/js-yaml.cjs.js` entry point), so
this is most likely a locally mangled install rather than a substituted package — but an
impossible version number in a dependency tree should be run down, not assumed benign.

### C3. Checkout does not check basket ownership
`routes/order.ts:34-51`

```ts
const id = req.params.id
BasketModel.findOne({ where: { id }, include: [...] })
```

`retrieveBasket` (`routes/basket.ts:25-33`) and `applyCoupon` (`routes/coupon.ts:26-30`) were both
given explicit ownership checks. `placeOrder` was not, and it is the most destructive of the three.
`app.use('/rest/basket/:id', security.isAuthorized())` only proves *some* valid session exists.

Any authenticated user can `POST /rest/basket/<victim-id>/checkout` and:
- have the victim's basket items destroyed (`BasketItemModel.destroy({ where: { BasketId: id } })`, line 50)
- have the victim's coupon cleared (line 49)
- have the **bonus points for the victim's basket credited to their own wallet** — `req.body.UserId`
  comes from `appendUserId()` on the caller's token, so line 160 increments the *attacker's* balance
- generate a PDF of the victim's order into a publicly readable directory (see H6)

### C4. Ownership guards fall open when the caller is not in the session map
`routes/basket.ts:26`, `routes/basketItems.ts:54`

```ts
// basket.ts
const requester = security.authenticatedUsers.from(req)
if (requester != null && basket != null) { ...ownership check... }

// basketItems.ts
} else if (user && requestedBasketId && ... && Number(user.bid) != Number(requestedBasketId)) {
```

Both checks are written so that a **null requester skips the check entirely** rather than failing
closed. `isAuthorized()` validates the signature only; it never consults `tokenMap`. So any
signature-valid token that was not minted by this process's login flow — which is exactly what C1
produces — reaches the permissive branch and can read or write any basket by id.

The in-code comment at `basket.ts:22-24` states this is deliberate ("a valid token that predates
this process still behaves as it did before"), but the compatibility it buys is the same hole an
attacker uses.

---

## High

### H1. Weak and unsalted password hashing
`lib/insecurity.ts:44`, `models/user.ts:68-73`

```ts
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

Unsalted MD5. Any database read (SQL injection, backup, `/api/Users` as admin) yields instantly
crackable credentials. Used for login comparison, the 2FA password confirmation
(`routes/2fa.ts:107,152`), and `changePassword`.

### H2. Hardcoded HMAC key for security answers, and a hardcoded cookie secret
`lib/insecurity.ts:45`, `server.ts:286`

```ts
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')...
app.use(cookieParser('kekse'))
```

`models/securityAnswer.ts:45-47` confirms answers are stored as `security.hmac(answer)` — a single
unsalted SHA-256 HMAC under a key that is in the source. Security answers are low-entropy by nature
(the seeded ones are values like `Samuel`, `Zaya`, `West-2082`), so anyone with the repo can build a
rainbow table over a name list and invert the whole `SecurityAnswers` table offline; no interaction
with `resetPassword` (`routes/resetPassword.ts:41`) is needed. The cookie signing secret is likewise
public, so any signed cookie can be forged.

### H3. Discount coupons are unsigned and self-minting
`lib/insecurity.ts:156-178`

```ts
export const generateCoupon = (discount, date = new Date()) => z85.encode(utils.toMMMYY(date) + '-' + discount)
```

A coupon is z85 of `MMMYY-<discount>` with no MAC and no server-side record. `discountFromCoupon`
accepts anything that decodes to the current month and a numeric discount, up to 99%. Any customer
can mint a maximum-discount coupon with three lines of code — no request to the server required.

### H4. The chatbot's coupon tool has no server-side cap
`routes/chat.ts:185-196`

```ts
inputSchema: z.object({ discount: z.number().describe('The discount percentage for the coupon (maximum 10)') }),
execute: async ({ discount }) => { ... security.generateCoupon(discount) }
```

"Maximum 10" exists only in the prompt text and the Zod `.describe()` string — neither constrains
the value. `z.number()` accepts any number. A prompt injection that persuades the model to call the
tool with `discount: 95` mints a real, redeemable coupon. Tool arguments coming out of an LLM are
untrusted input and need the same validation as an HTTP body.

`/rest/chat` (`server.ts:661`) is also **unauthenticated and unrate-limited**, so both the injection
surface and the token-spend are open to anonymous callers.

### H5. Campaign coupon validity is decided by data the client sends
`routes/order.ts:196-205`

```ts
const couponData = Buffer.from(req.body.couponData, 'base64').toString().split('-')
const couponDate = Number(couponData[1])
if (campaign && couponDate == campaign.validOn) { return campaign.discount }
```

The date the discount is validated against arrives in the request body. Any long-expired campaign
(`WMNSDY2019`, 75%) can be replayed by sending the campaign's own `validOn` value back. Note also
the loose `==` on line 202.

### H6. Order confirmation PDFs are written into a publicly browsable directory
`routes/order.ts:41-45`, `server.ts:268-269`, `routes/fileServer.ts:43`

```ts
const pdfFile = `order_${orderId}.pdf`
const fileWriter = doc.pipe(fs.createWriteStream(path.join('ftp/', pdfFile)))
```

`/ftp` has directory listing enabled (`serveIndex('ftp')`) and `servePublicFiles` explicitly allows
`.pdf`. Every customer's order confirmation — email address, line items, totals, delivery address —
is listed and downloadable by any anonymous visitor. Order ids contain 16 random hex chars, but the
directory index removes the need to guess.

`lib/startup/cleanupFtpFolder.ts` deletes `ftp/*.pdf` at boot, so the exposure is bounded by uptime
rather than being permanent — but a long-running instance accumulates every order placed since the
last restart, and the cleanup is indiscriminate (it would also remove any PDF legitimately placed
there). Order PDFs should be written outside the served directory and fetched through an
ownership-checked handler.

### H7. `/rest/memories` leaks the full user record of every user who has uploaded a memory
`routes/memory.ts:22-30`

```ts
const memories = await MemoryModel.findAll({
  include: [{ model: UserModel, attributes: { exclude: ['password', 'totpSecret'] } }]
})
```

The route has no authentication (`server.ts:653`). The `include` is an inner join, so the exposure is
scoped to users who have actually uploaded a memory — not the whole user table. For each of those,
excluding two columns still discloses `email`, `role`, `deluxeToken`, `lastLoginIp` and `id`. That is
a ready-made target list for credential stuffing, and `deluxeToken` is the exact value `isDeluxe()`
compares against (`lib/insecurity.ts:259`).

**Chains with:** H1 (crack the hashes you obtain elsewhere), M4 (security-question reset by email),
M3 (unrate-limited login).

### H8. Websockets broadcast solved-challenge notifications, including flags, to anyone
`lib/startup/registerWebsocketEvents.ts:24-52`

```ts
io.on('connection', (socket) => {
  notifications.forEach((notification) => { socket.emit('challenge solved', notification) })
  socket.on('notification received', (data) => { ...notifications.splice(i, 1) })
  socket.on('verifyLocalXssChallenge', (data) => { challengeUtils.solveIf(...) })
```

Three problems in one handler:
1. Every notification object — which carries `flag: utils.ctfFlag(challenge.name)`
   (`lib/challengeUtils.ts:48,62`) — is pushed to **every** connecting socket with no authentication.
2. Any client can delete entries from the shared global `notifications` array by emitting a flag
   value back, affecting all other users.
3. `verifyLocalXssChallenge`, `verifySvgInjectionChallenge` and `verifyCloseNotificationsChallenge`
   let an unauthenticated client assert application state by sending a chosen payload.

`routes/repeatNotification.ts` is a second, unauthenticated HTTP path to the same notification
(and flag) for any already-solved challenge.

### H9. Profile image URL upload writes attacker-controlled SVG into the web root
`routes/profileImageUrlUpload.ts:203-204`

```ts
const ext = ['jpg','jpeg','png','svg','gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? ... : 'jpg'
const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, ...)
```

The extension is taken from the URL string and `svg` is on the list, while the downloaded **content
is never inspected**. Point the endpoint at `https://attacker.example/x.svg` serving an SVG with an
embedded `<script>`, and the file lands at `/assets/public/images/uploads/<id>.svg`, served from the
application's own origin. Rendering it in an `<img>` is harmless; navigating directly to that URL
executes the script same-origin.

Worth contrasting with the sibling handler `routes/profileImageFileUpload.ts:24-33`, which does the
right thing (magic-byte sniffing via `file-type`, `image/*` prefix check). The two upload paths
disagree about what "an image" means.

The SSRF hardening in this file is otherwise thorough. Two residual gaps: the guard resolves DNS
(`resolveOutboundTarget`, line 120) and then `fetch` resolves **again** (line 147), leaving a
DNS-rebinding window; and there is no cap on the response body size, so a large remote file writes
unbounded bytes to disk.

### H10. Passwords are sent and logged in a URL query string
`frontend/src/app/Services/user.service.ts:54`, `routes/changePassword.ts:13-14`, `server.ts:335`

```ts
this.http.get(this.hostServer + '/rest/user/change-password?current=' + passwords.current + '&new=' + ...)
```

The current and new password travel as GET query parameters. `morgan('combined')` writes the full
request line to `logs/access.log`, so both plaintext passwords are persisted to disk on every
password change, and they also land in browser history and any intermediate proxy log. (CWE-598.)

### H11. Unsafe YAML deserialization on an attacker-supplied upload
`routes/fileUpload.ts:229`, `package.json` (`"js-yaml": "^3.14.0"`)

```ts
const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
```

In js-yaml **v3**, `load()` uses the full schema and honours `!!js/function`, `!!js/regexp` and
friends — the safe entry point in v3 is `safeLoad()`. The manifest pins the v3 range, so a Docker
build gets a loader that will construct functions from uploaded YAML. `vm.createContext` is not a
security boundary and does not help here. (The locally installed tree reports a different version —
see C2 — which is exactly why this is hard to reason about.)

The alias/expansion budget guards above it (lines 19-58) are a genuinely good defence against YAML
bombs; they just do not address the deserialization type problem.

### H12. Individually aged dependencies

The drift problem itself is C2; these declarations warrant attention regardless of which tree wins:
`express-jwt@0.1.3` (pre-6.0, carries no algorithm restriction of its own — the CVE-2020-15084
class, mitigated here only by the bolt-on `hasAcceptedAlgorithm` check at `lib/insecurity.ts:73`),
`libxmljs2 ~0.37.0`, `multer 1.x`, `marsdb` (unmaintained; backs the `$where` evaluation in M16),
`socket.io@^3.1.2`, `helmet@^4.6.0`, and `notevil@1.3.3` — declared at `package.json:140` but
imported nowhere in the codebase, so it is attack surface shipped for no reason. Remove it.

### H13. `jwt.verify`'s algorithm restriction is a no-op on the installed version
*(Same root cause as C2 — resolved by a correct install from the manifest. Recorded separately
because the misleading comment survives the upgrade.)*
`lib/insecurity.ts:282-286`

```ts
// The accepted algorithm is pinned here as well as in the header check above, so the
// verifier can never be talked into treating the public key as an HMAC secret.
jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err, decoded) => {
```

The comment asserts a second, independent layer of defence that does not exist. Verified against the
installed `jsonwebtoken@0.4.0` (`node_modules/jsonwebtoken/index.js:33-40`):

```js
module.exports.verify = function(jwtString, secretOrPublicKey, options, callback) {
  if (!options) options = {};
  try { valid = jws.verify(jwtString, secretOrPublicKey); }   // two-arg form
```

The `options` object is accepted and then never read for algorithm purposes, and `jws.verify` is
called in its **two-argument** form — the form that reads the algorithm out of the token's own
header. That is precisely the algorithm-confusion primitive (`alg: none`, or HS256 signed with the
RSA public key published at `/encryptionkeys/jwt.pub`) that the rest of this file works to prevent.

The only thing actually pinning the algorithm on this path is the `hasAcceptedAlgorithm(token)`
call on line 282. It is sufficient today, but the defence is one line deep while the code and its
comment claim it is two, so an edit that removes the pre-check would look safe and would reopen
full token forgery.

### H14. `/file-upload` is unauthenticated and the type check never rejects
`server.ts:306`, `routes/fileUpload.ts:166-179`

```ts
app.post('/file-upload', uploadToMemory.single('file'), ensureFileIsPassed, ..., checkUploadSize, checkFileType, handleZipFileUpload, ...)

function checkFileType ({ file }, res, next) {
  const fileType = file?.originalname.substr(...)
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => { return !(fileType === 'pdf' || ...) })
  next()   // <- always
}
```

`checkUploadSize` and `checkFileType` are named like guards but neither one blocks: both record a
condition and call `next()` unconditionally. Any anonymous caller can push any file type through
this pipeline.

### H15. Zip extraction is unbounded and leaks temp directories
`routes/fileUpload.ts:111-164`

The path-containment work here is excellent — name validation, lexical prefix check, `realpath` on
the parent, and `O_NOFOLLOW` on the open. Three things it does not cover:

- No cap on entry count or on **decompressed** size, so a decompression bomb can fill the disk.
- `fs.mkdtempSync(...)` (line 121) creates a fresh temp directory per upload that is never removed —
  unbounded disk growth from an unauthenticated endpoint (H14).
- `res.status(204).end()` (line 160) fires while extraction is still running, so extraction errors
  reach a response that has already been sent.

---

## Medium

### M1. Free deluxe membership via a missing wallet, and the card is never charged
`routes/deluxe.ts:32-48`

```ts
const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
if ((wallet != null) && wallet.balance < 49) { ...reject... } else {
  await WalletModel.decrement({ balance: 49 }, { where: { UserId: req.body.UserId } })
}
```

If the user has **no wallet row**, `wallet == null` sends control into the `else`, the decrement
affects zero rows, and the upgrade proceeds free. Wallet creation is fire-and-forget with a
swallowed error (`server.ts:526-528`), so a missing row is reachable. The `card` branch validates
ownership and expiry but never charges anything either — a valid unexpired card is sufficient.

Line 52's `freeDeluxeChallenge` condition (`paymentMode !== 'wallet' && !== 'card'`) is now dead
code, since those values are rejected above.

### M2. Wallet top-up credits without charging
`routes/wallet.ts:27-48` — the amount is validated (0 < amount ≤ 1000, finite) and card ownership is
checked, but no charge is issued. Repeat the call for unlimited balance.

### M3. Login has no rate limit and ignores `isActive`
`server.ts:611`, `routes/login.ts:32-56`, `models/user.ts:111`

`/rest/user/reset-password` and the 2FA routes get `rateLimit` middleware; `/rest/user/login` gets
none. The login query also filters only on `email`, `password` and `deletedAt` — the `isActive`
column is never consulted, so a deactivated account can still authenticate.

### M4. Vowel-masked email used as an identity key
`routes/orderHistory.ts:16-17`, `routes/dataExport.ts:22`, `routes/chat.ts:174-178`

```ts
const updatedEmail = email.replace(/[aeiou]/gi, '*')
const order = await ordersCollection.find({ email: updatedEmail })
```

A lossy transform is being used as a lookup key. `abc@x.com` and `ebc@x.com` both mask to
`*bc@x.c*m`, so two accounts that differ only in vowels see each other's orders. `dataExport.ts`
noticed this and added an order-id prefix filter (line 39-43); `orderHistory` and the chatbot's
`getOrderById` did not. Registering a vowel-variant of a target address is trivial.

### M5. Data-erasure POST has no CSRF protection and never verifies the answer
`routes/dataErasure.ts:73-111`

The handler authenticates from `req.cookies.token` alone. Unlike `/profile` and `/profile/image/*`
(`server.ts:307-308,690`), it is **not** wrapped in `security.sameOriginOnly()`, so a cross-site form
post can file an erasure request for a logged-in visitor. It also collects `securityAnswer` from the
form and never checks it against anything.

### M6. JSONP on an endpoint that returns user data
`routes/currentUser.ts:59-64`

```ts
if (req.query.callback === undefined) { res.json(response) } else { ...; res.jsonp(response) }
```

Express escapes the callback name, and the session cookie is `SameSite=Strict`, so this is not
directly exploitable today — but it is a legacy cross-origin data-exfiltration primitive on the
"who am I" endpoint, kept alive only to satisfy a challenge check.

### M7. Unvalidated `Range` header and a `throw` inside an fs callback
`routes/videoHandler.ts:24-29,52`

```ts
const start = parseInt(parts[0], 10)
const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1
const file = fs.createReadStream(path, { start, end })
...
fs.readFile('views/promotionVideo.pug', async function (err, buf) { if (err != null) throw err
```

`Range: bytes=abc-` yields `NaN`; a start beyond EOF or a negative value is never rejected, and no
416 is returned. Separately, `throw err` inside an asynchronous fs callback is not catchable by the
Express error handler and will terminate the process — a one-request denial of service if the
template is ever unreadable.

### M8. Unbounded cache keyed on user input
`routes/vulnCodeFixes.ts:20-45`

`readFixes(key)` writes `CodeFixes[key] = { fixes: [], correct: -1 }` for **every** key it is asked
about, including keys that match nothing. `GET /snippets/fixes/<random>` in a loop grows the object
without limit. Each uncached call also does a synchronous `fs.readdirSync` on the request path.

### M9. Slash-collapsing middleware rewrites query strings
`server.ts:202-205`

```ts
req.url = req.url.replace(/[/]+/g, '/')
```

The regex is applied to the whole URL, query string included, so on a plain reading
`?to=https://github.com/juice-shop/juice-shop` reaches the handler as `https:/github.com/...`, and
since `isRedirectAllowed` does an exact-string match against the allowlist
(`lib/insecurity.ts:189-195`), no legitimate `/redirect` target could ever match.

**Not confirmed** — I could not settle statically whether `req.query` is parsed before or after this
reassignment, and this middleware is inherited from upstream where the redirect flow reportedly
works, which is evidence against the reading. Worth one manual request to `/redirect?to=<allowlisted>`
to settle it. If it does reproduce, every other parameter carrying a URL is corrupted the same way.

### M10. Whole configuration served unauthenticated
`routes/appConfiguration.ts:11-15` — `config.util.toObject(config)` with only `llmApiUrl` removed.
Everything else in `config/*.yml` is public, including OAuth client ids and challenge parameters.
An allowlist of client-needed keys would be safer than a denylist of one.

### M10b. The quarantine exclusion is written in a syntax the router may not support
`server.ts:269-270`

```ts
app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
app.use('/ftp/quarantine/:file', serveQuarantineFiles())
```

The intent is "serve `/ftp/<file>` through the allowlisted handler, except under `/ftp/quarantine`".
But Express 4 compiles path strings with path-to-regexp 0.1.7, which has no negative-lookahead
support — `(?!/quarantine)` is not a lookahead there, it is parsed as an ordinary group. Depending
on how it compiles, the first route may match quarantine paths (subjecting them to the `.md`/`.pdf`
allowlist, which would be harmless) or may fail to match paths it should handle.

I could not determine the compiled behaviour by reading alone, so this is unconfirmed — but it is
load-bearing for M11, and a route whose exclusion clause is written in unsupported syntax should not
be left to chance. Replace it with an explicit handler check.

### M10c. `/api/Quantitys/:id` is permanently unreachable
`server.ts:443`

```ts
app.use('/api/Quantitys/:id', security.isAccounting(), IpFilter(['123.456.789'], { mode: 'allow' }))
```

`123.456.789` is not a valid IPv4 address — no octet may exceed 255, and there are only three. With
`mode: 'allow'`, everything not on the list is denied, so the list being unmatchable means the route
denies every caller, including a legitimately authenticated accounting user. The `isAccounting()`
check in front of it can therefore never matter. Either the filter is vestigial and should be
removed, or the allowlist is wrong and quantity management is silently broken in production.

### M11. File servers without extension allowlists
`routes/keyServer.ts:13-14`, `routes/quarantineServer.ts:13-14`

Both serve any file present in their directory (`encryptionkeys/`, `ftp/quarantine/`) with only a
forward-slash check. `servePublicFiles` next door has an allowlist and a null-byte check; these two
do not. Anything that ever lands in those directories becomes public.

`routes/logfileServer.ts` is dead code — nothing mounts it — but it has the same shape and would
expose `logs/` (which, per H10, contains passwords) if re-enabled.

### M12. "Private" assets protected only by an obscure path
`routes/easterEgg.ts`, `routes/privacyPolicyProof.ts`

Both `sendFile` out of `assets/private/` with no authorization check. `routes/premiumReward.ts:16`
was fixed to require `isDeluxe`; these two were left as URL-guessing games. Inconsistent treatment of
the same asset class.

### M13. Double `next()` and response-after-next in the upload chain
`routes/fileUpload.ts:181-214,216-251`

`handleXmlUpload` calls `next(new Error(...))` inside the `.xml` branch and then falls through to an
unconditional `next()` on line 213. `handleYamlUpload` does the same and then calls
`res.status(204).end()` on line 250 after having passed an error to `next`. Both produce
double-dispatch and "headers already sent" behaviour.

### M14. Token rotation leaves the old token valid, and flips the cookie's `httpOnly`
`routes/updateUserProfile.ts:36-40`

```ts
const updatedToken = security.authorize(userWithStatus)
security.authenticatedUsers.put(updatedToken, userWithStatus)
res.cookie('token', updatedToken, { httpOnly: true, sameSite: 'strict', secure: req.secure })
```

The previous token is never removed from `tokenMap`, so profile updates accumulate permanently valid
credentials — permanently so on the installed tree, where tokens carry no expiry; on a correct
install from the manifest this reduces to a memory leak plus a six-hour revocation gap (see C2).
Also, `insecurity.ts:289-293` deliberately sets this cookie
**without** `httpOnly` because the client clears it on logout; this handler sets `httpOnly: true`.
After one profile update the client can no longer clear its own session cookie, which is precisely
the failure the other comment warns about. `routes/deluxe.ts:57` mints a third token the same way.

### M15. `lastLoginTime` is computed with an operator-precedence bug
`routes/authenticatedUsers.ts:21`

```ts
lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken?.iat ?? 0 * 1000).getTime()) : null
```

`0 * 1000` binds before `??`, so the expression is `(parsedToken?.iat ?? 0)` and the `* 1000` never
applies to `iat`. A seconds-epoch value is then handed to `new Date()`, which expects milliseconds,
giving a timestamp in January 1970. `doesUserHaveAnActiveSession`
(`administration.component.ts:147-150`) therefore always reports "no active session" and the admin
table's session colouring is always wrong.

### M16. `$where` JavaScript evaluation, and reviewer emails disclosed
`routes/showProductReviews.ts:40`, `routes/chat.ts:158`

```ts
db.reviewsCollection.find({ $where: 'this.product == ' + id })
```

The injection itself is closed — `id` is coerced with `Number()` first — but building a query out of
string concatenation into an evaluated `$where` clause is a pattern one refactor away from being
exploitable again; a plain `{ product: id }` selector would be equivalent and inert. The response
also includes each review's full `likedBy` array, disclosing the email address of every user who
liked a product to any anonymous caller.

### M17. Restore paths for coding challenges are weaker than the main one
`routes/restoreProgress.ts:70` vs `:100,125`

`restoreProgress` requires that decoded ids are both *known* and *already solved*.
`restoreProgressFindIt` and `restoreProgressFixIt` check only *known*. If the per-process hashids
salt is ever recovered, the two coding-challenge paths can be made to mint progress the main path
would refuse. (Line 73's `ids.includes(999)` is unreachable for the same reason the main path is
safe — 999 is not a known challenge id — so `continueCodeChallenge` can no longer be solved.)

### M18. `document.write` of user-controlled export data
`frontend/src/app/data-export/data-export.component.ts:71`

```ts
window.open('', '_blank', 'width=500')?.document.write(this.userData)
```

`userData` is the JSON export containing `username`, review `message` and memory `caption` — none of
which are HTML-escaped, and review messages and memory captions are not sanitized on write either
(`routes/createProductReviews.ts:24-30`, `routes/memory.ts:12-17`). A blank `window.open` inherits
the opener's origin, so script in that string executes same-origin. Mostly self-inflicted (you export
your own data), but it is a live sink.

### M19. Client-side guards decode the token without verifying it
`frontend/src/app/app.guard.ts:33-60`

`AdminGuard` and `AccountingGuard` read `payload.data.role` from `jwtDecode(localStorage.token)`.
Any user can hand-edit a token to reach the admin UI. The server-side `isAdmin` does verify, so this
is a defence-in-depth gap rather than a bypass — worth noting because the comment at
`lib/insecurity.ts:221-223` cites exactly this guard as the reason the server-side check exists.

### M20. OAuth local password is derived from a non-secret identifier
`frontend/src/app/oauth/oauth.component.ts:74-84`

```ts
return btoa(encodeURIComponent(`${oauthPasswordScope}:${String(subject)}:${String(profile?.email ?? '')}`))
```

Much better than the previous `btoa(reverse(email))`, but the provider `sub`/`id` is not a secret —
it is handed to every client the user authorizes. Anyone who learns it can compute the local account
password and log in through the ordinary form. A server-generated random secret would remove the
class of problem entirely.

### M21. Untyped values flow into Sequelize `where` clauses
`routes/resetPassword.ts:35-40`, `routes/captcha.ts:68`, `routes/dataErasure.ts:33-38`

```ts
const data = await SecurityAnswerModel.findOne({ include: [{ model: UserModel, where: { email } }] })
```

`email` comes straight from the JSON body with no type check. `routes/securityQuestion.ts:18` does
the same lookup and coerces with `?.toString()`. Sequelize 6 no longer aliases string operators, so I
could not construct an exploit — but the inconsistency means the safety depends on an ORM default
rather than on the code, and one of the two call sites is clearly the intended pattern.

### M22. `eval()` in CAPTCHA generation
`routes/captcha.ts:22` — `const answer = eval(expression).toString()`. The expression is built from
server-side random values so it is not injectable, but `eval` on a generated arithmetic string is
unnecessary; the three operators could be a lookup. `/rest/captcha` is also unauthenticated and
inserts a row per call, so it is a cheap way to grow the database.

### M23. Unauthenticated read of orders and recycle records by id
`routes/trackOrder.ts`, `routes/recycles.ts:11-28`

`trackOrder` is mounted with no auth (`server.ts:640`) and returns order contents for a guessable-ish
id. `getRecycleItem` returns any recycle row by integer id with no ownership check, disclosing the
associated `UserId` and `AddressId`.

### M24. Blanket CORS and missing transport/response headers
`server.ts:181-190`

```ts
app.options('*', cors()); app.use(cors())
// app.use(helmet.xssFilter());
```

`Access-Control-Allow-Origin: *` on the entire API. Credentials are not reflected and the session
cookie is `SameSite=Strict`, so this is not immediately exploitable, but it is a blanket grant with a
comment ("Allow everything!") acknowledging it. Also absent: any CSP on the Angular application
(only `/profile` sets one), HSTS, and `Referrer-Policy`. `errorhandler()` (`server.ts:702`) is
mounted unconditionally and returns stack traces.

---

## Low / best practice

- **`routes/search.ts:70`** — `next(error.parent)`. When `parent` is undefined this is `next()`,
  which *continues routing* instead of raising, silently swallowing the failure.
- **`routes/changePassword.ts:39`** — compares against `loggedInUser.data.password`, the cached
  session copy, which is not refreshed after a password change; an older session can keep
  re-authenticating with the previous password. No minimum length or strength check on `newPassword`.
- **`routes/changePassword.ts:27`** — `headers.authorization.substr('Bearer='.length)` hand-parses
  the header instead of using `utils.jwtFrom`, and accepts any scheme. `routes/orderHistory.ts:13`
  and `routes/dataExport.ts:18` use a third variant (`.replace('Bearer ', '')`). Three parsers for
  one header is a bug waiting to happen — consolidate on `utils.jwtFrom`.
- **Timing-unsafe secret comparisons** — `routes/checkKeys.ts:32`, `routes/captcha.ts:69`,
  `routes/imageCaptcha.ts:56`, `routes/resetPassword.ts:41`. Use `crypto.timingSafeEqual`.
- **No length limits on stored user strings** — review `message`, memory `caption`, feedback
  `comment`, `b2bOrder` body. `JSON.parse` on an unbounded `orderLinesData` (`routes/b2bOrder.ts:17`)
  is a cheap CPU/memory sink.
- **`views/dataErasureForm.hbs`** — `placeholder={{userEmail}}` is an **unquoted** HTML attribute.
  Handlebars escapes `=` so this is not currently injectable, but the safety is incidental; quote it.
- **Dead code and unreachable conditions** — `routes/logfileServer.ts` (unmounted),
  `routes/deluxe.ts:52`, `routes/restoreProgress.ts:73`, `routes/fileUpload.ts:143`
  (`solveIf(... absolutePath === path.resolve('ftp/legal.md'))` can never be true given the
  containment check above it), `notevil` in `package.json`.
- **`global.sleep`** (`routes/showProductReviews.ts:18-29`) is a neutered stub kept only so that
  references resolve. Nothing references it — delete it rather than leaving a disarmed footgun.
- **Loose equality on security-relevant comparisons** — `routes/basketItems.ts:54,63,101`,
  `routes/order.ts:202`, `routes/verify.ts:32`, each with an `eslint-disable eqeqeq`.
- **`/metrics`** (`server.ts:749`) is readable by any authenticated user and includes default Node
  process metrics.
- **Secrets copied into the Docker image** — `Dockerfile:2` `COPY . /juice-shop` brings `ctf.key`,
  `encryptionkeys/`, and all of `config/`. `.dockerignore` correctly excludes `.git/`.
- **`app.enable('trust proxy')`** (`server.ts:339`) with no trusted-proxy list means `req.ip` is
  attacker-controlled via `X-Forwarded-For`. `routes/captcha.ts:75` already works around this by
  using `req.socket.remoteAddress`; the rate limiters on `/rest/user/reset-password` and the 2FA
  routes do not, so their per-IP limits can be evaded with a spoofed header.
- **Unused parameters** — `next` in `routes/likeProductReviews.ts:40`, `routes/orderHistory.ts:26`,
  `query` in `routes/fileServer.ts:16` and `routes/quarantineServer.ts:10`, `req` in several others.
- **`utils.ts:44`** — `contains()` carries a TODO saying it adds nothing over `String.includes`.
  It is called ~40 times; the indirection hides the `str ? ... : false` null-guard, which is the only
  reason it still exists.
- **`data/datacreator.ts:300-313`** — generated user passwords are `makeRandomString(5)`: five
  characters from a 62-symbol alphabet drawn with `Math.random()`. That is ~30 bits from a
  non-cryptographic PRNG. `numberOfRandomFakeUsers` is `0` in `config/default.yml` so none are
  created by default, but any deployment that raises it seeds trivially guessable accounts.
- **`lib/accuracy.ts:41-51`** — `totalAccuracy()` returns `sumAccuracy / totalSolved`, which is
  `NaN` when nothing has been solved. That value is fed straight into
  `accuracyMetrics.set(...)` on every 5-second tick of the metrics loop (`routes/metrics.ts:190-191`).
- **`lib/accuracy.ts:53-56`** — `calculateAccuracy` dereferences `solves[challengeKey][phase]` with
  no existence check. Every current caller happens to run `storeVerdict` first, so it is safe today
  purely by call ordering.

---

## Suggested order of work

1. **C2 first, before anything else is re-tested.** Run a clean `npm ci` from a committed lockfile
   and re-verify. Until the tree is pinned, neither this report nor any re-test can distinguish
   "the code is wrong" from "the laptop is stale" — that ambiguity is what let a deliberate
   `jsonwebtoken` upgrade sit un-applied for the whole review.
2. **C1** — nothing else matters while the signing key is public. Generate it at startup or load it
   from the environment, and rotate. Every authorization control in the app depends on this one
   secret.
3. **C3, C4** — add the ownership check to `placeOrder`; invert the two basket guards so a missing
   session fails closed rather than open.
4. **H3, H4, H5** — sign coupons server-side and enforce the discount ceiling at the point of
   minting, not in prompt text.
5. **H6, H7, H8** — move order PDFs out of `/ftp`; authenticate `/rest/memories`; stop broadcasting
   notifications to unauthenticated sockets.
6. **M9, M10b** — two unconfirmed findings that one live request each would settle. Do these while
   an instance is already running for the re-test in step 1.
