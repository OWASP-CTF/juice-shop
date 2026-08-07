# Requirements Document

## Project Description (Input)
OWASP Top 10 2025 A01: Broken Access Control の観点で Juice Shop のコードベースを調査し、該当する脆弱性箇所を特定・修正計画を立てる。

調査済みの候補（ファイル:行、CWE番号付き）:

### 1. IDOR（不完全な直接オブジェクト参照チェック）
- `routes/basket.ts` の `retrieveBasket()`（`GET /rest/basket/:id`）: `server.ts:398` で `security.isAuthorized()` は適用されているが、これはJWTの有効性検証のみで、リクエストされたバスケットIDが認証済みユーザー自身のものかを検証していない。所有者チェック（`basket.ts:21-24`）はチャレンジ検知用のログにしか使われておらず、レスポンス返却をブロックしないため、basketIdを変えるだけで他ユーザーのバスケット内容を取得可能。(CWE-639)
- `routes/order.ts` の `placeOrder()`: `req.body.UserId` を信頼してウォレット残高を増減しており、他ユーザーのウォレットを操作可能。(CWE-639)
- `routes/updateProductReviews.ts`: レビュー著者チェックなしに誰でも他人のレビュー本文を書き換え可能。(CWE-639)
- `routes/trackOrder.ts`: 認証・所有者チェックなしに任意の `orderId` の注文情報を取得可能。(CWE-284)

### 2. 認可漏れ / Force Browsing
- `server.ts` の `/rest/admin/application-version`, `/rest/admin/application-configuration` に認可ミドルウェアが付与されていない。
- `routes/securityQuestion.ts`（`GET /rest/user/security-question`）: 未認証のままメールアドレスから秘密の質問を取得できる。(CWE-200 / CWE-284)
- `POST /api/Users` + `models/user.ts` の `role` セッター: リクエストボディの `role` フィールドに `admin` を指定して自己昇格できる（Mass Assignment）。(CWE-862)

### 3. CORS設定
- `server.ts` の `app.use(cors())` がオリジン制限なしで設定されている。(CWE-346)

### 4. JWT / セッション管理
- `lib/insecurity.ts` にRSA秘密鍵がハードコードされている。
- `express-jwt` が古いバージョン（0.1.3）で、`algorithms` オプションの明示的な指定がない。
- ログアウト時のサーバー側トークン失効（revocation）機構がなく、発行済みJWTは `exp` まで有効。(CWE-613)

### 5. Path Traversal / ファイル公開
- `routes/fileServer.ts`, `routes/logfileServer.ts`, `routes/quarantineServer.ts`: ファイル名検証が `includes('/')` のみで不十分。(CWE-22)
- `server.ts` の `/ftp`, `/.well-known`, `/encryptionkeys`, `/support/logs` がディレクトリリスティング付きで公開されている。(CWE-548 / CWE-538)

これらのうち、Juice Shop本来の「意図的なCTFチャレンジ実装」（`vuln-code-snippet` コメントや `challengeUtils.solveIf` を伴うもの）と、実運用コードとして本来修正すべき設計不備（CORS設定、JWTアルゴリズム指定、秘密鍵管理など）を区別しながら、要件定義から修正方針までをspec化する。

## Requirements
<!-- Will be generated in /kiro-spec-requirements phase -->
