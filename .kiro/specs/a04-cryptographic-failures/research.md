# Research & Design Decisions

---
**Purpose**: requirements.md(8要件)とJuice Shop既存コードベースとのGap Analysis。design.md作成前の情報収集結果であり、実装方針の決定ではない(`.kiro/settings/rules/gap-analysis.md`の"Information over Decisions"原則に従う)。
---

## Summary
- **Feature**: `a04-cryptographic-failures`
- **Discovery Scope**: Extension(既存の脆弱な実装を安全な実装に置き換える。新規機能追加ではない)
- **Key Findings**:
  - Requirement 2(JWTアルゴリズム固定)が最大の技術的制約: `express-jwt@0.1.3` / `jsonwebtoken@0.4.0` / `jws@0.2.6` はいずれも`algorithms`許可リストオプションを一切サポートしない古いバージョンであり、設定変更では実現不可能。ライブラリのメジャーアップグレード、またはトークンヘッダを事前検査する自前ラッパーのいずれかが必要。
  - `jwtUnsignedChallenge`・`jwtForgedChallenge`はアルゴリズム固定を実装すると**恒久的に解答不能**になる(チャレンジの意図そのものがこの脆弱性の実演のため、想定内の結果)。
  - `test/server/insecuritySpec.ts`が`hash()`/`hmac()`/`generateCoupon()`の出力を**リテラル値で直接アサート**しており、Requirement 1・3・5の実装により機械的に破壊される。修正の一部として書き換えが必要(既存テストの破壊は想定内だが、設計フェーズで明示する必要がある)。
  - Requirement 6(カード番号暗号化)は専用の作成用routeが存在せず、`finale-rest`汎用CRUDが直接Sequelizeモデルに書き込むため、`models/card.ts`にSequelizeのgetter/setterを追加する以外の介入点がない。
  - Requirement 7(localStorage→安全な保管)は影響範囲が想定より大きい: すでに非`httpOnly`のCookieを`ngy-cookie`経由でクライアント側から並行して書き込む仕組みが実装済みだが、`httpOnly`/`secure`/`sameSite`フラグが一切設定されていない。真の修正は「保管先の変更」ではなく「認証方式のサーバー主導への転換+CSRF対策の追加」に近い規模になる。

## Research Log

### Requirement 1: パスワードハッシュの強化
- **Context**: `lib/insecurity.ts:43` の `hash()`(MD5・無ソルト)を安全な適応型ハッシュに置き換える。
- **Findings**:
  - `hash()`はパスワード専用ではなく、注文ID生成(`routes/order.ts:40`, `routes/b2bOrder.ts:41`)、メールハッシュ表示(`routes/userProfile.ts:75`)、GDPRエクスポートファイル名(`routes/dataExport.ts:104`)にも汎用IDジェネレータとして使い回されている(Missing: パスワード専用関数とID生成専用関数の分離)。
  - パスワード用途の呼び出し元: `models/user.ts:77`(setter、書込時に無条件ハッシュ化)、`routes/login.ts:34`(生SQL文字列へ直接連結して比較)、`routes/changePassword.ts:39,54`、`routes/2fa.ts:107,152`。
  - `routes/login.ts:34`は認証チェック自体がSQL文の`=`比較で行われているため、bcrypt等の非決定的ハッシュに切り替える場合はSQL比較そのものを廃止し、アプリケーション側でユーザー取得後にハッシュ検証する必要がある(アーキテクチャ変更を伴うConstraint)。
  - `test/server/insecuritySpec.ts:191-197`はMD5の固定16進値を直接アサートしており、ソルト付き方式に変えると非決定的になるため必ず失敗する(既存テストの書き換えが前提)。
  - Node組込みの`crypto.scrypt`/`crypto.pbkdf2`(`node:crypto`は既に`lib/insecurity.ts`でimport済み)で新規依存なしに実装可能。`bcrypt`/`argon2`を選ぶ場合は新規依存追加が必要(Unknown: どちらを選ぶかは設計判断)。
- **Implications**: 移行ロジック(旧MD5ユーザーの検出・再ハッシュ)は`routes/login.ts`内の認証成功後、SQL比較を経ずに実行する必要がある。設計フェーズで「SQL比較の廃止」自体を決定事項として明記すべき。

### Requirement 2: JWT鍵管理とアルゴリズム検証の強化
- **Context**: ハードコードされたRSA秘密鍵、`algorithms`未指定のJWT検証、`/encryptionkeys`の公開、鍵の目的外流用(`deluxeToken`)。
- **Findings**:
  - `lib/insecurity.ts:22-23`: `publicKey`をファイルから読込・`privateKey`をソース直書き。
  - `lib/insecurity.ts:54-58,191`, `routes/verify.ts:119`: `expressJwt`/`jws.verify`/`jwt.verify`の呼び出し箇所(全て`algorithms`指定なし)。
  - `deluxeToken()`(`lib/insecurity.ts:151-154`)が`privateKey`をHMAC鍵として再利用。
  - `server.ts:276-278`, `routes/keyServer.ts:9-19`: `/encryptionkeys`ディレクトリの一覧表示・個別ファイル配信。
  - **重要な制約**: `node_modules`内の実バージョンを確認した結果、`express-jwt@0.1.3`・`jsonwebtoken@0.4.0`・`jws@0.2.6`は三者とも`algorithms`許可リストオプションを実装しておらず、`jws`は`jwa`経由で`"none"`アルゴリズムを含む全アルゴリズムをトークンヘッダから読み取って検証する。**設定変更では要件2-2/2-3を満たせない**。
  - 対応策は大きく2方向: (a) `jsonwebtoken`を現行メジャー(9.x系)・`express-jwt`を8.x系(ESM、API変更あり)にアップグレードする、(b) 既存の古いライブラリはそのまま維持し、`verify()`呼び出し前にトークンヘッダの`alg`を自前で検査する薄いラッパーを追加する。
  - `data/static/codefixes/directoryListingChallenge_1_correct.ts`(既存の「正解」コードフィックス)は`/encryptionkeys`の一覧表示を維持したまま`/ftp`のみ対処する内容になっている。Requirement 2-4(`/encryptionkeys`一覧表示の無効化)を実装すると、この既存の正解データと矛盾する(既存チャレンジの正解データとの整合性調整が必要)。
- **Implications**: 設計フェーズで(a)アップグレード方針か(b)自前ラッパー方式かを選択する必要がある。後者は依存追加なしで要件を満たせる可能性が高く、リスクが低い。

### Requirement 3: 一方向ハッシュ・HMACアルゴリズムの是正
- **Context**: CTFフラグ生成のSHA-1 HMAC、秘密の質問検証のハードコードHMAC鍵。
- **Findings**:
  - `lib/utils.ts:76-90`(`ctfFlag`)呼び出し元: `lib/challengeUtils.ts:48`(チャレンジ解答通知)、`lib/webhook.ts:30`(外部Webhook送信)。
  - `lib/insecurity.ts:44`(`hmac`、ハードコード鍵`'pa4qacea4VK9t9nGv7yZtwmj'`)呼び出し元: `models/securityAnswer.ts:43-48`(書込)、`routes/resetPassword.ts:41`(検証)。
  - `ctfFlag`のアルゴリズム変更は、外部CTFスコアリングプラットフォーム(Webhook経由)に対して既に発行済みのフラグ値との互換性を破壊する(稼働中のCTFインスタンスでは移行タイミングの検討が必要。本リポジトリはCTF開催前のセットアップであるため実害は低いと推定)。
  - `hmac()`の鍵はセキュリティ質問専用であり、他の鍵(JWT鍵等)との再利用はない。鍵の外部化(環境変数化)のみで解決でき、アルゴリズム自体(SHA-256)は変更不要。
  - `test/server/insecuritySpec.ts:199-205`がリテラルなHMAC値をアサートしており書き換えが必要。`test/api/security-answer.test.ts`はHTTPステータスのみを検証しており影響を受けない。
- **Implications**: Requirement3は比較的低リスク・低コスト(鍵の環境変数化+アルゴリズム変更、依存追加不要)。

### Requirement 4: 安全な乱数生成の利用
- **Context**: `denyAll()`のJWTシークレット、math CAPTCHA生成における`Math.random()`。
- **Findings**: `lib/insecurity.ts:55`、`routes/captcha.ts:14-19`(`routes/imageCaptcha.ts`は別実装で`svg-captcha`パッケージを使用、対象外)。両箇所とも`node:crypto`の`crypto.randomInt()`/`crypto.randomBytes()`で依存追加なしに置換可能。関連する既存テストは数値リテラルをアサートしておらず、破壊されるテストは確認されなかった(Low risk)。

### Requirement 5: クーポン・トークンの完全性保護
- **Context**: `generateCoupon`/`discountFromCoupon`(Z85エンコードのみ、署名なし)。
- **Findings**:
  - `lib/insecurity.ts:99-121`。呼び出し元: `routes/chat.ts:182`(正規発行)、`routes/order.ts:185,187`(検証・`forgedCouponChallenge`の判定条件)、`routes/coupon.ts:15`。
  - `routes/order.ts:190-210`に別系統のBase64+固定`campaigns`マップによるクーポン処理が存在し、Z85/HMAC変更の影響を受けない(対象外として明確化が必要)。
  - `test/server/insecuritySpec.ts:36-83`が`z85.encode()`を直接呼んで手作りのテストフィクスチャを構築しており、HMAC層を追加すると全て「未署名」として弾かれ約7件のアサーションが破壊される(書き換え必須)。
  - Cypressの`forgedCoupon`チャレンジテスト(`cypress.config.ts`の`GenerateCoupon`タスク、`test/cypress/e2e/basket.spec.ts:141`)は本物の`generateCoupon()`を呼ぶため、HMAC追加後も自動的に green のまま残る。一方で「プレイヤーが手動でクーポン文字列を偽造する」という本来の解答経路は暗号学的に不可能になる(チャレンジの意図は守られるが、自動テストの結果だけでは検知できない)。
- **Implications**: 設計フェーズで「`forgedCouponChallenge`は自動テスト上は緑のまま残るが、意図された手動解法は無効化される」という非対称な状態を明記する必要がある。

### Requirement 6: 機密データの保管時暗号化
- **Context**: カード番号(`models/card.ts`)、TOTPシークレット(`models/user.ts`)、秘密の質問回答(`models/securityAnswer.ts`、Requirement3と鍵管理を共有)。
- **Findings**:
  - カード番号: `models/card.ts:15-25,39-45`(`cardNum: INTEGER`、平文)。専用の作成routeが存在せず、`server.ts:437`の`finale-rest`汎用CRUD(`app.post('/api/Cards', security.appendUserId())`)がリクエストボディを直接永続化する。マスキングは`routes/payment.ts:31-32,57-58`の読込時のみ。
  - TOTPシークレット: `models/user.ts:33`(setter/getter変換なし、平文カラム)。書込は`routes/2fa.ts:129,162`。
  - 秘密の質問回答: 既にHMAC化済み(Requirement3参照)、一方向のため「復号」ではなく鍵管理の問題として扱う。
  - カード番号暗号化は`models/user.ts`のパスワードsetterと同じパターン(Sequelizeのsetter/getterで暗号化/復号を透過的に行う)が既存コードベースの慣習に合致する(`card.ts`にはまだこのパターンがない)。
  - フロントエンドのカード表示テスト(`frontend/src/app/order-summary/order-summary.component.spec.ts:144-146`等)はマスキング済みAPIレスポンスのみを検証しており、保管形式の変更による破壊は想定されない。
  - TOTPシークレットのテスト(`test/api/2fa.test.ts`)はAPI境界(平文input/output)のみを検証しており、DB行を直接検査するテストは存在しない→暗号化/復号が透過的であれば破壊されない。
- **Implications**: 3種の機密データいずれも「Sequelizeのgetter/setterで透過的に暗号化」という共通パターンで実装可能。新規依存は不要(`node:crypto`のAES-GCM等で対応可能)。

### Requirement 7: クライアント側トークン保管の見直し
- **Context**: `localStorage`への認証トークン保管。
- **Findings**:
  - `localStorage`読み書き箇所は20箇所以上(`login.component.ts`, `oauth.component.ts`, `two-factor-auth-enter.component.ts`, `payment.component.ts`, `request.interceptor.ts`, `app.guard.ts`, `navbar.component.ts`, `sidenav.component.ts`等)。
  - **既存の部分的な緩和策が判明**: `ngy-cookie`経由で`login.component.ts:108`等4箇所がクライアント側から`token`Cookieを並行して書き込んでいるが、`httpOnly`/`secure`/`sameSite`フラグは一切設定されていない。サーバー側`lib/insecurity.ts:188-201`の`updateAuthenticatedUsers()`も`res.cookie('token', token)`をフラグなしで発行している。
  - 真に安全な保管に切り替えるには、(1) `httpOnly`/`secure`/`sameSite`フラグをサーバー側Cookie発行に追加、(2) クライアント側の`localStorage`書込と`cookieService.put`書込を全て削除、(3) `request.interceptor.ts`の手動`Authorization`ヘッダ付与ロジックを削除(`httpOnly`Cookieは自動送信されるためJSからは不要かつ不可能)、(4) Cookie認証がambientになることに伴うCSRF対策の追加、が必要 — 単純な「保管先の付け替え」ではなくフロントエンド認証フロー全体の変更に近い規模。
  - 7件のCypressスペック(`restApi.spec.ts`, `profile.spec.ts`, `basket.spec.ts`, `changePassword.spec.ts`, `dataErasure.spec.ts`, `b2bOrder.spec.ts`, `noSql.spec.ts`)が`localStorage.getItem('token')`を読んで自前で`Authorization`ヘッダを組み立てており、`httpOnly`化後はJSから読めなくなるため書き換えが必要。
- **Implications**: Requirement7は本spec中最も影響範囲が広く、設計フェーズでのフロントエンド変更範囲の見積りが重要(Effort: L〜XL相当、他要件より大きい)。

### Requirement 8: 修正によるCTFチャレンジ整合性の確認
- **Findings**(チャレンジ単位):

  | チャレンジ | 解答判定の実体 | 本specの修正による影響 |
  |---|---|---|
  | `weakPasswordChallenge` | `routes/login.ts:60`: 提出されたemail/passwordの値のみを比較 | 影響なし(ハッシュアルゴリズムと無関係) |
  | `jwtUnsignedChallenge` | `routes/verify.ts:84-85,110-127`: `alg:"none"`トークンの検証成功を要求 | 恒久的に解答不能になる(Requirement2の目的そのもの) |
  | `jwtForgedChallenge` | `routes/verify.ts:87-88`: 公開鍵をHMAC鍵に転用した`alg:"HS256"`トークンの検証成功を要求 | 恒久的に解答不能になる(同上) |
  | `forgedCouponChallenge` | `routes/order.ts:187`: 割引率が80%以上かのみを判定、生成経路は見ていない | 自動テストはgreenのまま残るが、意図された手動偽造経路は暗号学的に閉じる |
  | `twoFactorAuthUnsafeSecretStorageChallenge` | `routes/2fa.ts:38`: 特定ユーザーでの2FAログイン完了のみを判定、保存形式は見ていない | 影響なし(チャレンジ名と実際の判定条件が乖離している) |
  | `resetPasswordBjoernOwaspChallenge` | `routes/resetPassword.ts:62`: 平文で提出された回答文字列を直接比較(HMAC照合は手前の`:41`で別途実施) | 鍵を書込/検証で一貫して移行すれば影響なし |
- **Implications**: `jwtUnsignedChallenge`・`jwtForgedChallenge`の2つは設計フェーズで「意図的に無効化する」ことを明示的な決定事項として記載する必要がある(黒魔術的に壊れるのではなく、既知のトレードオフとして)。

### Technology Verification(Light Discovery — Design Phase追加調査)
- **Context**: Requirement1(パスワードハッシュ)の具体アルゴリズム選定、Requirement2(JWT)のライブラリアップグレード可否について、設計フェーズ開始時に最新情報を確認。
- **Sources Consulted**: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [jsonwebtoken - npm](https://www.npmjs.com/package/jsonwebtoken), [HS256 reported as invalid algorithm? · Issue #988](https://github.com/auth0/node-jsonwebtoken/issues/988)
- **Findings**:
  - OWASP推奨は Argon2id(19MiB以上, iteration2以上, parallelism1以上) > scrypt(N=2^17以上, r=8, p=1) > bcrypt(cost12以上)の優先順。Node組込みの`crypto.scrypt`はOWASP推奨パラメータをそのまま指定可能で新規依存が不要。
  - `jsonwebtoken`は4.2.2以降、鍵の型(RSA/EC/secret)に応じたデフォルトアルゴリズム許可リストを持つよう修正されており(alg-confusion対策)、9.x系ではさらに`algorithms`オプションの明示指定がベストプラクティスとして強く推奨されている。現行の`jsonwebtoken@0.4.0`はこの修正より遥かに古い。
- **Implications**: Requirement1は`crypto.scrypt`(OWASP推奨パラメータ)を採用し新規依存を回避する。Requirement2は「自前ラッパーで`alg`を事前検査する(Option C)」を採用しつつ、将来的な`jsonwebtoken`メジャーアップグレードは本specのスコープ外(Out of Boundary)として明示する — アップグレードはAPI互換性の広範な影響評価を要するため、別スペックで扱うべき規模。

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| A: 既存関数を直接拡張 | `hash()`/`hmac()`/`generateCoupon()`等の実装本体だけを安全な実装に置き換え、シグネチャ・呼び出し元は変えない | 変更箇所が最小、既存パターンに追従 | パスワード用途と汎用ID生成用途が同じ`hash()`関数を共有している問題(Req.1)はOption Aだけでは解決しない | Requirement3・4・6は概ねこの方式で十分 |
| B: 新規コンポーネント作成 | パスワード専用の`hashPassword()`/`verifyPassword()`等を新設し、既存`hash()`は汎用ID生成用として残す | 責務分離が明確、既存の非パスワード用途を壊さない | 呼び出し元の書き換えが必要な箇所が増える | Requirement1(パスワード/ID生成の分離)、Requirement2(JWT検証ラッパー新設)に適する |
| C: ハイブリッド | 既存ライブラリ構成は維持しつつ、検証前チェックを行う薄いラッパーを追加 | 依存アップグレードのリスクを回避しながら要件を満たせる | ラッパーの抜け漏れがあれば脆弱性が再発するため設計の正確性が重要 | Requirement2(JWTアルゴリズム固定を自前ラッパーで実現)に有力 |

## Effort & Risk (要件ごと)

| 要件 | Effort | Risk | 根拠 |
|---|---|---|---|
| 1. パスワードハッシュ | M | Medium | 既存パターン(setter)は流用可能だが、`login.ts`のSQL比較廃止という構造変更を伴う |
| 2. JWT鍵管理・アルゴリズム | M〜L | High | 依存ライブラリが要件を構造的に満たせず、アップグレードか自前ラッパーかの選択が必要。チャレンジ2件の無効化判断も伴う |
| 3. HMAC/ハッシュ鍵管理 | S | Low | 鍵の環境変数化のみ、依存追加不要 |
| 4. CSPRNG | S | Low | 既存importで対応可能、影響テストなし |
| 5. クーポン完全性 | S〜M | Medium | 実装は小さいが既存テストの書き換えが約7件発生 |
| 6. 保管時暗号化 | M | Medium | 3箇所とも既存パターン(getter/setter)の横展開で対応可能 |
| 7. クライアント側トークン | L〜XL | High | 20箇所超の呼び出し元、CSRF対策追加を伴う認証フロー全体の変更 |
| 8. チャレンジ整合性確認 | S | Low(分析としては完了済み) | 上表の通り分析済み。設計への反映のみ残る |

## Risks & Mitigations
- **Requirement2のライブラリ制約**(`algorithms`オプション非対応) — 自前のヘッダ事前検査ラッパー(Option C)で依存アップグレードを回避、またはメジャーアップグレードの影響範囲を設計フェーズで別途評価する。
- **既存テストの機械的破壊**(`insecuritySpec.ts`のリテラル値アサート、複数要件で共通) — 設計フェーズでテスト書き換え自体をタスクとして明示し、「テストが落ちる」ことと「実装が壊れている」ことを区別する。
- **チャレンジの意図的な無効化**(`jwtUnsignedChallenge`/`jwtForgedChallenge`) — `models/challenge.ts`側で無効化フラグを立てる/challenges.ymlから除外する等、静かに壊すのではなく明示的に扱う。
- **Requirement7の影響範囲の広さ** — 一括対応ではなく、サーバー側Cookieのフラグ付与→クライアント側書込除去→interceptor改修の順に段階的実装を検討する。

## Recommendations for Design Phase
- Requirement1: Option B(パスワード専用ハッシュ関数の新設)を推奨。既存`hash()`は非パスワード用途のID生成関数として残す。
- Requirement2: Option C(自前アルゴリズム事前検査ラッパー)をまず検討し、依存アップグレードは別スコープとして切り出すかを設計フェーズで判断する。
- Requirement5・6: Option A(既存関数/既存setterパターンの直接拡張)で十分。
- Requirement7: 段階的実装(Cookieフラグ付与→クライアント書込除去→interceptor改修→CSRF対策)を設計に明記し、一括変更のリスクを避ける。
- Research Needed(設計フェーズで深掘り): (a) Requirement2のライブラリアップグレード可否の詳細調査、(b) Requirement7のCSRF対策の具体的な実装方式。

## References
- `.kiro/settings/rules/gap-analysis.md` — 本分析が従うフレームワーク
- `.kiro/specs/a04-cryptographic-failures/requirements.md` — 分析対象の8要件
