# Requirements Document

## Project Description (Input)
A04-CryptGraphicFilures

## Introduction
本specは、OWASP Juice Shopのコードベースに対して事前調査で洗い出したOWASP Top 10 2025「A04: Cryptographic Failures」該当箇所（弱いハッシュアルゴリズム、ハードコードされた暗号鍵、JWT署名検証の不備、弱いPRNG、クーポン/トークンのエンコードと暗号化の混同、機密データの平文保存、クライアント側トークン保管）を、実際に修正するための要件を定義する。Juice Shopは意図的に脆弱性を組み込んだ学習・CTF用アプリケーションであり、各脆弱性は`models/challenge.ts`の名前付きチャレンジに対応しているため、修正がチャレンジの解答可能性に与える影響も要件として明示する。

## Boundary Context (Optional)
- **In scope**: 事前調査（本conversationで実施した`lib/insecurity.ts`, `lib/utils.ts`, `routes/*`, `models/*`, `data/static/users.yml`, `config/default.yml`, frontend `localStorage`利用箇所）で特定した7カテゴリの暗号関連の欠陥の修正方針の策定と実装
- **Out of scope**: 本specの調査で挙がっていない新規脆弱性の発見・A04以外のOWASPカテゴリ（アクセス制御、インジェクション等）の是正、UI/UXデザインの変更、パフォーマンスチューニング
- **Adjacent expectations**: 修正は`models/challenge.ts`に登録された既存チャレンジ（`weakPasswordChallenge`, `jwtUnsignedChallenge`, `jwtForgedChallenge`, `forgedCouponChallenge`, `twoFactorAuthUnsafeSecretStorageChallenge`等）の解答可能性に影響する可能性があるため、設計フェーズで各チャレンジの扱い（維持・別モード提供・廃止）を明示すること

## Requirements

### Requirement 1: パスワードハッシュの強化
**Objective:** As a セキュリティ担当者, I want ユーザーパスワードが強力な適応型ハッシュ関数でソルト付きで保存されること, so that パスワードデータベース漏洩時にも解読が困難になる

#### Acceptance Criteria
1. When 新規ユーザーが登録される, the 認証モジュール shall パスワードをソルト付きの適応型(work factorを持つ)ハッシュ関数でハッシュ化して保存する
2. When 既存ユーザーがログインする, the 認証モジュール shall 保存されているハッシュが新方式・旧方式(既存の脆弱なハッシュ方式)のいずれかを判別し、旧方式のユーザーには次回ログイン時に新方式へ移行する経路を提供する
3. If パスワードの比較処理が実行される, then 認証モジュール shall タイミング攻撃に対して安全な比較関数を使用する
4. The 認証モジュール shall パスワードハッシュ用途でMD5を使用しない

### Requirement 2: JWT鍵管理とアルゴリズム検証の強化
**Objective:** As a セキュリティ担当者, I want JWT署名鍵が安全に管理され、検証時に許可アルゴリズムが明示的に固定されること, so that 鍵漏洩やアルゴリズム混同攻撃によるトークン偽造を防止できる

#### Acceptance Criteria
1. The 認証モジュール shall JWT署名鍵(秘密鍵/公開鍵)をソースコードにハードコードせず、環境変数または鍵管理システムから読み込む
2. When JWTトークンを検証する, the 認証モジュール shall 許可する署名アルゴリズムを明示的に指定し、それ以外のアルゴリズムを受け付けない
3. If トークンのアルゴリズムヘッダが許可リスト外(`alg: none`や想定外の対称鍵アルゴリズム等)である, then 認証モジュール shall トークンを拒否する
4. If 鍵materialを含む静的ファイル配信ディレクトリへの一覧表示・不要ファイルの取得が要求される, then サーバー shall 当該ディレクトリの一覧表示を無効化し、公開が必要なファイルのみを個別に許可する
5. The 認証モジュール shall 同一の鍵material をJWT署名と`deluxeToken`のHMAC等、異なる暗号目的で再利用しない

### Requirement 3: 一方向ハッシュ・HMACアルゴリズムの是正
**Objective:** As a セキュリティ担当者, I want CTFフラグ生成やセキュリティ質問検証などのHMAC処理が非推奨アルゴリズムやハードコード鍵に依存しないこと, so that 署名偽造や衝突攻撃のリスクを排除できる

#### Acceptance Criteria
1. The CTFフラグ生成モジュール shall HMAC計算にSHA-1の代わりにSHA-256以上のアルゴリズムを使用する
2. The セキュリティ質問検証モジュール shall 回答検証用のHMAC鍵をソースコードのハードコード文字列ではなく、安全に管理された鍵から取得する

### Requirement 4: 安全な乱数生成の利用
**Objective:** As a セキュリティ担当者, I want セキュリティに関連する値がすべて暗号論的に安全な乱数生成器(CSPRNG)から生成されること, so that 値の予測によるバイパスを防止できる

#### Acceptance Criteria
1. The アクセス制御モジュール shall JWT検証を無効化する一時シークレット等のセキュリティ関連値に予測可能な擬似乱数生成器を使用せず、暗号論的に安全な乱数生成器(CSPRNG)を使用する
2. Where CAPTCHAがボット対策・セキュリティ制御として機能する場合, the CAPTCHA生成モジュール shall 予測可能性を低減するために暗号論的乱数を利用する

### Requirement 5: クーポン・トークンの完全性保護
**Objective:** As a セキュリティ担当者, I want クーポンコードや同様の生成トークンが署名によって保護されること, so that 攻撃者が任意の割引・特典を偽造できないようにする

#### Acceptance Criteria
1. When クーポンコードを発行する, the クーポン発行モジュール shall コード本体にHMACまたは同等の署名を付与する
2. When クーポンコードを検証・適用する, the クーポン適用モジュール shall 署名を検証し、署名が不正または改ざんされたコードを拒否する
3. The クーポン適用モジュール shall Base64/Z85等の可逆エンコードのみに依存した検証を行わない

### Requirement 6: 機密データの保管時暗号化
**Objective:** As a セキュリティ担当者, I want クレジットカード番号・TOTPシークレット・秘密の質問の回答などの機密データが保管時に暗号化・保護されること, so that データベース漏洩時の被害を最小化できる

#### Acceptance Criteria
1. The 決済情報モデル shall カード番号を平文の整数として保存せず、暗号化またはトークン化(マスキング表示用の下4桁を除く)した形式で保存する
2. The 二要素認証モジュール shall TOTPシークレットを暗号化して保存する
3. The 秘密の質問モジュール shall 回答を平文で保存せず、ハッシュ化または暗号化した形式で保存する
4. Where 設定管理システムに機密性の高い既定回答・秘密情報が含まれる場合, the 設定管理プロセス shall 当該値をリポジトリから排除し、必要に応じて環境変数や鍵管理システムへ移行する

### Requirement 7: クライアント側トークン保管の見直し
**Objective:** As a セキュリティ担当者, I want 認証トークンがXSSによる窃取リスクを低減する方法で保管されること, so that クロスサイトスクリプティングが発生した際の影響範囲を限定できる

#### Acceptance Criteria
1. The フロントエンド認証モジュール shall 認証トークンを、クライアント側スクリプトから読み取り不能な保管方法で管理する
2. If 既存のクライアント側スクリプトから読み取り可能なトークン保管に依存するコードが残存する, then 移行計画 shall 影響を受けるコンポーネントを明示し、置き換え方針を定める

### Requirement 8: 修正によるCTFチャレンジ整合性の確認
**Objective:** As a Juice Shop保守者, I want 暗号関連の修正が既存のCTF/チャレンジ機構に与える影響を把握できること, so that チャレンジの解答不能化や意図しない誤動作を防止できる

#### Acceptance Criteria
1. When 暗号関連の修正を適用する, the 開発プロセス shall `models/challenge.ts`内の関連チャレンジ(`weakPasswordChallenge`, `jwtUnsignedChallenge`, `jwtForgedChallenge`, `forgedCouponChallenge`, `twoFactorAuthUnsafeSecretStorageChallenge`等)への影響を洗い出す
2. If 修正によって特定のチャレンジが解答不能になる, then 設計フェーズ shall 当該チャレンジの扱い(維持・別モードでの提供・非推奨化)について明示的な方針を定める
