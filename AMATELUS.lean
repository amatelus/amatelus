/-
# AMATELUSプロトコルの論理的完全性に関する形式的証明

このファイルは、AMATELUSプロトコルの形式証明のメインモジュールです。
-/

-- 暗号プリミティブ型定義
import AMATELUS.CryptoTypes

-- DID
import AMATELUS.DID

-- セキュリティ仮定
import AMATELUS.SecurityAssumptions

-- 暗号学的基盤の証明 (Theorem 3.1-3.5)
import AMATELUS.Cryptographic

-- 信頼連鎖メカニズムの証明 (Theorem 4.2, 4.4)
import AMATELUS.TrustChain

-- Wallet/Holder/Issuer/Verifier操作定義
import AMATELUS.Operations

-- 通信レイヤー定義
import AMATELUS.Network

-- 相互認証プロトコル（Verifier認証）
import AMATELUS.MutualAuthentication

-- マルチデバイス対応
import AMATELUS.MultiDevice

-- 失効確認フロー
import AMATELUS.RevocationMerkle

-- 秘密鍵ライフサイクル管理
import AMATELUS.KeyManagement

-- プライバシー保護機構の証明 (Theorem 5.1, 5.3)
import AMATELUS.Privacy

-- 監査メカニズムの証明 (Theorem 6.1, 6.2)
import AMATELUS.Audit

-- プロトコル全体の証明 (Theorem 7.1, 7.2, 8.1)
import AMATELUS.Protocol
