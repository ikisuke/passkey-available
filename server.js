/**
 * server.js
 * 例:
 *   npm init -y
 *   npm install express body-parser base64url @simplewebauthn/server
 *   node server.js
 */

const express = require("express");
const bodyParser = require("body-parser");
const base64url = require("base64url");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const { isoUint8Array } = require("@simplewebauthn/server/helpers");
const crypto = require("crypto");

const app = express();
app.use(express.static("public"));
app.use(bodyParser.json());

// 環境変数の設定
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ORIGIN || "http://localhost:3000";
const RPID = process.env.RPID || "localhost";

// 簡易的にメモリ上でユーザ情報を管理
const inMemoryDB = {
  // userId: { userName, credential: { ... }, savedCipher: { iv, ciphertext } }
};

//---------------------------------
// 1) ユーザ登録 (Credential Creation)
//---------------------------------
app.post("/register-start", async (req, res) => {
  const { userId, userName } = req.body;
  // 認証オプション生成
  // データベースで保存
  //     const prfKey = crypto.randomBytes(32);
  // generateRegistrationOptionsでWebAuthn登録用オプションを生成
  const options = await generateRegistrationOptions({
    rpName: "Passkey Demo",
    rpID: RPID,
    userID: isoUint8Array.fromUTF8String(userId),
    userName: userName,
    // HMAC-Secret拡張を有効化 (CTAP2レベルでhmac-secretを作成可能にする)
    //     authenticatorSelection: {
    //       authenticatorAttachment: "cross-platform",
    //     },
    extensions: {
      hmacCreateSecret: true,
      // prf: {},
      largeBlob: { support: "preferred" },
    },
  });
  console.log(options);

  // ユーザ情報を保存(この段階でDBに保存など)
  if (!inMemoryDB[userId]) {
    inMemoryDB[userId] = { userName, credential: null };
  }
  inMemoryDB[userId].currentChallenge = options.challenge;

  // フロントにオプション返却
  res.json(options);
});

app.post("/register-finish", async (req, res) => {
  const { userId, attResp } = req.body;
  const expectedChallenge = inMemoryDB[userId]?.currentChallenge;
  if (!expectedChallenge) {
    return res.status(400).send("No challenge found for this user.");
  }

  try {
    // 登録レスポンスの検証
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RPID,
      requireUserVerification: false,
    });
    const { registrationInfo } = verification;
    if (!registrationInfo) throw new Error("Cannot parse registrationInfo");

    // 登録成功なら認証器情報を保存
    inMemoryDB[userId].credential = {
      credentialID: registrationInfo.credential.id,
      credentialPublicKey: registrationInfo.credential.publicKey,
      counter: registrationInfo.credential.counter,
    };

    res.json({ status: "ok", userId });
  } catch (err) {
    console.error(err);
    return res.status(400).send("Registration failed");
  }
});

//---------------------------------
// 2) ログイン (Credential Request)
//---------------------------------
app.post("/login-start", async (req, res) => {
  const { userId } = req.body;
  console.log(userId);
  const userRecord = inMemoryDB[userId];
  if (!userRecord || !userRecord.credential) {
    return res.status(400).send("User not found or no credential registered.");
  }

  // 認証オプション生成
  //   const prfKey = crypto.randomBytes(32);
  const options = await generateAuthenticationOptions({
    allowCredentials: [
      {
        id: userRecord.credential.credentialID,
        type: "public-key",
      },
    ],
    // ここでHMAC-Secret拡張を再度要求。鍵が生成可能に。
    extensions: {
      hmacCreateSecret: true, // これは登録時に必要
      prf: {
        eval: {
          first: "114514",
        },
      },
      // 実際、認証時にはライブラリによっては特別な指定をしないケースもあるが、
      // 一部実装ではhmac-secret用の追加設定を行う可能性がある。
    },
  });

  userRecord.currentChallenge = options.challenge;
  res.json(options);
});

app.post("/login-finish", async (req, res) => {
  const { userId, authResp } = req.body;
  const userRecord = inMemoryDB[userId];
  if (!userRecord || !userRecord.credential) {
    return res.status(400).send("User not found or no credential registered.");
  }
  console.log("login-finish", userRecord);

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResp,
      expectedChallenge: userRecord.currentChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RPID,
      credential: {
        id: userRecord.credential.credentialID,
        publicKey: userRecord.credential.credentialPublicKey,
        counter: userRecord.credential.counter,
      },
    });

    const { authenticationInfo } = verification;
    if (!authenticationInfo) {
      throw new Error("Cannot parse authenticationInfo");
    }

    // カウンタ更新
    console.log("login-finish", userRecord.credential);
    userRecord.credential.counter = authenticationInfo.newCounter;
    // フロントでHMAC-Secretを利用する場合:
    //   -> ここではサーバではなくフロント( clientExtensionResults )側に
    //      HMAC-Secretの出力が載っている場合がある。(実装依存)
    //
    // ただし@simplewebauthn/serverはまだHMAC-Secretの結果パースを
    // 行わないことが多いので、このまま成功応答だけ返す。

    res.json({ status: "ok" });
  } catch (err) {
    console.error(err);
    return res.status(400).send("Authentication failed");
  }
});

//---------------------------------
// 3) 暗号文の保存
//---------------------------------
app.post("/save-ciphertext", (req, res) => {
  const { userId, iv, ciphertext } = req.body;
  const userRecord = inMemoryDB[userId];
  if (!userRecord) {
    return res.status(400).send("User not found.");
  }
  // DB等に保存
  userRecord.savedCipher = { iv, ciphertext };
  console.log("save-ciphertext", userRecord);
  res.json({ status: "ciphertext saved" });
});

//---------------------------------
// 4) 暗号文の取得
//---------------------------------
app.post("/get-ciphertext", (req, res) => {
  const { userId } = req.body;
  const userRecord = inMemoryDB[userId];
  if (!userRecord?.savedCipher) {
    return res.status(404).send("No ciphertext found for this user.");
  }
  res.json(userRecord.savedCipher);
});

//---------------------------------
// サーバ起動
//---------------------------------
app.listen(PORT, () => {
  console.log(`Listening at ${ORIGIN}`);
});
