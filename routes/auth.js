const express = require("express");
const router = express.Router();
const db = require("../firebase");

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} = require("@simplewebauthn/server");

const { v4: uuidv4 } = require("uuid");

const rpName = "SecurePass";
const rpID = "localhost"; // change to your deployed domain
const origin = "http://localhost:5173"; // change to frontend deployed URL

// ================= REGISTER OPTIONS =================

router.post("/register/options", async (req, res) => {
  const { name, email } = req.body;

  const userRef = db.collection("users").doc(email);
  const userDoc = await userRef.get();

  let user;

  if (!userDoc.exists) {
    user = {
      id: uuidv4(),
      name,
      email,
      credentials: [],
    };
    await userRef.set(user);
  } else {
    user = userDoc.data();
  }

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: user.email,
    timeout: 60000,
    attestationType: "none",
  });

  await userRef.update({ currentChallenge: options.challenge });

  res.json(options);
});

// ================= REGISTER VERIFY =================

router.post("/register/verify", async (req, res) => {
  const { email, credential } = req.body;

  const userRef = db.collection("users").doc(email);
  const userDoc = await userRef.get();

  if (!userDoc.exists) return res.status(400).json({ error: "User not found" });

  const user = userDoc.data();

  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: user.currentChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
  });

  if (verification.verified) {
    const { credentialID, credentialPublicKey, counter } =
      verification.registrationInfo;

    // Store base64url values directly
    user.credentials.push({
      credentialID: credentialID,
      publicKey: credentialPublicKey,
      counter,
    });

    await userRef.update({ credentials: user.credentials });

    res.json({ verified: true });
  } else {
    res.status(400).json({ verified: false });
  }
});

// ================= LOGIN OPTIONS =================
router.post("/login/options", async (req, res) => {
  const { email } = req.body;

  const userRef = db.collection("users").doc(email);
  const userDoc = await userRef.get();

  if (!userDoc.exists) return res.status(400).json({ error: "User not found" });

  const user = userDoc.data();

  // Get registered credentials for this user
  const allowedCredentials = user.credentials.map((cred) => ({
    id: cred.credentialID,
    type: "public-key",
  }));

  const options = generateAuthenticationOptions({
    timeout: 60000,
    allowCredentials: allowedCredentials,
    userVerification: "preferred",
    rpID,
  });

  // Store challenge in Firestore for verification
  await userRef.update({ currentChallenge: options.challenge });

  res.json(options);
});

// ================= LOGIN VERIFY =================
router.post("/login/verify", async (req, res) => {
  const { email, credential } = req.body;

  const userRef = db.collection("users").doc(email);
  const userDoc = await userRef.get();

  if (!userDoc.exists) return res.status(400).json({ error: "User not found" });

  const user = userDoc.data();

  // Find credential from user credentials
  const dbCred = user.credentials.find((c) => c.credentialID === credential.id);

  if (!dbCred)
    return res.status(400).json({ error: "Credential not registered" });

  const verification = verifyAuthenticationResponse({
    response: credential,
    expectedChallenge: user.currentChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    authenticator: {
      credentialID: dbCred.credentialID,
      publicKey: dbCred.publicKey,
      counter: dbCred.counter,
    },
  });

  if (verification.verified) {
    // Update counter
    dbCred.counter = verification.authenticationInfo.newCounter;
    await userRef.update({ credentials: user.credentials });

    res.json({ verified: true });
  } else {
    res.status(400).json({ verified: false });
  }
});

module.exports = router;
