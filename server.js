const express = require('express');
const app = express();
const knex = require('knex')(require('./knexfile').development);
const cors = require('cors');
const crypto = require('node:crypto');
const base64url = require('base64url');
const bcrypt = require('bcrypt');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');
require('dotenv').config();

const expectedOrigin = process.env.EXPECTED_ORIGIN || 'http://localhost:5002';
const expectedRPID = process.env.EXPECTED_RPID||'localhost';

if(!global.crypto) {
    global.crypto = require('node:crypto');
}

const PORT = process.env.PORT||5002;

app.use(cors());
app.use(express.static('./public'));
app.use(express.json());


app.get('/h', (req, res) => {
    res.send("Hello World");
    res.send("<h1>I'm fine :)</h1>");
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const ifUserExists = await knex('b_users').where({ email }).first();
    if (ifUserExists) {
        return res.status(201).json(ifUserExists);
    }
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

    const user = await knex('b_users').insert({ email, password: hashedPassword }).returning('*');
    res.status(201).json(user[0]);
});

app.post("/register-challenge/:user_id", async (req, res) => {
    const { user_id } = req.params;
    if(!user_id) return res.status(400).json({ message: 'User ID is required' });
    const ifUserExists = await knex('b_users').where({ id: user_id
    }).first();
    if (!ifUserExists) {
        return res.status(404).json({ message: 'User not found' });
    }
    const challengePayload = await generateRegistrationOptions({
        rpID: expectedRPID,
        rpName: 'Trying out WebAuthn',
        userName: ifUserExists.email,
        userID: ifUserExists.id,
    });

    await knex('b_users').where({ id: user_id }).update({
        challenge: challengePayload.challenge,
    });

    return res.json({options: challengePayload});
});


app.post('/register-verify', async (req, res) => {
    const { user_id, cred } = req.body;
    const ifUserExists = await knex('b_users').where({ id: user_id }).first();
    
    if (!ifUserExists) {
        console.log('User not found');
        return res.status(404).json({ message: 'User not found' });
    }

    const { verified, registrationInfo } = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge: ifUserExists.challenge,
        expectedOrigin,
        expectedRPID,
    });

    if (!verified) {
        console.log('Verification failed');
        return res.status(401).json({ message: 'Verification failed' });
    }

    // Convert publicKey from Uint8Array to base64 string before storing
    const publicKeyBase64 = Buffer.from(registrationInfo.credentialPublicKey).toString('base64');

    // Store the credential ID and public key as base64 strings
    await knex('b_users').where({ id: user_id }).update({
        credential_id: registrationInfo.credentialID,
        public_key: publicKeyBase64, // Store as base64 string
        counter: 0, // Reset the counter
    });

    console.log('Verification success');
    return res.json({ message: 'Verification success' });
});


app.post('/login-challenge/:email', async (req, res) => {
    const { email } = req.params;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const ifUserExists = await knex('b_users').where({ email }).first();
    if (!ifUserExists) {
        return res.status(404).json({ message: 'User not found' });
    }

    let credentialId = ifUserExists.credential_id;

    // Generate authentication options
    const challengePayload = await generateAuthenticationOptions({
        rpID: expectedRPID,
        userVerification: 'preferred',
        allowCredentials: [{
            id: credentialId || null,
            type: 'public-key',
            transports: ['usb', 'ble', 'nfc', 'internal'],
        }],
    });
    
    await knex('b_users').where({ email }).update({
        challenge: challengePayload.challenge,
    });
    
    console.log('login challenge generated');
    return res.json({ options: challengePayload });
});

app.post('/login-verify', async (req, res) => {
    const { email, cred } = req.body;

    // Fetch user from the database
    const ifUserExists = await knex('b_users').where({ email }).first();
    if (!ifUserExists) {
        return res.status(404).json({ message: 'User not found' });
    }

    try {
        // Convert the public key from base64 string to a Buffer
        const publicKeyBuffer = base64url.toBuffer(ifUserExists.public_key);

        const verification = await verifyAuthenticationResponse({
            response: cred,
            expectedChallenge: ifUserExists.challenge,
            expectedOrigin,
            expectedRPID,
            authenticator: {
              credentialID: ifUserExists.credential_id,
              credentialPublicKey: publicKeyBuffer,
              counter: ifUserExists.counter,
              transports: ['usb', 'ble', 'nfc', 'internal'],
            },
          });

        if (verification.verified) {
            // Update the counter in the database if verification is successful
            await knex('b_users').where({ email }).update({
                counter: verification.authenticationInfo.newCounter, // Update with new counter
            });
            res.json({ success: true });
        } else {
            res.status(401).json({ success: false, error: 'Authentication failed' });
        }

    } catch (error) {
        console.error('Error verifying authentication:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});