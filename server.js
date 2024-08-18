const express = require('express');
const app = express();
const knex = require('knex')(require('./knexfile').development);
const cors = require('cors');
const crypto = require('node:crypto');
const base64url = require('base64url');
const bcrypt = require('bcrypt');
const path = require('path');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const jwt = require('jsonwebtoken');
const winston = require('winston');
require('dotenv').config();

const expectedOrigin = process.env.NODE_ENV === 'production' ? process.env.PROD_EXPECTED_ORIGIN : process.env.DEV_EXPECTED_ORIGIN;
const expectedRPID = process.env.NODE_ENV === 'production' ? process.env.PROD_EXPECTED_RPID : process.env.DEV_EXPECTED_RPID;


if(!global.crypto) {
    global.crypto = require('node:crypto');
}

const PORT = process.env.PORT||5002;

app.use(cors());
app.use(express.static(path.join(__dirname, './public')));
app.use(express.json());

const logger = winston.createLogger({
    level: 'info', // Log level
    format: winston.format.combine(
        winston.format.timestamp(), // Add timestamp to logs
        winston.format.printf(({ level, message, timestamp }) => {
            return `[${timestamp}] ${level}: ${message}`;
        }) // Custom log format
    ),
    transports: [
        new winston.transports.Console(), // Log to console
    ],
});

// Middleware to log incoming requests
app.use((req, res, next) => {
    logger.info(`Received a ${req.method} request for ${req.url}`);
    next(); // Proceed to the next middleware or route handler
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});


app.get('/health', (req, res) => {
    res.status(200).json({ status: "success", message: "I'm fine :)" });
});

app.post('/register', async (req, res) => {
    const { email, password, name } = req.body;
    const ifUserExists = await knex('b_users').where({ email }).first();
    if (ifUserExists) {
        return res.status(201).json({msg: "Already a User", data: ifUserExists});
    }
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

    const user = await knex('b_users').insert({ name, email, password: hashedPassword }).returning('*');
    res.status(201).json(user[0]);
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await knex('b_users').where({ email }).first();
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid password' });
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '5h' });
    return res.json({ token, user: {
        id: user.id,
        name: user.name,
    } });
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

    return res.json({ message: 'Verification success' });
});


app.post('/login-challenge/:email', async (req, res) => {
    const { email } = req.params;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const ifUserExists = await knex('b_users').where({ email }).first();
    if (!ifUserExists || !ifUserExists.challenge) {
        return res.status(404).json({ message: 'User not found or passkey not registered' });
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
            const token = jwt.sign({ id: ifUserExists.id }, process.env.JWT_SECRET, { expiresIn: '5h' });
            res.json({ 
                success: true,
                token,
                user: {
                    id: ifUserExists.id,
                    name: ifUserExists.name,
                },
            });
        } else {
            res.status(401).json({ success: false, error: 'Authentication failed' });
        }

    } catch (error) {
        console.error('Error verifying authentication:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/me', async (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token is required' });
    }
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        const user = await knex('b_users').where({ id: decoded.id }).first();
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        return res.json(user);
    });
});


app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});