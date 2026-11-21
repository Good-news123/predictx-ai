import "dotenv/config";

import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { fileURLToPath } from "node:url";

import db from "./database.js";

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const APP_URL = process.env.APP_URL;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters.");
}

if (!PAYSTACK_SECRET_KEY) {
    throw new Error("PAYSTACK_SECRET_KEY is missing.");
}

if (!APP_URL) {
    throw new Error("APP_URL is missing.");
}

app.set("trust proxy", 1);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    }
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-7",
    legacyHeaders: false
});

const paymentLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false
});

// Paystack webhook must receive the raw body.
app.post(
    "/api/paystack/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        try {
            const signature = req.headers["x-paystack-signature"];

            if (!signature || !Buffer.isBuffer(req.body)) {
                return res.sendStatus(401);
            }

            const expected = crypto
                .createHmac("sha512", PAYSTACK_SECRET_KEY)
                .update(req.body)
                .digest("hex");

            const suppliedBuffer = Buffer.from(signature);
            const expectedBuffer = Buffer.from(expected);

            if (
                suppliedBuffer.length !== expectedBuffer.length ||
                !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
            ) {
                return res.sendStatus(401);
            }

            const event = JSON.parse(req.body.toString());

            if (event.event === "charge.success") {
                await verifyPayment(event.data.reference);
            }

            return res.sendStatus(200);
        } catch (error) {
            console.error("Webhook error:", error);
            return res.sendStatus(400);
        }
    }
);

app.use(express.json({ limit: "20kb" }));

app.use(express.static(path.join(__dirname, "public")));

const plans = {
    weekly: {
        amount: Number(process.env.PRICE_WEEKLY_NGN || 1500),
        duration: 7
    },
    monthly: {
        amount: Number(process.env.PRICE_MONTHLY_NGN || 5000),
        duration: 30
    },
    lifetime: {
        amount: Number(process.env.PRICE_LIFETIME_NGN || 25000),
        duration: null
    }
};

function createToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: "7d" }
    );
}

function authenticate(req, res, next) {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
        ? header.slice(7)
        : null;

    if (!token) {
        return res.status(401).json({ error: "Please log in." });
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: "Session expired. Log in again." });
    }
}

function getSubscription(userId) {
    const subscription = db.prepare(
        "SELECT * FROM subscriptions WHERE user_id = ?"
    ).get(userId);

    if (!subscription) return null;

    if (
        subscription.plan !== "lifetime" &&
        (!subscription.expires_at ||
         new Date(subscription.expires_at).getTime() <= Date.now())
    ) {
        db.prepare(
            "UPDATE subscriptions SET active = 0 WHERE user_id = ?"
        ).run(userId);

        return { ...subscription, active: 0 };
    }

    return subscription;
}

function accountResponse(userId) {
    const subscription = getSubscription(userId);

    return {
        subscription: subscription ? {
            plan: subscription.plan,
            active: Boolean(subscription.active),
            expires_at: subscription.expires_at
        } : null
    };
}

app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        service: "PREDICTX AI"
    });
});

app.get("/api/config", (req, res) => {
    res.json({
        currency: process.env.CURRENCY || "NGN",
        prices: {
            weekly: plans.weekly.amount,
            monthly: plans.monthly.amount,
            lifetime: plans.lifetime.amount
        },
        whatsappChannel: process.env.WHATSAPP_CHANNEL || "",
        whatsappAdmin: process.env.WHATSAPP_ADMIN || ""
    });
});


// ============================================
// FOOTBALL-DATA.ORG INTEGRATION
// ============================================

const footballCache = new Map();
const FOOTBALL_API = "https://api.football-data.org/v4";
const FOOTBALL_CACHE_TIME = 15 * 60 * 1000;

async function footballRequest(endpoint) {
    if (!process.env.FOOTBALL_DATA_TOKEN) {
        throw new Error("Football API token is not configured.");
    }

    const cached = footballCache.get(endpoint);

    if (cached && Date.now() - cached.time < FOOTBALL_CACHE_TIME) {
        return cached.data;
    }

    const response = await fetch(`${FOOTBALL_API}${endpoint}`, {
        headers: {
            "X-Auth-Token": process.env.FOOTBALL_DATA_TOKEN
        },
        signal: AbortSignal.timeout(12000)
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        const error = new Error(
            data.message || `Football API error: ${response.status}`
        );
        error.status = response.status;
        throw error;
    }

    footballCache.set(endpoint, {
        time: Date.now(),
        data
    });

    return data;
}

function validCompetition(code) {
    return /^[A-Z0-9]{2,5}$/.test(code || "");
}

function validDate(value) {
    return /^\d{4}-\d{2}-\d{2}$/.test(value || "") &&
        !Number.isNaN(Date.parse(value));
}

// Poisson probability calculation.
function poisson(lambda, goals) {
    let factorial = 1;

    for (let i = 2; i <= goals; i++) {
        factorial *= i;
    }

    return Math.exp(-lambda) * Math.pow(lambda, goals) / factorial;
}

function calculatePredictions(match, standingsData) {
    const homeId = match.homeTeam?.id;
    const awayId = match.awayTeam?.id;

    const table = standingsData.standings?.find(
        item => item.type === "TOTAL"
    )?.table || [];

    const home = table.find(row => row.team.id === homeId);
    const away = table.find(row => row.team.id === awayId);

    if (
        !home || !away ||
        home.playedGames < 3 ||
        away.playedGames < 3
    ) {
        return {
            available: false,
            reason: "Not enough league statistics for a reliable estimate."
        };
    }

    const homeAttack = home.goalsFor / home.playedGames;
    const homeDefence = home.goalsAgainst / home.playedGames;

    const awayAttack = away.goalsFor / away.playedGames;
    const awayDefence = away.goalsAgainst / away.playedGames;

    // Estimated goals, with a modest home advantage.
    const expectedHome = Math.max(
        0.15,
        ((homeAttack + awayDefence) / 2) * 1.10
    );

    const expectedAway = Math.max(
        0.15,
        ((awayAttack + homeDefence) / 2) * 0.90
    );

    const homeProb = [];
    const awayProb = [];

    for (let i = 0; i <= 6; i++) {
        homeProb[i] = poisson(expectedHome, i);
        awayProb[i] = poisson(expectedAway, i);
    }

    let homeWin = 0;
    let draw = 0;
    let awayWin = 0;
    let over25 = 0;
    let btts = 0;
    let bestScore = { score: "0-0", probability: -1 };

    for (let h = 0; h <= 6; h++) {
        for (let a = 0; a <= 6; a++) {
            const probability = homeProb[h] * awayProb[a];

            if (h > a) homeWin += probability;
            else if (h === a) draw += probability;
            else awayWin += probability;

            if (h + a > 2) over25 += probability;
            if (h > 0 && a > 0) btts += probability;

            if (probability > bestScore.probability) {
                bestScore = {
                    score: `${h}-${a}`,
                    probability
                };
            }
        }
    }

    const percent = value =>
        Math.round(value * 100);

    return {
        available: true,
        expectedGoals: {
            home: Number(expectedHome.toFixed(2)),
            away: Number(expectedAway.toFixed(2))
        },
        markets: {
            homeWin: percent(homeWin),
            draw: percent(draw),
            awayWin: percent(awayWin),
            over15: percent(1 - poisson(expectedHome + expectedAway, 0)
                - poisson(expectedHome + expectedAway, 1)),
            over25: percent(over25),
            under25: percent(1 - over25),
            bothTeamsToScore: percent(btts)
        },
        correctScore: bestScore.score,
        method: "League scoring statistics and Poisson estimates"
    };
}

// Get available competitions.
app.get("/api/football/competitions", async (req, res) => {
    try {
        const data = await footballRequest("/competitions");

        res.json({
            competitions: (data.competitions || []).map(item => ({
                id: item.id,
                name: item.name,
                code: item.code,
                area: item.area?.name,
                plan: item.plan
            }))
        });
    } catch (error) {
        console.error("Competitions error:", error.message);
        res.status(error.status || 502).json({
            error: error.message
        });
    }
});

// Get fixtures and predictions for a competition.
app.get("/api/football/predictions", async (req, res) => {
    try {
        const competition = String(req.query.competition || "PL");
        const today = new Date().toISOString().slice(0, 10);

        const dateFrom = req.query.dateFrom || today;

        const defaultEnd = new Date(
            Date.now() + 7 * 86400000
        ).toISOString().slice(0, 10);

        const dateTo = req.query.dateTo || defaultEnd;

        if (!validCompetition(competition)) {
            return res.status(400).json({
                error: "Invalid competition code."
            });
        }

        if (!validDate(dateFrom) || !validDate(dateTo) ||
            dateFrom > dateTo) {
            return res.status(400).json({
                error: "Invalid date range."
            });
        }

        const base = `/competitions/${competition}`;

        const [matchesData, standingsData] = await Promise.all([
            footballRequest(
                `${base}/matches?dateFrom=${dateFrom}&dateTo=${dateTo}`
            ),
            footballRequest(`${base}/standings`)
        ]);

        const matches = (matchesData.matches || []).map(match => ({
            id: match.id,
            competition: match.competition?.name,
            utcDate: match.utcDate,
            status: match.status,
            homeTeam: {
                id: match.homeTeam?.id,
                name: match.homeTeam?.name,
                crest: match.homeTeam?.crest
            },
            awayTeam: {
                id: match.awayTeam?.id,
                name: match.awayTeam?.name,
                crest: match.awayTeam?.crest
            },
            score: match.score?.fullTime || null,
            prediction: match.status === "SCHEDULED"
                ? calculatePredictions(match, standingsData)
                : null
        }));

        res.json({
            competition: competition,
            dateFrom,
            dateTo,
            count: matches.length,
            matches
        });

    } catch (error) {
        console.error("Prediction error:", error.message);

        res.status(error.status || 502).json({
            error: error.message
        });
    }
});

// Get actual league standings.
app.get("/api/football/standings", async (req, res) => {
    try {
        const competition = String(req.query.competition || "PL");

        if (!validCompetition(competition)) {
            return res.status(400).json({
                error: "Invalid competition code."
            });
        }

        const data = await footballRequest(
            `/competitions/${competition}/standings`
        );

        const total = data.standings?.find(
            item => item.type === "TOTAL"
        );

        res.json({
            competition: data.competition,
            table: total?.table || []
        });

    } catch (error) {
        console.error("Standings error:", error.message);

        res.status(error.status || 502).json({
            error: error.message
        });
    }
}):

// Register
app.post("/api/register", authLimiter, async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: "Enter a valid email." });
        }

        if (password.length < 8 || password.length > 72) {
            return res.status(400).json({
                error: "Password must contain 8 to 72 characters."
            });
        }

        const existing = db.prepare(
            "SELECT id FROM users WHERE email = ?"
        ).get(email);

        if (existing) {
            return res.status(409).json({
                error: "An account with this email already exists."
            });
        }

        const hashed = await bcrypt.hash(password, 12);

        const result = db.prepare(
            "INSERT INTO users (email, password) VALUES (?, ?)"
        ).run(email, hashed);

        const user = { id: Number(result.lastInsertRowid), email };

        res.status(201).json({
            token: createToken(user),
            email,
            subscription: null
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Registration failed." });
    }
});

// Login
app.post("/api/login", authLimiter, async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        const user = db.prepare(
            "SELECT * FROM users WHERE email = ?"
        ).get(email);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({
                error: "Incorrect email or password."
            });
        }

        res.json({
            token: createToken(user),
            email: user.email,
            ...accountResponse(user.id)
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Login failed." });
    }
});

// Current account
app.get("/api/me", authenticate, (req, res) => {
    const user = db.prepare(
        "SELECT email FROM users WHERE id = ?"
    ).get(req.user.id);

    if (!user) {
        return res.status(404).json({ error: "Account not found." });
    }

    res.json({
        email: user.email,
        ...accountResponse(req.user.id)
    });
});

// Verify a Paystack payment and activate its subscription.
async function verifyPayment(reference) {
    const payment = db.prepare(
        "SELECT * FROM payments WHERE reference = ?"
    ).get(reference);

    if (!payment) throw new Error("Payment reference not found.");

    if (payment.status === "success") return payment;

    const response = await fetch(
        `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
        {
            headers: {
                Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
            }
        }
    );

    const result = await response.json();

    if (
        !response.ok ||
        !result.status ||
        result.data.status !== "success" ||
        result.data.currency !== (process.env.CURRENCY || "NGN") ||
        Number(result.data.amount) !== payment.amount
    ) {
        throw new Error("Payment could not be verified.");
    }

    const plan = plans[payment.plan];

    if (!plan) throw new Error("Invalid payment plan.");

    const expiresAt = plan.duration
        ? new Date(Date.now() + plan.duration * 86400000).toISOString()
        : null;

    const activate = db.transaction(() => {
        db.prepare(
            "UPDATE payments SET status = 'success' WHERE reference = ?"
        ).run(reference);

        db.prepare(`
            INSERT INTO subscriptions (user_id, plan, expires_at, active)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(user_id) DO UPDATE SET
                plan = excluded.plan,
                expires_at = excluded.expires_at,
                active = 1
        `).run(payment.user_id, payment.plan, expiresAt);
    });

    activate();

    return payment;
}

// Initialize payment
app.post(
    "/api/payment/initialize",
    authenticate,
    paymentLimiter,
    async (req, res) => {
        try {
            const planName = String(req.body.plan || "");
            const plan = plans[planName];

            if (!plan) {
                return res.status(400).json({
                    error: "Invalid subscription plan."
                });
            }

            const user = db.prepare(
                "SELECT email FROM users WHERE id = ?"
            ).get(req.user.id);

            if (!user) {
                return res.status(404).json({ error: "Account not found." });
            }

            const reference = "PX_" + crypto.randomUUID().replace(/-/g, "");

            db.prepare(`
                INSERT INTO payments
                (user_id, reference, plan, amount, status)
                VALUES (?, ?, ?, ?, 'pending')
            `).run(req.user.id, reference, planName, plan.amount * 100);

            const response = await fetch(
                "https://api.paystack.co/transaction/initialize",
                {
                    method: "POST",
                    headers: {
                        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        email: user.email,
                        amount: plan.amount * 100,
                        currency: process.env.CURRENCY || "NGN",
                        reference,
                        callback_url: `${APP_URL}/?payment=callback`
                    })
                }
            );

            const result = await response.json();

            if (!response.ok || !result.status) {
                throw new Error(result.message || "Could not initialize payment.");
            }

            res.json({
                authorization_url: result.data.authorization_url,
                reference
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({
                error: error.message || "Payment initialization failed."
            });
        }
    }
);

// Verify payment after returning from Paystack.
app.get("/api/payment/verify/:reference", authenticate, async (req, res) => {
    try {
        const payment = db.prepare(
            "SELECT * FROM payments WHERE reference = ? AND user_id = ?"
        ).get(req.params.reference, req.user.id);

        if (!payment) {
            return res.status(404).json({ error: "Payment not found." });
        }

        await verifyPayment(payment.reference);

        res.json({
            success: true,
            ...accountResponse(req.user.id)
        });
    } catch (error) {
        res.status(400).json({
            error: error.message || "Payment verification failed."
        });
    }
});

// VIP content
app.get("/api/vip/content", authenticate, (req, res) => {
    const subscription = getSubscription(req.user.id);

    if (!subscription || !subscription.active) {
        return res.status(403).json({
            error: "An active VIP subscription is required."
        });
    }

    res.json({
        tips: [
            {
                title: "VIP Prediction Updates",
                message: "Your VIP account is active. VIP predictions will be published here by the administrator."
            }
        ]
    });
});

// Frontend fallback
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
    console.log(`PREDICTX AI running on port ${PORT}`);
});
