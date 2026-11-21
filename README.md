# PREDICTX AI

Football prediction platform with:
- Home page
- Free football tips
- Match standings
- VIP predictions
- Premium subscriptions
- User registration and login
- Paystack payments

## Requirements

- Node.js 20 or newer
- npm
- Paystack account

## Install locally

Run:

npm install

Configure your environment variables in .env.

Start the application:

npm start

Open:

http://localhost:3000

## Render deployment

1. Push the project to GitHub.
2. Create a new Web Service on Render.
3. Connect your GitHub repository.
4. Set the build command to:

npm install

5. Set the start command to:

npm start

6. Add your environment variables in Render.

Required variables:

PORT=10000
APP_URL=https://YOUR-RENDER-DOMAIN
JWT_SECRET=YOUR_LONG_RANDOM_SECRET
PAYSTACK_SECRET_KEY=YOUR_PAYSTACK_SECRET
CURRENCY=NGN
PRICE_WEEKLY_NGN=1500
PRICE_MONTHLY_NGN=5000
PRICE_LIFETIME_NGN=25000
DB_FILE=/var/data/predictx.sqlite
WHATSAPP_CHANNEL=YOUR_CHANNEL_LINK
WHATSAPP_ADMIN=YOUR_ADMIN_LINK

Replace all example values.

## Database persistence

For production, attach a persistent Render disk.

Use:

/var/data

as the disk mount path.

This keeps SQLite data between service restarts and deployments.

## Paystack

Configure your Paystack webhook URL as:

https://YOUR-RENDER-DOMAIN/api/paystack/webhook

Use your Paystack test keys for testing before switching to live keys.

## Important

The free tips and standings currently contain demonstration data.

A secure administrator publishing dashboard and live football data provider still need to be added.
