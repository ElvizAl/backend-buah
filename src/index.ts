import 'dotenv/config'

import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { cors } from 'hono/cors'
import { HTTPException } from 'hono/http-exception'
import { authRouter } from './modules/auth/auth.router'
import { env } from './config/env'

const app = new Hono()

  .basePath("api")

	.use(logger())

	.use(
		"*",
		cors({
			origin: (origin) => {
				const allowedOrigins = [
					"http://localhost:3000",
					env.FRONTEND_URL,
				].filter(Boolean);

				// Jika origin ada di daftar, kembalikan origin tersebut
				if (allowedOrigins.includes(origin)) {
					return origin;
				}

				// Untuk request tanpa origin (server-to-server), izinkan
				return allowedOrigins[0];
			},
			allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
			allowHeaders: ["Content-Type", "Authorization"],
			credentials: true,
		}),
	)

	.get("/", (c) => {
		return c.json({ message: "Hello, World!" })
	})

	.route("/auth", authRouter)

	.notFound((c) => {
		return c.json({ message: "Tidak Ditemukan" }, 404);
	})

	.onError((err, c) => {
		if (err instanceof HTTPException) {
			return c.json({ message: err.message }, err.status);
		}

		console.error("Internal Server Error:", err);
		return c.json({ message: "Internal Server Error" }, 500);
	});

// Untuk development lokal
if (process.env.NODE_ENV !== "production") {
	serve({
		fetch: app.fetch,
		port: 8000
	}, (info) => {
		console.log(`Server is running on http://localhost:${info.port}`)
	})
}

// Export untuk Vercel serverless
export default app
