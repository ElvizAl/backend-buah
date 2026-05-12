import 'dotenv'

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
			origin: [
				"http://localhost:3000",
				env.FRONTEND_URL || "http://localhost:3000",
			],
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

serve({
  fetch: app.fetch,
  port: 8000
}, (info) => {
  console.log(`Server is running on http://localhost:${info.port}`)
})
