import { z } from "zod";

const envSchema = z.object({
	DATABASE_URL: z.string().min(1),
	JWT_SECRET: z.string().min(1),
	JWT_EXPIRES_IN: z.string().default("5m"),
	EMAIL_FROM: z.string().default(""),
	RESEND_API_KEY: z.string().default(""),
	OTP_EXPIRES_MINUTES: z.coerce.number().default(5),
	FRONTEND_URL: z.string().default("http://localhost:3000"),
});

export const env = envSchema.parse(process.env);