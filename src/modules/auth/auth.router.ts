import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { requireAuth } from "../../middleware/auth";
import {
	changePasswordSchema,
	forgotPasswordSchema,
	loginSchema,
	registerSchema,
	resendVerificationOtpSchema,
	resetPasswordSchema,
	verifyEmailOtpSchema,
} from "./auth.schema";
import {
	changePasswordService,
	forgotPasswordService,
	loginService,
	registerService,
	resendVerificationOtpService,
	resetPasswordService,
	verifyEmailOtpService,
} from "./auth.service";

export const authRouter = new Hono()

	.post("/register", zValidator("json", registerSchema), async (c) => {
		const data = c.req.valid("json");
		const result = await registerService(data);
		return c.json(result, 201);
	})

	.post("/login", zValidator("json", loginSchema), async (c) => {
		const data = c.req.valid("json");
		const result = await loginService(data);
		return c.json(result, 200);
	})

	.post(
		"/verify-email",
		zValidator("json", verifyEmailOtpSchema),
		async (c) => {
			const data = c.req.valid("json");
			const result = await verifyEmailOtpService(data);
			return c.json(result, 200);
		},
	)

	.post(
		"/resend-otp",
		zValidator("json", resendVerificationOtpSchema),
		async (c) => {
			const data = c.req.valid("json");
			const result = await resendVerificationOtpService(data);
			return c.json(result, 200);
		},
	)

	.post(
		"/forgot-password",
		zValidator("json", forgotPasswordSchema),
		async (c) => {
			const data = c.req.valid("json");
			const result = await forgotPasswordService(data);
			return c.json(result, 200);
		},
	)

	.post(
		"/reset-password",
		zValidator("json", resetPasswordSchema),
		async (c) => {
			const data = c.req.valid("json");
			const result = await resetPasswordService(data);
			return c.json(result, 200);
		},
	)

	.post(
		"/change-password",
		requireAuth,
		zValidator("json", changePasswordSchema),
		async (c) => {
			const userId = c.get("user").sub;
			const body = c.req.valid("json");
			const result = await changePasswordService(userId, body);
			return c.json(result, 200);
		},
	);