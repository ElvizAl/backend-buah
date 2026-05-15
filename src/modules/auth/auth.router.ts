import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { setCookie, getCookie, deleteCookie } from "hono/cookie";
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
	logoutService,
	refreshTokenService,
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

		const isProduction = process.env.NODE_ENV === "production";

		// Set accessToken sebagai httpOnly cookie (short-lived)
		setCookie(c, "accessToken", result.accessToken, {
			httpOnly: true,
			secure: isProduction,
			sameSite: "Lax",
			path: "/",
			maxAge: 60 * 15, // 15 menit
		});

		// Set refreshToken sebagai httpOnly cookie (long-lived)
		setCookie(c, "refreshToken", result.refreshToken, {
			httpOnly: true,
			secure: isProduction,
			sameSite: "Lax",
			path: "/api/auth",
			maxAge: 60 * 60 * 24 * 7, // 7 hari
		});

		return c.json({ message: result.message }, 200);
	})

	.post("/logout", async (c) => {
		const refreshToken = getCookie(c, "refreshToken");

		if (refreshToken) {
			await logoutService(refreshToken);
		}

		deleteCookie(c, "accessToken", { path: "/" });
		deleteCookie(c, "refreshToken", { path: "/api/auth" });

		return c.json({ message: "Logout berhasil" }, 200);
	})

	.post("/refresh-token", async (c) => {
		const refreshToken = getCookie(c, "refreshToken");

		if (!refreshToken) {
			return c.json({ message: "Refresh token tidak ditemukan" }, 401);
		}

		const result = await refreshTokenService(refreshToken);
		const isProduction = process.env.NODE_ENV === "production";

		// Set access token baru
		setCookie(c, "accessToken", result.accessToken, {
			httpOnly: true,
			secure: isProduction,
			sameSite: "Lax",
			path: "/",
			maxAge: 60 * 15, // 15 menit
		});

		// Set refresh token baru (rotation)
		setCookie(c, "refreshToken", result.refreshToken, {
			httpOnly: true,
			secure: isProduction,
			sameSite: "Lax",
			path: "/api/auth",
			maxAge: 60 * 60 * 24 * 7, // 7 hari
		});

		return c.json({ message: "Token berhasil diperbarui" }, 200);
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