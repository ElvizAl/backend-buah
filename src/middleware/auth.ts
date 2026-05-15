import { createMiddleware } from "hono/factory";
import { getCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import type { Role } from "../generated/prisma/enums";
import type { AppVariables } from "../types";
import { verifyAccessToken } from "../utils/jwt";

export const requireAuth = createMiddleware<AppVariables>(async (c, next) => {
	// Cek token dari Authorization header terlebih dahulu, lalu dari cookie
	const authHeader = c.req.header("Authorization");
	let token: string | undefined;

	if (authHeader && authHeader.startsWith("Bearer ")) {
		token = authHeader.split(" ")[1];
	} else {
		token = getCookie(c, "accessToken");
	}

	if (!token) {
		throw new HTTPException(401, {
			message: "Unauthorized - Token tidak ditemukan",
		});
	}

	try {
		const payload = verifyAccessToken(token);
		// Menyimpan payload ke dalam context Hono
		c.set("user", {
			sub: payload.sub,
			email: payload.email,
			role: payload.role as Role,
		});
		await next();
	} catch (error) {
		if (error instanceof HTTPException) throw error;
		throw new HTTPException(401, {
			message: "Unauthorized - Token tidak valid atau kedaluwarsa",
		});
	}
});

export const requireRole = (allowedRoles: Role[]) => {
	return createMiddleware<AppVariables>(async (c, next) => {
		const user = c.get("user");

		if (
			!user ||
			(Array.isArray(allowedRoles) && !allowedRoles.includes(user.role))
		) {
			throw new HTTPException(403, { message: "Forbidden - Akses Ditolak" });
		}

		await next();
	});
};