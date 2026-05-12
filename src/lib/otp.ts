import { customAlphabet } from "nanoid";
import { env } from "../config/env";

export function generateVerificationCode() {
	const generateCode = customAlphabet("123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 6);
	return generateCode();
}

export function getOtpExpiresAt() {
	const minutes = env.OTP_EXPIRES_MINUTES;
	return new Date(Date.now() + minutes * 60 * 1000);
}