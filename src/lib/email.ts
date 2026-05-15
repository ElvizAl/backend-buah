import { HTTPException } from "hono/http-exception";
import { env } from "../config/env";
import { VerificationPurpose } from "../generated/prisma/enums";
import { prisma } from "../utils/prisma";
import { resend } from "../utils/resend";
import { generateVerificationCode, getOtpExpiresAt } from "./otp";

export async function sendOtpEmail(params: {
	email: string;
	code: string;
	purpose: VerificationPurpose;
}) {
	const subject =
		params.purpose === VerificationPurpose.VERIFY_EMAIL
			? "Kode verifikasi email"
			: "Kode reset password";

	const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.6;">
      <h2>${subject}</h2>
      <p>Kode OTP kamu:</p>
      <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px;">${params.code}</div>
      <p>Kode ini berlaku selama ${env.OTP_EXPIRES_MINUTES} menit.</p>
    </div>
  `;

	if (!env.RESEND_API_KEY || !env.EMAIL_FROM) {
		console.log(
			`[DEV OTP] ${params.purpose} | ${params.email} | ${params.code}`,
		);
		return;
	}

	const { error } = await resend.emails.send({
		from: env.EMAIL_FROM,
		to: [params.email],
		subject,
		html,
	});

	if (error) {
		throw new HTTPException(500, {
			message: error.message || "Gagal mengirim OTP email",
		});
	}
}

export async function upsertVerificationCode(
	userId: string,
	purpose: VerificationPurpose,
) {
	const code = generateVerificationCode();
	const expiresAt = getOtpExpiresAt();

	return prisma.verificationCode.upsert({
		where: {
			userId_purpose: {
				userId,
				purpose,
			},
		},
		update: {
			code,
			expiresAt,
		},
		create: {
			userId,
			purpose,
			code,
			expiresAt,
		},
	});
}