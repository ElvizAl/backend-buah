import { z } from "zod";

export const registerSchema = z.object({
	name: z.string().min(2, "Nama minimal 2 karakter"),
	email: z.email("Format email tidak valid"),
	password: z.string().min(8, "Kata sandi minimal 8 karakter"),
});

export const verifyEmailOtpSchema = z.object({
	email: z.email("Format email tidak valid"),
	code: z.string().length(6, "Kode OTP harus 6 karakter"),
});

export const resendVerificationOtpSchema = z.object({
	email: z.email("Format email tidak valid"),
});

export const loginSchema = z.object({
	email: z.email("Format email tidak valid"),
	password: z.string().min(1, "Kata sandi wajib diisi"),
});

export const forgotPasswordSchema = z.object({
	email: z.email("Format email tidak valid"),
});

export const resetPasswordSchema = z
	.object({
		email: z.email("Format email tidak valid"),
		code: z.string().length(6, "Kode OTP harus 6 karakter"),
		newPassword: z.string().min(8, "Kata sandi baru minimal 8 karakter"),
		confirmPassword: z.string().min(1, "Konfirmasi kata sandi wajib diisi"),
	})
	.refine((data) => data.newPassword === data.confirmPassword, {
		message: "Konfirmasi kata sandi tidak cocok",
		path: ["confirmPassword"],
	});

export type RegisterInput = z.infer<typeof registerSchema>;
export type VerifyEmailOtpInput = z.infer<typeof verifyEmailOtpSchema>;
export type ResendVerificationOtpInput = z.infer<
	typeof resendVerificationOtpSchema
>;
export type LoginInput = z.infer<typeof loginSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

export const changePasswordSchema = z
	.object({
		currentPassword: z.string().min(1, "Password lama wajib diisi"),
		newPassword: z.string().min(8, "Password baru minimal 8 karakter"),
		confirmPassword: z.string().min(1, "Konfirmasi password wajib diisi"),
	})
	.refine((data) => data.newPassword === data.confirmPassword, {
		message: "Konfirmasi password tidak cocok",
		path: ["confirmPassword"],
	});

export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;