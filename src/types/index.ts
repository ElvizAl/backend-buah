import type { Role } from "../generated/prisma/enums";

export type AppVariables = {
	Variables: {
		user: {
			sub: string;
			email: string;
			role: Role;
		};
	};
};

export type AccessTokenPayload = {
	sub: string;
	email: string;
	role: Role;
};

export type RefreshTokenPayload = {
	sub: string;
	type: "refresh";
};