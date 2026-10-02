export type ErrorCode =
	| "INVALID_MESSAGE"
	| "ACCOUNT_EXISTS"
	| "ACCOUNT_NOT_FOUND"
	| "INVALID_PUBLIC_KEY"
	| "CHALLENGE_NOT_FOUND"
	| "CHALLENGE_EXPIRED"
	| "INVALID_SIGNATURE"
	| "ALREADY_LOGGED_IN"
	| "NOT_LOGGED_IN"
	| "USER_NOT_CONNECTED"
	| "INTERNAL_ERROR";

export class ProtocolError extends Error {
	constructor(
		public readonly code: ErrorCode,
		message: string,
	) {
		super(message);
		this.name = "ProtocolError";
	}
}
