import { Data, DataType } from "./data";
import { ProtocolError } from "./errors";

export function normalizeUsername(username: string): string {
	return username.trim().toLowerCase();
}

export function isValidUsername(username: string): boolean {
	return /^[a-zA-Z0-9_]{3,32}$/.test(username.trim());
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
	const cleaned = base64.replace(/\s+/g, "");
	const binary = atob(cleaned);
	const bytes = new Uint8Array(binary.length);

	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}

	return bytes.buffer;
}

export function parseMessage(input: unknown): Data {
	if (typeof input !== "object" || input === null || !("type" in input)) {
		throw new ProtocolError("INVALID_MESSAGE", "Invalid message");
	}

	const message = input as { type: DataType; data?: unknown };

	switch (message.type) {
		case DataType.SIGNUP:
			if (
				typeof message.data !== "object" ||
				message.data === null ||
				typeof (message.data as { username?: unknown }).username !== "string" ||
				typeof (message.data as { key?: unknown }).key !== "string"
			) {
				throw new ProtocolError("INVALID_MESSAGE", "Invalid signup payload");
			}
			return message as unknown as Data;

		case DataType.LOGIN:
			if (
				typeof message.data !== "object" ||
				message.data === null ||
				typeof (message.data as { username?: unknown }).username !== "string"
			) {
				throw new ProtocolError("INVALID_MESSAGE", "Invalid login payload");
			}
			return message as unknown as Data;

		case DataType.CHALLENGE_SIGNED:
			if (
				typeof message.data !== "object" ||
				message.data === null ||
				typeof (message.data as { original?: unknown }).original !== "string" ||
				typeof (message.data as { signed?: unknown }).signed !== "string"
			) {
				throw new ProtocolError("INVALID_MESSAGE", "Invalid signed challenge payload");
			}
			return message as unknown as Data;

		case DataType.SEND_MESSAGE:
			if (
				typeof message.data !== "object" ||
				message.data === null ||
				typeof (message.data as { username?: unknown }).username !== "string" ||
				typeof (message.data as { data?: unknown }).data !== "string"
			) {
				throw new ProtocolError("INVALID_MESSAGE", "Invalid message payload");
			}
			return message as unknown as Data;

		case DataType.REQUEST_PUBKEY:
			if (
				typeof message.data !== "object" ||
				message.data === null ||
				typeof (message.data as { username?: unknown }).username !== "string"
			) {
				throw new ProtocolError("INVALID_MESSAGE", "Invalid public key request payload");
			}
			return message as unknown as Data;

		default:
			throw new ProtocolError("INVALID_MESSAGE", "Unknown message type");
	}
}
