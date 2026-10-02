import { DurableObject } from "cloudflare:workers";
import { Data, DataType } from "./data";
import { ProtocolError } from "./errors";
import {
	base64ToArrayBuffer,
	normalizeUsername,
	isValidUsername,
	parseMessage,
} from "./protocol";

interface Challenge {
	expires: number;
	challenge: string;
	username: string;
}

export class ChatServer extends DurableObject<Env> {
	private readonly userSessions = new Map<string, WebSocket>();
	private readonly challenges = new Map<string, Challenge>();
	private readonly challengeTtlMs = 10_000;
	private readonly maxMessageSize = 64 * 1024;

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);

		for (const ws of this.ctx.getWebSockets()) {
			const attachment = ws.deserializeAttachment() as { username?: string } | null;

			if (attachment?.username) {
				this.userSessions.set(attachment.username, ws);
			}
		}
	}

	async fetch(request: Request): Promise<Response> {
		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("Expected WebSocket", {
				status: 426,
			});
		}

		const pair = new WebSocketPair();
		const [client, server] = Object.values(pair);

		this.ctx.acceptWebSocket(server);

		return new Response(null, {
			status: 101,
			webSocket: client,
		});
	}

	async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
		try {
			const raw = typeof message === "string" ? message : new TextDecoder().decode(message);
			const payload = JSON.parse(raw) as unknown;
			const parsed = parseMessage(payload);
			const response = await this.handleMessage(parsed, ws);
			ws.send(JSON.stringify(response));
		} catch (error) {
			const protocolError = error instanceof ProtocolError
				? error
				: new ProtocolError("INTERNAL_ERROR", "Internal server error");

			if (!(error instanceof ProtocolError)) {
				console.error("WebSocket protocol error", error);
			}

			ws.send(JSON.stringify({
				error: protocolError.message,
			}));
		}
	}

	async webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean) {
		const attachment = ws.deserializeAttachment() as { username?: string } | null;
		const username = attachment?.username;

		if (!username) {
			return;
		}

		if (this.userSessions.get(username) === ws) {
			this.userSessions.delete(username);
		}
	}

	private async handleMessage(message: Data, ws: WebSocket): Promise<Data> {
		this.cleanupExpiredChallenges();

		switch (message.type) {
			case DataType.SIGNUP: {
				const username = normalizeUsername(message.data.username);

				if (!isValidUsername(username)) {
					throw new ProtocolError("INVALID_MESSAGE", "Invalid username");
				}

				const existing = await this.getUser(username);
				if (existing) {
					throw new ProtocolError("ACCOUNT_EXISTS", "Account already exists");
				}

				try {
					await crypto.subtle.importKey(
						"spki",
						base64ToArrayBuffer(message.data.key),
						{
							name: "RSA-PSS",
							hash: "SHA-256",
						},
						false,
						["verify"],
					);
				} catch {
					throw new ProtocolError("INVALID_PUBLIC_KEY", "Invalid public key");
				}

				try {
					await this.env.XChat.prepare(
						"INSERT INTO USERS (USERNAME, PUBLICKEY) VALUES (?, ?)"
					).bind(username, message.data.key).run();
				} catch (error) {
					console.error("Signup failed", error);
					throw new ProtocolError("INTERNAL_ERROR", "Unable to create account");
				}

				return { type: DataType.SIGNUP_SUCCESSFUL };
			}

			case DataType.LOGIN: {
				const username = normalizeUsername(message.data.username);

				if (!isValidUsername(username)) {
					throw new ProtocolError("INVALID_MESSAGE", "Invalid username");
				}

				const existingUser = await this.getUser(username);
				if (!existingUser) {
					throw new ProtocolError("ACCOUNT_NOT_FOUND", "Account doesn't exist");
				}

				const challenge = crypto.randomUUID();
				this.challenges.set(challenge, {
					challenge,
					expires: Date.now() + this.challengeTtlMs,
					username,
				});

				return {
					type: DataType.CHALLENGE,
					data: { challenge },
				};
			}

			case DataType.CHALLENGE_SIGNED: {
				const challenge = this.challenges.get(message.data.original);
				if (!challenge) {
					throw new ProtocolError("CHALLENGE_NOT_FOUND", "No challenge for account");
				}

				if (Date.now() > challenge.expires) {
					this.challenges.delete(message.data.original);
					throw new ProtocolError("CHALLENGE_EXPIRED", "Challenge expired");
				}

				const userRecord = await this.getUser(challenge.username);
				if (!userRecord) {
					this.challenges.delete(message.data.original);
					throw new ProtocolError("ACCOUNT_NOT_FOUND", "Account doesn't exist");
				}

				let publicKey: CryptoKey;
				try {
					publicKey = await crypto.subtle.importKey(
						"spki",
						base64ToArrayBuffer(userRecord.PUBLICKEY),
						{
							name: "RSA-PSS",
							hash: "SHA-256",
						},
						false,
						["verify"],
					);
				} catch {
					this.challenges.delete(message.data.original);
					throw new ProtocolError("INVALID_PUBLIC_KEY", "Invalid public key");
				}

				const valid = await crypto.subtle.verify(
					{
						name: "RSA-PSS",
						saltLength: 32,
					},
				publicKey,
				base64ToArrayBuffer(message.data.signed),
				new TextEncoder().encode(challenge.challenge),
				);

				this.challenges.delete(message.data.original);

				if (!valid) {
					throw new ProtocolError("INVALID_SIGNATURE", "Invalid signature");
				}

				const existingSession = this.userSessions.get(challenge.username);
				if (existingSession && existingSession.readyState === WebSocket.OPEN) {
					throw new ProtocolError("ALREADY_LOGGED_IN", "Already logged in");
				}

				if (existingSession && existingSession.readyState !== WebSocket.OPEN) {
					this.userSessions.delete(challenge.username);
				}

				ws.serializeAttachment({ username: challenge.username });
				this.userSessions.set(challenge.username, ws);

				return { type: DataType.LOGIN_SUCCESSFUL };
			}

			case DataType.REQUEST_PUBKEY: {
				const username = normalizeUsername(message.data.username);
				const user = await this.getUser(username);

				if (user) {
					return {
						type: DataType.PUBKEY,
						data: {
							username,
							key: user.PUBLICKEY,
						},
					};
				}

				throw new ProtocolError("ACCOUNT_NOT_FOUND", "User doesn't exist");
			}

			case DataType.SEND_MESSAGE: {
				const from = this.getAttachedUsername(ws);
				if (!from) {
					throw new ProtocolError("NOT_LOGGED_IN", "You aren't logged in");
				}

				const recipient = normalizeUsername(message.data.username);
				const sendTo = this.userSessions.get(recipient);
				if (!sendTo) {
					throw new ProtocolError("USER_NOT_CONNECTED", "User isn't connected");
				}

				if (sendTo.readyState !== WebSocket.OPEN) {
					throw new ProtocolError("USER_NOT_CONNECTED", "User isn't connected");
				}

				sendTo.send(JSON.stringify({
					type: DataType.RECEIVE_MESSAGE,
					data: {
						username: from,
						data: message.data.data,
					},
				} satisfies Data));

				return { type: DataType.SEND_MESSAGE_SUCCESSFUL };
			}

			default: {
				throw new ProtocolError("INVALID_MESSAGE", "Unknown message type");
			}
		}
	}

	private cleanupExpiredChallenges() {
		const now = Date.now();
		for (const [id, challenge] of this.challenges.entries()) {
			if (challenge.expires <= now) {
				this.challenges.delete(id);
			}
		}
	}

	private getAttachedUsername(ws: WebSocket): string | null {
		const attachment = ws.deserializeAttachment() as { username?: string } | null;
		return attachment?.username ?? null;
	}

	private async getUser(username: string): Promise<{ USERNAME: string; PUBLICKEY: string } | null> {
		return this.env.XChat.prepare(
			"SELECT USERNAME, PUBLICKEY FROM USERS WHERE USERNAME = ?"
		).bind(username).first<{ USERNAME: string; PUBLICKEY: string }>();
	}
}

