import { ChatServer } from "./chat";

export { ChatServer };

export default {
	async fetch(request, env): Promise<Response> {
		const upgradeHeader = request.headers.get("Upgrade");

		if (!upgradeHeader || upgradeHeader !== "websocket") {
			return new Response("Expected Upgrade: websocket", {
				status: 426,
			});
		}

		const id = env.CHAT.idFromName("global");
		const stub = env.CHAT.get(id);

		return stub.fetch(request);
	},
} satisfies ExportedHandler<Env>;
